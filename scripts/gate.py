#!/usr/bin/env python3
"""pr-risk-gate: count approvals, read the rating cache, post the required check run. See SPEC.md."""
import argparse
import json
import os
import re
import subprocess
import sys
from urllib.parse import quote

RANKS = ("low", "medium", "high")
MARKER_RE = re.compile(r"<!-- pr-risk-gate-rating: (.*?) -->")
DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "policy", "policy.json")
TEXT_LIMIT = 65535  # GitHub cap on check run output.summary and output.text
HUMAN_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
DEFAULT_CHECK_NAME = "pr-risk-gate"  # used when the policy file cannot be read; matches policy.check_name
WRITE_PERMISSIONS = ("admin", "maintain", "write")


# ---- pure functions (no I/O) ----

def max_rank(*risks):
    """Highest of the given risks. Unknown value -> ValueError (fail closed)."""
    return max(risks, key=RANKS.index)


def approvers_from_reviews(reviews, head_sha, author):
    """Human logins whose latest submitted review is APPROVED on head_sha, excluding the PR author."""
    latest = {}
    for r in sorted(reviews, key=lambda r: r.get("submitted_at") or ""):
        login = (r.get("user") or {}).get("login")
        # SPEC rule 7: the latest submitted review decides, so a later COMMENTED drops an approval.
        # PENDING is unsubmitted and never counts.
        if login and r.get("state") != "PENDING":
            latest[login.lower()] = r
    return {
        r["user"]["login"]
        for key, r in latest.items()
        if r.get("state") == "APPROVED" and r.get("commit_id") == head_sha and key != author.lower()
        # Missing type or association -> not counted (fail closed).
        and r["user"].get("type") not in (None, "Bot") and r.get("author_association") in HUMAN_ASSOCIATIONS
    }


def commit_logins(commit):
    """Lowercased GitHub logins of a commit's author and committer (either may be missing)."""
    return {(commit.get(k) or {}).get("login", "").lower() for k in ("author", "committer")} - {""}


def with_write_access(logins, permission_of):
    """Logins for which permission_of(login) is write or higher. A failed lookup -> not counted."""
    ok = set()
    for login in sorted(logins):
        try:
            if permission_of(login) in WRITE_PERMISSIONS:
                ok.add(login)
        except Exception:  # one bad lookup drops that login only; it never adds an approval
            pass
    return ok


def decide(rating, approvals_count, policy):
    """-> (passed, final, required)."""
    final = max_rank(rating["deterministic"]["risk"], rating["ai"]["risk"])
    required = policy["approvals"][final]
    return approvals_count >= required, final, required


def _code(text):
    # Reasons carry PR-controlled text (file names, AI output): render inert, one line, bounded.
    return "`" + " ".join(str(text).replace("`", "'").split())[:300] + "`"


def build_check_payload(policy, pr, head_sha, rating, approvers, passed, final, required):
    reasons = list(rating["deterministic"].get("reasons") or [])
    if rating["ai"].get("reason"):
        reasons.append("AI: " + rating["ai"]["reason"])
    shown = reasons[:50]
    lines = [
        f"**Final risk:** {final} (deterministic: {rating['deterministic']['risk']}, AI: {rating['ai']['risk']})",
        f"**Approvals:** {len(approvers)} of {required} required on `{head_sha}`",
        "",
        "**Reasons:**",
        *([f"- {_code(r)}" for r in shown] or ["- none"]),
        *([f"- and {len(reasons) - len(shown)} more"] if len(reasons) > len(shown) else []),
        "",
        "**Approvers:** " + (", ".join(_code(a) for a in sorted(approvers)) or "none"),
    ]
    # Escape < and > so rating text cannot close the HTML comment; still valid JSON.
    # "pr" binds the cached rating to one PR: the same SHA can be the head of several PRs.
    compact = json.dumps({**rating, "pr": pr}, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")
    marker = f"<!-- pr-risk-gate-rating: {compact} -->"
    return {
        "name": policy["check_name"],
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": "success" if passed else "failure",
        "output": {
            "title": f"{final} risk: {len(approvers)}/{required} approvals",
            "summary": "\n".join(lines)[:TEXT_LIMIT],
            # Oversized rating: skip the cache marker (next run re-rates) rather than fail the POST.
            "text": marker if len(marker) <= TEXT_LIMIT else "rating too large to cache",
        },
    }


def parse_marker(text):
    """Rating dict from a check run's output.text, or None."""
    m = MARKER_RE.search(text) if isinstance(text, str) else None
    if not m:
        return None
    try:
        rating = json.loads(m.group(1))
        if rating["deterministic"]["risk"] in RANKS and rating["ai"]["risk"] in RANKS:
            return rating
    except (ValueError, KeyError, TypeError):
        pass
    return None


def shared_commit_failure(open_prs, head_sha):
    """Failure reason when head_sha is the head of more than one open PR (SPEC rule 9), else None."""
    n = sum(1 for p in open_prs if p.get("state") == "open" and (p.get("head") or {}).get("sha") == head_sha)
    return f"commit is the head of {n} open PRs" if n > 1 else None


# ---- I/O ----

class GateFailure(Exception):
    """A gate rule failed (not an API or parse error)."""


def gh_api(args, body=None):
    """Run `gh api`; return the list of JSON documents printed (one per page with --paginate)."""
    out = subprocess.run(
        ["gh", "api", *args], input=body, capture_output=True, text=True, encoding="utf-8", check=True
    ).stdout.strip()
    dec, pages = json.JSONDecoder(), []
    while out:
        doc, end = dec.raw_decode(out)
        pages.append(doc)
        out = out[end:].lstrip()
    return pages


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cmd_cache_get(args):
    try:
        name = load_json(args.policy)["check_name"]
        pages = gh_api(["--paginate", f"repos/{args.repo}/commits/{args.sha}/check-runs?check_name={quote(name, safe='')}&per_page=100"])
        # SPEC rule 9: only the App's own check runs are trusted; a run without app never matches.
        runs = [r for p in pages for r in p["check_runs"]
                if r["name"] == name and (r.get("app") or {}).get("id") == args.app_id]
        rating = parse_marker(max(runs, key=lambda r: r["id"])["output"]["text"]) if runs else None
        if rating and rating.pop("pr", None) == args.pr:
            print(json.dumps(rating, separators=(",", ":")))
    except Exception:  # cache miss by contract: print nothing, exit 0, caller re-rates
        pass
    return 0


def cmd_run(args):
    try:  # resolve the name first so the failure check below can always be posted
        check_name = load_json(args.policy)["check_name"]
    except Exception:
        check_name = DEFAULT_CHECK_NAME
    try:
        pr = gh_api([f"repos/{args.repo}/pulls/{args.pr}"])[0]
        if pr.get("state") != "open" or (pr.get("head") or {}).get("sha") != args.head_sha:
            raise GateFailure("PR moved or closed")
        author = pr["user"]["login"]
        base = (pr.get("base") or {}).get("ref")
        if base != args.base_ref:  # a pass here must not be reusable for a PR into another base
            raise GateFailure(f"PR targets {base}, not the default branch")
        pages = gh_api(["--paginate", f"repos/{args.repo}/commits/{args.head_sha}/pulls?per_page=100"])
        reason = shared_commit_failure([p for page in pages for p in page], args.head_sha)
        if reason:
            raise GateFailure(reason)
        policy, rating = load_json(args.policy), load_json(args.rating)
        pages = gh_api(["--paginate", f"repos/{args.repo}/pulls/{args.pr}/reviews?per_page=100"])
        approvers = approvers_from_reviews([r for p in pages for r in p], args.head_sha, author)
        # Whoever authored or committed the head commit never approves it.
        pushers = commit_logins(gh_api([f"repos/{args.repo}/commits/{args.head_sha}"])[0])
        # Needs the App's Metadata read permission. `.permission` is the legacy level:
        # maintain is reported as write and triage as read.
        approvers = with_write_access(
            {a for a in approvers if a.lower() not in pushers},
            lambda login: gh_api([f"repos/{args.repo}/collaborators/{quote(login, safe='')}/permission"])[0]["permission"],
        )
        passed, final, required = decide(rating, len(approvers), policy)
        payload = build_check_payload(policy, args.pr, args.head_sha, rating, approvers, passed, final, required)
        gh_api(["-X", "POST", f"repos/{args.repo}/check-runs", "--input", "-"], body=json.dumps(payload))
    except Exception as e:  # fail closed on any API or parse error
        if isinstance(e, GateFailure):
            cause = str(e)
        elif isinstance(e, subprocess.CalledProcessError):
            cause = f"gh api failed: {(e.stderr or '').strip()}"
        else:
            cause = f"{type(e).__name__}: {e}"
        print(f"gate error: {cause}", file=sys.stderr)
        try:  # best effort: replace any earlier success on this SHA; no marker, so nothing is cached
            gh_api(["-X", "POST", f"repos/{args.repo}/check-runs", "--input", "-"], body=json.dumps({
                "name": check_name, "head_sha": args.head_sha,
                "status": "completed", "conclusion": "failure",
                "output": {"title": "gate error", "summary": "gate error: " + _code(cause)},
            }))
        except Exception:
            pass
        return 1
    print(f"{'PASS' if passed else 'FAIL'}: {payload['output']['title']}")
    return 0 if passed else 1


def _pattern(regex, what):
    def check(value):
        if not re.fullmatch(regex, value):
            raise argparse.ArgumentTypeError(f"invalid {what}: {value!r}")
        return value
    return check


def main(argv=None):
    # These values go into API paths, so validate their shape.
    repo = _pattern(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", "OWNER/REPO")
    sha = _pattern(r"[0-9a-f]{40}([0-9a-f]{24})?", "commit SHA")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    cache = sub.add_parser("rating-cache").add_subparsers(dest="action", required=True).add_parser("get")
    cache.add_argument("--repo", required=True, type=repo)
    cache.add_argument("--sha", required=True, type=sha)
    cache.add_argument("--pr", required=True, type=int)
    cache.add_argument("--app-id", required=True, type=int)
    cache.add_argument("--policy", default=DEFAULT_POLICY)
    cache.set_defaults(func=cmd_cache_get)

    run = sub.add_parser("run")
    run.add_argument("--repo", required=True, type=repo)
    run.add_argument("--pr", required=True, type=int)
    run.add_argument("--head-sha", required=True, type=sha)
    run.add_argument("--app-id", required=True, type=int)
    run.add_argument("--base-ref", required=True)
    run.add_argument("--policy", required=True)
    run.add_argument("--rating", required=True)
    run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
