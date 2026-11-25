"""Deterministic PR risk rating. See SPEC.md."""
import argparse
import json
import re
import subprocess
import sys

LEVELS = ["low", "medium", "high"]
TEST_GLOBS = ["**/tests/**", "**/test/**", "**/test_*.py", "**/*_test.*", "**/*.spec.*"]
HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def match_glob(path, pattern):
    parts = pattern.split("/")
    rx = ""
    for i, seg in enumerate(parts):
        last = i == len(parts) - 1
        if seg == "**":
            rx += ".*" if last else "(?:.*/)?"
        else:
            rx += "".join("[^/]*" if c == "*" else re.escape(c) for c in seg)
            rx += "" if last else "/"
    return re.fullmatch(rx, path, re.DOTALL) is not None


def is_test_path(path):
    return any(match_glob(path, g) for g in TEST_GLOBS)


def classify(changes, added_lines, policy, deleted=None):
    """changes: [(status, path)], added_lines: [(path, lineno, text)], deleted: {path: deleted line count}."""
    deleted = deleted or {}
    floors = []  # (risk, reason)
    paths = [p for _, p in changes]
    for rule in policy["path_rules"]:
        # Path rules ignore case: IAM_roles.json and Auth/ are as sensitive as iam_roles.json and auth/.
        hits = [p for p in paths if any(match_glob(p.lower(), g.lower()) for g in rule["globs"])]
        if hits:
            more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
            floors.append((rule["risk"], f"{rule['reason']}: {hits[0]}{more}"))

    # A submodule pointer bump pulls in code the diff does not show: a supply-chain change.
    for path in (p for s, p in changes if s == "G"):
        floors.append(("high", f"submodule pointer changed: {path}"))
    # "d": a test renamed to a non-test path. "T": a test replaced by a symlink or submodule. Neither runs any more.
    for path in (p for s, p in changes if s in ("D", "d", "T") and is_test_path(p)):
        floors.append((policy["deleted_test_risk"], f"deleted test file: {path}"))
    # A test gutted in place (or while renamed) is as good as deleted.
    for path in dict.fromkeys(p for s, p in changes if s in ("M", "R") and is_test_path(p)):
        if deleted.get(path, 0) > sum(1 for a in added_lines if a[0] == path):
            floors.append((policy["deleted_test_risk"], f"test file shrunk: {path}"))

    # A rename is one changed file: its source ("r"/"d") counts for path rules, not for size.
    files = len({p for s, p in changes if s not in ("r", "d", "G")})
    lines = len(added_lines) + sum(deleted.values())
    for n, unit in ((lines, "lines"), (files, "files")):
        for level in ("high", "medium"):
            limit = policy["size"][f"{level}_{unit}"]
            if n > limit:
                floors.append((level, f"{n} {unit} changed (over {limit})"))
                break

    patterns = [re.compile(rule["regex"]) for rule in policy["secret_patterns"]]
    for path, lineno, text in added_lines:
        if any(pattern.search(text) for pattern in patterns):
            # Keep the report useful without including policy values or matched text.
            floors.append(("high", f"possible secret in {path}:{lineno}"))

    # LEVELS.index raises on an unknown risk value in the policy: fail closed.
    risk = LEVELS[max([LEVELS.index(r) for r, _ in floors], default=0)]
    return {"risk": risk, "reasons": [reason for _, reason in floors], "files": files, "lines": lines}


def parse_name_status(out):
    """Parse `git diff --raw -M -z` (or `--name-status -M -z`) output into [(status, path)].

    A rename's source path is ("r", old), or ("d", old) when a test path leaves the test globs.
    A raw record whose old or new mode is 160000 (a submodule commit pointer) adds ("G", path) after its change.
    """
    tok = out.split("\0")
    if tok and tok[-1] == "":
        tok.pop()
    changes, i = [], 0
    while i < len(tok):
        meta = tok[i].split()
        gitlink = tok[i].startswith(":") and "160000" in (m.lstrip(":") for m in meta[:2])
        status = meta[-1][:1] if meta else ""
        if status in ("R", "C"):
            old, new = tok[i + 1], tok[i + 2]
            i += 3
            if status == "R":
                # A test renamed to a non-test path no longer runs: treat as deleted.
                gone = is_test_path(old) and not is_test_path(new)
                changes.append(("d" if gone else "r", old))
            changes.append((status, new))
        elif status in ("A", "D", "M", "T"):
            changes.append((status, tok[i + 1]))
            i += 2
        else:
            raise ValueError(f"unexpected name-status record {tok[i]!r}")
        if gitlink:
            changes.append(("G", changes[-1][1]))
    return changes


ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def unquote_git(s):
    """Decode a git C-style quoted path; a string not wrapped in double quotes is returned as is."""
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return s

    def byte(m):
        e = m[1].decode("latin-1")
        return bytes([int(e, 8) if len(e) == 3 else ESCAPES[e]])  # unknown escape raises: fail closed

    # Octal escapes are UTF-8 bytes, so decode on bytes, then the same way git_diff decodes stdout.
    raw = re.sub(rb"\\([0-7]{3}|.)", byte, s[1:-1].encode("utf-8"), flags=re.DOTALL)
    return raw.decode("utf-8", "replace")


def parse_patch(out):
    """Parse `git diff -U0` output into ([(path, lineno, text)], {path: deleted_count}).

    Lines of a deleted file are counted under "/dev/null" (its "+++" path).
    """
    added, deleted = [], {}
    path, lineno, old, new = None, 0, 0, 0
    for line in out.split("\n"):
        if old or new:
            # Inside a hunk, counted by the header, so "+++ x" content is never read as a file header.
            if line.startswith("+") and new:
                added.append((path, lineno, line[1:]))
                lineno += 1
                new -= 1
            elif line.startswith("-") and old:
                deleted[path] = deleted.get(path, 0) + 1
                old -= 1
            elif not line.startswith("\\"):
                raise ValueError("unexpected line inside diff hunk")
        elif line.startswith("+++ "):
            # git quotes a path holding a double quote, backslash or control character, whatever core.quotePath says.
            path = unquote_git(line[4:].rstrip("\t"))
            path = path.removeprefix("b/")
        else:
            m = HUNK.match(line)
            if m:
                old = 1 if m[1] is None else int(m[1])
                lineno = int(m[2])
                new = 1 if m[3] is None else int(m[3])
    if old or new:
        raise ValueError("truncated diff hunk")
    return added, deleted


def git_diff(*args):
    # --text: a PR-supplied .gitattributes `-diff` must not hide lines from the scan.
    # --ignore-submodules=none: a PR-supplied .gitmodules `ignore = all` must not hide a submodule pointer change.
    cmd = ["git", "-c", "core.quotePath=false", "diff", "--no-ext-diff", "--no-textconv", "--text",
           "--ignore-submodules=none", *args, "--"]
    r = subprocess.run(cmd, capture_output=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git diff failed: {r.stderr.decode('utf-8', 'replace').strip()}")
    return r.stdout.decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    a = ap.parse_args()
    try:
        if a.base.startswith("-") or a.head.startswith("-"):
            raise ValueError("base and head must be revisions, not options")
        with open(a.policy, encoding="utf-8") as f:
            policy = json.load(f)
        rng = f"{a.base}...{a.head}"
        changes = parse_name_status(git_diff("--raw", "-M", "-z", rng))
        added, deleted = parse_patch(git_diff("-U0", rng))
        result = classify(changes, added, policy, deleted)
    # Fail closed: any git, policy or parse error fails the gate with one stderr line and exit 1.
    # A policy file of the wrong shape can raise almost anything, so the catch stays broad.
    except Exception as error:  # noqa: BLE001
        print(f"risk.py: unable to rate the diff ({type(error).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
