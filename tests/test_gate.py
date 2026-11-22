import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import gate  # noqa: E402

HEAD = "a" * 40
OLD = "b" * 40
APP = 4242
POLICY = {"check_name": "pr-risk-gate", "approvals": {"low": 0, "medium": 1, "high": 2}}


def review(login, state, commit=HEAD, at="2026-01-01T00:00:00Z", type="User", assoc="MEMBER"):
    return {"user": {"login": login, "type": type}, "state": state, "commit_id": commit,
            "submitted_at": at, "author_association": assoc}


def pull(sha=HEAD, state="open", login="alice", number=7, base="main"):
    return {"number": number, "state": state, "head": {"sha": sha}, "user": {"login": login}, "base": {"ref": base}}


def rating(det="low", ai="low", verdict="PASS"):
    """verdict=None leaves the field out (a rating from before the verdict existed)."""
    r = {
        "deterministic": {"risk": det, "reasons": ["CI or workflow file"], "files": 1, "lines": 2},
        "ai": {"risk": ai, "verdict": verdict, "reason": "looks --> fine"},
    }
    if verdict is None:
        del r["ai"]["verdict"]
    return r


class ApproverTests(unittest.TestCase):
    def test_stale_approval_on_old_commit_does_not_count(self):
        self.assertEqual(gate.approvers_from_reviews([review("bob", "APPROVED", OLD)], HEAD, "alice"), set())

    def test_author_approval_does_not_count(self):
        reviews = [review("Alice", "APPROVED"), review("bob", "APPROVED")]
        self.assertEqual(gate.approvers_from_reviews(reviews, HEAD, "alice"), {"bob"})

    def test_latest_changes_requested_removes_earlier_approval(self):
        reviews = [
            review("bob", "CHANGES_REQUESTED", at="2026-01-02T00:00:00Z"),
            review("bob", "APPROVED", at="2026-01-01T00:00:00Z"),  # listed out of order on purpose
        ]
        self.assertEqual(gate.approvers_from_reviews(reviews, HEAD, "alice"), set())

    def test_reapproval_after_changes_requested_counts_once(self):
        reviews = [
            review("bob", "CHANGES_REQUESTED", at="2026-01-01T00:00:00Z"),
            review("BOB", "APPROVED", at="2026-01-02T00:00:00Z"),
        ]
        self.assertEqual(len(gate.approvers_from_reviews(reviews, HEAD, "alice")), 1)

    def test_dismissed_no_user_and_later_comment(self):
        reviews = [
            review("bob", "DISMISSED"),
            {"user": None, "state": "APPROVED", "commit_id": HEAD},
            review("carol", "APPROVED", at="2026-01-01T00:00:00Z"),
            review("carol", "COMMENTED", at="2026-01-02T00:00:00Z"),
        ]
        self.assertEqual(gate.approvers_from_reviews(reviews, HEAD, "alice"), set())

    def test_pending_ignored_and_list_order_breaks_ties(self):
        reviews = [
            review("bob", "APPROVED"),
            {**review("bob", "PENDING"), "submitted_at": None},
            review("carol", "APPROVED"),
            review("carol", "CHANGES_REQUESTED"),  # same timestamp: later in the list wins
        ]
        self.assertEqual(gate.approvers_from_reviews(reviews, HEAD, "alice"), {"bob"})

    def test_only_human_owner_member_collaborator_count(self):
        no_type = review("erin", "APPROVED")
        del no_type["user"]["type"]
        no_assoc = review("frank", "APPROVED")
        del no_assoc["author_association"]
        reviews = [
            review("o", "APPROVED", assoc="OWNER"), review("m", "APPROVED"),
            review("c", "APPROVED", assoc="COLLABORATOR"),
            review("app[bot]", "APPROVED", type="Bot"),
            review("dave", "APPROVED", assoc="CONTRIBUTOR"), review("eve", "APPROVED", assoc="NONE"),
            no_type, no_assoc,
        ]
        self.assertEqual(gate.approvers_from_reviews(reviews, HEAD, "alice"), {"o", "m", "c"})


class AccessTests(unittest.TestCase):
    def test_commit_logins(self):
        commit = {"author": {"login": "Bob"}, "committer": None}
        self.assertEqual(gate.commit_logins(commit), {"bob"})
        self.assertEqual(gate.commit_logins({"author": {"login": "a"}, "committer": {"login": "C"}}), {"a", "c"})
        self.assertEqual(gate.commit_logins({}), set())

    def test_with_write_access(self):
        perms = {"a": "admin", "m": "maintain", "w": "write", "t": "triage", "r": "read", "n": "none"}
        self.assertEqual(gate.with_write_access(set(perms) | {"missing"}, perms.__getitem__), {"a", "m", "w"})


class DecideTests(unittest.TestCase):
    def test_requirement_met_and_unmet_for_each_level(self):
        for risk, required in POLICY["approvals"].items():
            with self.subTest(risk=risk):
                self.assertEqual(gate.decide(rating(risk), required, POLICY), (True, risk, required))
                self.assertEqual(gate.decide(rating(risk), required - 1, POLICY), (False, risk, required))

    def test_max_rank_across_sources(self):
        self.assertEqual(gate.max_rank("low", "medium"), "medium")
        self.assertEqual(gate.max_rank("high", "low"), "high")
        self.assertEqual(gate.max_rank("low", "low"), "low")
        self.assertEqual(gate.decide(rating("low", "high"), 1, POLICY), (False, "high", 2))
        self.assertEqual(gate.decide(rating("medium", "low"), 2, POLICY), (True, "medium", 1))

    def test_low_risk_pass_needs_no_approval(self):
        self.assertEqual(gate.decide(rating("low"), 0, POLICY), (True, "low", 0))

    def test_changes_fails_even_with_enough_approvals(self):
        self.assertEqual(gate.decide(rating("low", verdict="CHANGES"), 2, POLICY), (False, "low", 0))
        self.assertEqual(gate.failures(rating("low", verdict="CHANGES"), 2, 0), ["AI review: CHANGES"])

    def test_missing_or_unknown_verdict_fails_closed(self):
        for verdict in (None, "pass", "PASS ", "APPROVE", "", True, 1, ["PASS"]):
            with self.subTest(verdict=verdict):
                self.assertEqual(gate.decide(rating("low", verdict=verdict), 2, POLICY), (False, "low", 0))

    def test_failures_name_each_unmet_condition(self):
        self.assertEqual(gate.failures(rating("high"), 2, 2), [])
        self.assertEqual(gate.failures(rating("high"), 1, 2), ["approvals 1 of 2 required"])
        self.assertEqual(gate.failures(rating("high", verdict=None), 1, 2),
                         ["AI review: CHANGES", "approvals 1 of 2 required"])

    def test_unknown_risk_fails_closed(self):
        with self.assertRaises(ValueError):
            gate.decide(rating("low", "none"), 5, POLICY)


class SharedCommitTests(unittest.TestCase):
    def test_only_open_prs_with_this_head_count(self):
        others = [pull(state="closed", number=8), pull(sha=OLD, number=9)]
        self.assertIsNone(gate.shared_commit_failure([], HEAD))
        self.assertIsNone(gate.shared_commit_failure([pull(), *others], HEAD))
        self.assertEqual(gate.shared_commit_failure([pull(), pull(number=8), *others], HEAD),
                         "commit is the head of 2 open PRs")


class PayloadTests(unittest.TestCase):
    def test_payload_and_marker_round_trip(self):
        r = rating("high", "medium")
        p = gate.build_check_payload(POLICY, 7, HEAD, r, {"bob"}, False, "high", 2)
        self.assertEqual((p["name"], p["head_sha"], p["status"], p["conclusion"]),
                         ("pr-risk-gate", HEAD, "completed", "failure"))
        for part in ("high", "1 of 2", "CI or workflow file", "looks --> fine", "bob", "**AI review:** PASS",
                     "**Failed:** approvals 1 of 2 required"):
            self.assertIn(part, p["output"]["summary"])
        for verdict in ("CHANGES", None, "<b>PASS"):  # the summary never shows a raw verdict value
            s = gate.build_check_payload(POLICY, 7, HEAD, rating("high", verdict=verdict), {"bob"}, False, "high", 2)
            self.assertIn("**AI review:** CHANGES", s["output"]["summary"])
            self.assertIn("**Failed:** AI review: CHANGES; approvals 1 of 2 required", s["output"]["summary"])
            self.assertNotIn("<b>", s["output"]["summary"])
        ok = gate.build_check_payload(POLICY, 7, HEAD, r, {"b", "c"}, True, "high", 2)["output"]["summary"]
        self.assertNotIn("**Failed:**", ok)
        self.assertEqual(p["output"]["text"].count("-->"), 1)  # rating text cannot close the comment
        self.assertEqual(gate.parse_marker(p["output"]["text"]), {**r, "pr": 7})
        self.assertEqual(gate.build_check_payload(POLICY, 7, HEAD, r, {"b", "c"}, True, "high", 2)["conclusion"], "success")

    def test_parse_marker_rejects_bad_input(self):
        for text in (None, "", "no marker", "<!-- pr-risk-gate-rating: {oops -->",
                     '<!-- pr-risk-gate-rating: {"deterministic":{"risk":"low"},"ai":{"risk":"bogus","verdict":"PASS"}} -->',
                     # No verdict string (a rating cached before the verdict existed): not reusable.
                     '<!-- pr-risk-gate-rating: {"deterministic":{"risk":"low"},"ai":{"risk":"low"}} -->',
                     '<!-- pr-risk-gate-rating: {"deterministic":{"risk":"low"},"ai":{"risk":"low","verdict":null}} -->'):
            self.assertIsNone(gate.parse_marker(text))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.policy = self.write("policy.json", POLICY)

    def write(self, name, data):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def run_main(self, argv, outputs):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs.get("input")))
            return SimpleNamespace(stdout=outputs(cmd) if callable(outputs) else outputs.pop(0))

        out = io.StringIO()
        with mock.patch.object(gate.subprocess, "run", fake_run), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            code = gate.main(argv)
        return code, out.getvalue(), calls

    def run_argv(self, policy=None, rating_path=None):
        return ["run", "--repo", "o/r", "--pr", "7", "--head-sha", HEAD, "--app-id", str(APP), "--base-ref", "main",
                "--policy", policy or self.policy,
                "--rating", rating_path or self.write("rating.json", rating("low", "high"))]

    def run_gate(self, reviews_out, pr=None, head_prs=None, commit=None, perms=None, rating_data=None):
        """-> (exit code, stdout, gh calls).
        Calls: PR, PRs on the head commit, reviews, head commit, one permission per candidate, check POST.
        perms maps login -> permission (default write); the value "error" makes that lookup fail."""
        def route(cmd):
            path = cmd[-1]
            if "POST" in cmd:
                return "{}"
            if "/collaborators/" in path:
                permission = (perms or {}).get(path.split("/")[-2], "write")
                if permission == "error":
                    raise subprocess.CalledProcessError(1, cmd, stderr="HTTP 404")
                return json.dumps({"permission": permission})
            if "/reviews" in path:
                return reviews_out
            if path.endswith(f"commits/{HEAD}"):
                return json.dumps(commit or {"author": {"login": "alice"}, "committer": {"login": "web-flow"}})
            if f"commits/{HEAD}/pulls" in path:
                return json.dumps(head_prs or [pull()])
            return json.dumps(pr or pull())
        rating_path = self.write("rating.json", rating_data) if rating_data else None
        return self.run_main(self.run_argv(rating_path=rating_path), route)

    def test_run_verdict_and_approvals_per_tier(self):
        reviews = [review("bob", "APPROVED"), review("carol", "APPROVED")]
        cases = (  # (risk, verdict, approvals, exit code, text expected in the summary)
            ("low", "PASS", 0, 0, "**AI review:** PASS"),
            ("low", "CHANGES", 2, 1, "**Failed:** AI review: CHANGES"),
            ("low", None, 2, 1, "**Failed:** AI review: CHANGES"),
            ("low", "APPROVED", 2, 1, "**Failed:** AI review: CHANGES"),
            ("medium", "PASS", 0, 1, "**Failed:** approvals 0 of 1 required"),
            ("medium", "PASS", 1, 0, "1 of 1"),
            ("medium", "CHANGES", 1, 1, "**Failed:** AI review: CHANGES"),
            ("high", "PASS", 1, 1, "**Failed:** approvals 1 of 2 required"),
            ("high", "PASS", 2, 0, "2 of 2"),
            ("high", "CHANGES", 1, 1, "**Failed:** AI review: CHANGES; approvals 1 of 2 required"),
        )
        for risk, verdict, n, want, text in cases:
            with self.subTest(risk=risk, verdict=verdict, approvals=n):
                r = rating(risk, verdict=verdict)
                code, _, calls = self.run_gate(json.dumps(reviews[:n]), rating_data=r)
                body = json.loads(calls[-1][1])
                self.assertEqual((code, body["conclusion"]), (want, "failure" if want else "success"))
                self.assertIn(text, body["output"]["summary"])
                # The marker keeps the rating as given; one without a verdict is not reusable from the cache.
                self.assertEqual(gate.parse_marker(body["output"]["text"]), None if verdict is None else {**r, "pr": 7})

    def test_run_passes_across_pages_and_posts_check(self):
        pages = json.dumps([review("bob", "APPROVED")]) + json.dumps([review("carol", "APPROVED")])
        code, _, calls = self.run_gate(pages)
        self.assertEqual(code, 0)
        self.assertEqual(calls[0][0][2:], ["repos/o/r/pulls/7"])  # the PR is fetched before anything else
        self.assertIn(f"repos/o/r/commits/{HEAD}/pulls", calls[1][0][-1])
        self.assertEqual([c[0][-1] for c in calls[3:6]], [f"repos/o/r/commits/{HEAD}"] + [
            f"repos/o/r/collaborators/{u}/permission" for u in ("bob", "carol")])
        cmd, body = calls[-1]
        self.assertEqual(cmd[:4], ["gh", "api", "-X", "POST"])
        self.assertEqual(cmd[-2:], ["--input", "-"])
        self.assertEqual(json.loads(body)["conclusion"], "success")

    def test_run_fails_when_unmet_and_on_bad_api_output(self):
        code, _, calls = self.run_gate(json.dumps([review("bob", "APPROVED")]))
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(calls[-1][1])["conclusion"], "failure")
        code, _, calls = self.run_gate("not json")
        self.assertEqual((code, len(calls)), (1, 4))
        self.assertEqual(json.loads(calls[-1][1])["conclusion"], "failure")  # error overwrites any earlier success

    def test_run_excludes_head_commit_author_and_committer(self):
        both = json.dumps([review("bob", "APPROVED"), review("carol", "APPROVED")])
        self.assertEqual(self.run_gate(both)[0], 0)
        for commit in ({"author": {"login": "Bob"}, "committer": None},
                       {"author": None, "committer": {"login": "BOB"}}):
            with self.subTest(commit=commit):
                code, _, calls = self.run_gate(both, commit=commit)
                self.assertEqual(code, 1)
                self.assertIn("1 of 2", json.loads(calls[-1][1])["output"]["summary"])
                self.assertFalse(any("collaborators/bob/" in c[0][-1] for c in calls))

    def test_run_counts_only_write_access(self):
        both = json.dumps([review("bob", "APPROVED"), review("carol", "APPROVED")])
        for permission in ("read", "triage", "none", "error"):
            with self.subTest(permission=permission):
                code, _, calls = self.run_gate(both, perms={"carol": permission})
                body = json.loads(calls[-1][1])
                # A failed lookup drops carol only: the normal verdict is posted, with its marker.
                self.assertEqual((code, body["conclusion"]), (1, "failure"))
                self.assertIn("1 of 2", body["output"]["summary"])
                self.assertIn("text", body["output"])
        for permission in ("write", "maintain", "admin"):
            self.assertEqual(self.run_gate(both, perms={"carol": permission})[0], 0)

    def test_run_takes_author_from_pr(self):
        both = json.dumps([review("alice", "APPROVED"), review("bob", "APPROVED")])
        # alice wrote the PR: her approval does not count, so high risk (2 required) fails.
        self.assertEqual(self.run_gate(both)[0], 1)
        self.assertEqual(self.run_gate(both, pr=pull(login="carol"), commit={"author": {"login": "carol"}})[0], 0)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            gate.main(self.run_argv() + ["--author", "carol"])  # the flag is gone

    def test_run_fails_closed_before_reviews(self):
        two = [pull(), pull(number=8)]
        cases = (("PR targets release, not the default branch", {"pr": pull(base="release")}),
                 ("PR moved or closed", {"pr": pull(sha=OLD)}),
                 ("PR moved or closed", {"pr": pull(state="closed")}),
                 ("commit is the head of 2 open PRs", {"head_prs": two}))
        for reason, kwargs in cases:
            with self.subTest(kwargs=kwargs):
                code, _, calls = self.run_gate("[]", **kwargs)
                self.assertEqual(code, 1)
                cmd, body = calls[-1]  # the failing check; reviews were never fetched
                self.assertEqual(cmd[2:5], ["-X", "POST", "repos/o/r/check-runs"])
                self.assertFalse(any("/reviews" in c[0][-1] for c in calls))
                body = json.loads(body)
                self.assertEqual((body["head_sha"], body["conclusion"]), (HEAD, "failure"))
                self.assertIn(reason, body["output"]["summary"])
                self.assertNotIn("text", body["output"])

    def test_run_error_posts_failure_check_and_swallows_post_error(self):
        argv = self.run_argv()
        for second in ([{}], RuntimeError("post failed too")):
            with self.subTest(second=second), contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(gate, "gh_api", side_effect=[RuntimeError("boom"), second]) as api:
                self.assertEqual(gate.main(argv), 1)
            self.assertEqual(api.call_count, 2)
            cmd = api.call_args.args[0]
            body = json.loads(api.call_args.kwargs["body"])
            self.assertEqual(cmd[:3], ["-X", "POST", "repos/o/r/check-runs"])
            self.assertEqual((body["name"], body["head_sha"], body["status"], body["conclusion"]),
                             ("pr-risk-gate", HEAD, "completed", "failure"))
            self.assertTrue(body["output"]["summary"].startswith("gate error: "))
            self.assertIn("boom", body["output"]["summary"])
            self.assertNotIn("text", body["output"])  # no rating marker

    def test_run_unreadable_input_file_still_posts_failure_check(self):
        def bad(name):
            path = os.path.join(self.dir.name, name)
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            return path

        custom = self.write("custom.json", {**POLICY, "check_name": "custom-gate"})
        good_rating = self.write("rating.json", rating())
        cases = (("rating", custom, bad("bad-rating.json"), "custom-gate"),
                 ("policy", bad("bad-policy.json"), good_rating, gate.DEFAULT_CHECK_NAME))
        for broken, policy, rating_path, name in cases:
            argv = self.run_argv(policy, rating_path)
            with self.subTest(broken=broken), contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(gate, "gh_api", side_effect=[[pull()], [[pull()]], [{}]]) as api:
                self.assertEqual(gate.main(argv), 1)
                self.assertEqual(api.call_count, 3)
                self.assertEqual(api.call_args.args[0][:3], ["-X", "POST", "repos/o/r/check-runs"])
                body = json.loads(api.call_args.kwargs["body"])
                self.assertEqual((body["name"], body["head_sha"], body["conclusion"]), (name, HEAD, "failure"))

    def test_cache_get_newest_run_wins_and_misses_are_silent(self):
        argv = ["rating-cache", "get", "--repo", "o/r", "--sha", HEAD, "--pr", "7", "--policy", self.policy,
                "--app-id", str(APP)]
        text = gate.build_check_payload(POLICY, 7, HEAD, rating("high"), set(), False, "high", 2)["output"]["text"]
        runs = {"check_runs": [
            {"id": 1, "name": "pr-risk-gate", "app": {"id": APP}, "output": {"text": "<!-- pr-risk-gate-rating: {} -->"}},
            {"id": 2, "name": "pr-risk-gate", "app": {"id": APP}, "output": {"text": text}},
            {"id": 3, "name": "other", "app": {"id": APP}, "output": {"text": None}},
            # Newer runs from another app, or with no app, are ignored (SPEC rule 9).
            {"id": 4, "name": "pr-risk-gate", "app": {"id": APP + 1}, "output": {"text": text.replace("high", "low")}},
            {"id": 5, "name": "pr-risk-gate", "output": {"text": text.replace("high", "low")}},
        ]}
        code, out, _ = self.run_main(argv, [json.dumps(runs)])
        self.assertEqual((code, json.loads(out)), (0, rating("high")))
        for bad in (json.dumps({"check_runs": []}), json.dumps({"check_runs": runs["check_runs"][:1]}),
                    json.dumps({"check_runs": runs["check_runs"][3:]}), "garbage"):
            self.assertEqual(self.run_main(argv, [bad])[:2], (0, ""))
        # Same SHA, different PR: the cached rating is not reused.
        other = [a if a != "7" else "8" for a in argv]
        self.assertEqual(self.run_main(other, [json.dumps(runs)])[:2], (0, ""))
        # Marker without a pr field (older run) is a miss.
        runs["check_runs"][1]["output"]["text"] = "<!-- pr-risk-gate-rating: %s -->" % json.dumps(rating("high"))
        self.assertEqual(self.run_main(argv, [json.dumps(runs)])[:2], (0, ""))
        # Marker without a verdict (rated before the verdict existed) is a miss, so the PR is re-rated.
        runs["check_runs"][1]["output"]["text"] = "<!-- pr-risk-gate-rating: %s -->" % json.dumps(
            {**rating("high", verdict=None), "pr": 7})
        self.assertEqual(self.run_main(argv, [json.dumps(runs)])[:2], (0, ""))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            gate.main(argv[:6] + argv[8:])  # --pr is required
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            gate.main(argv[:-2])  # --app-id is required


if __name__ == "__main__":
    unittest.main()
