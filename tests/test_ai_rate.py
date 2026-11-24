"""Fail-closed behaviour of scripts/ai_rate.sh and scripts/json_field.py (SPEC security rule 3).

A fake `claude` on PATH stands in for the CLI, so no model is called and no key is needed.
"""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCRIPT = os.path.join(ROOT, "scripts", "ai_rate.sh")
FALLBACK = {"risk": "high", "verdict": "CHANGES"}

# The fake CLI prints $FAKE_OUT (the envelope) and exits $FAKE_RC. It records its arguments and stdin.
FAKE = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$FAKE_DIR/args"
cat > "$FAKE_DIR/stdin"
env > "$FAKE_DIR/env"
printf '%s' "$FAKE_OUT"
exit "${FAKE_RC:-0}"
"""


def envelope(result, is_error=False):
    return json.dumps({"is_error": is_error, "result": result, "total_cost_usd": 0.01})


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "needs bash and jq")
class AiRateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.bin = os.path.join(self.dir.name, "bin")
        os.mkdir(self.bin)
        fake = os.path.join(self.bin, "claude")
        with open(fake, "w", encoding="utf-8") as f:
            f.write(FAKE)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
        self.diff = os.path.join(self.dir.name, "pr.diff")
        with open(self.diff, "w", encoding="utf-8") as f:
            f.write("diff --git a/x b/x\n+hello\n")

    def rate(self, out="", rc=0, key="test-key", diff=None):
        env = {
            "PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
            "HOME": self.dir.name,
            "FAKE_DIR": self.dir.name, "FAKE_OUT": out, "FAKE_RC": str(rc),
            "DIFF_FILE": self.diff if diff is None else diff,
            "GH_TOKEN": "must-not-reach-claude",
        }
        if key is not None:
            env["ANTHROPIC_API_KEY"] = key
        r = subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)  # always exits 0
        lines = r.stdout.splitlines()
        self.assertEqual(len(lines), 1, r.stdout)  # exactly one JSON line
        return json.loads(lines[0])

    def assertFallback(self, result, reason_part):
        self.assertEqual({k: result[k] for k in FALLBACK}, FALLBACK)
        self.assertIn(reason_part, result["reason"])

    def test_valid_reply_passes_through_with_only_three_fields(self):
        reply = json.dumps({"risk": "low", "verdict": "PASS", "reason": "docs only", "extra": "dropped"})
        self.assertEqual(self.rate(envelope(reply)), {"risk": "low", "verdict": "PASS", "reason": "docs only"})

    def test_reply_in_code_fence_is_parsed(self):
        reply = '```json\n{"risk":"medium","verdict":"CHANGES","reason":"r"}\n```'
        self.assertEqual(self.rate(envelope(reply))["risk"], "medium")

    def test_cli_call_flags_stdin_and_no_gh_token(self):
        self.rate(envelope('{"risk":"low","verdict":"PASS","reason":"r"}'))
        with open(os.path.join(self.dir.name, "args"), encoding="utf-8") as f:
            args = f.read().split("\n")
        for flag in ("--bare", "--tools", "--output-format", "--max-budget-usd", "--max-turns"):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("--tools") + 1], "")  # no tools
        self.assertEqual(args[args.index("--model") + 1], "claude-sonnet-5-5")
        with open(os.path.join(self.dir.name, "stdin"), encoding="utf-8") as f:
            self.assertIn("+hello", f.read())
        with open(os.path.join(self.dir.name, "env"), encoding="utf-8") as f:
            self.assertNotIn("GH_TOKEN=", f.read())

    def test_preconditions_fail_closed_without_calling_the_model(self):
        self.assertFallback(self.rate(key=None), "no key")
        self.assertFallback(self.rate(key=""), "no key")
        self.assertFallback(self.rate(diff=os.path.join(self.dir.name, "missing.diff")), "no diff file")
        with open(self.diff, "wb") as f:
            f.write(b"x" * 60001)
        self.assertFallback(self.rate(), "too large")
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "args")))

    def test_size_cap_is_inclusive(self):
        with open(self.diff, "wb") as f:
            f.write(b"x" * 60000)
        self.assertEqual(self.rate(envelope('{"risk":"low","verdict":"PASS","reason":"r"}'))["verdict"], "PASS")

    def test_nonzero_exit_is_never_trusted(self):
        self.assertFallback(self.rate(envelope('{"risk":"low","verdict":"PASS","reason":"r"}'), rc=3), "CLI exit 3")

    def test_missing_cli_fails_closed(self):
        # A real claude may be installed on the machine: use a PATH with only the tools the script needs.
        tools = os.path.join(self.dir.name, "tools")
        os.mkdir(tools)
        for name in ("jq", "python3", "cat", "wc", "mktemp", "rm", "dirname", "env"):
            os.symlink(shutil.which(name, path="/usr/bin:/bin") or shutil.which(name), os.path.join(tools, name))
        env = {"PATH": tools, "ANTHROPIC_API_KEY": "k", "DIFF_FILE": self.diff, "HOME": self.dir.name}
        r = subprocess.run([shutil.which("bash"), SCRIPT], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFallback(json.loads(r.stdout), "CLI exit 127")

    def test_failed_cleanup_does_not_change_the_exit_status(self):
        # Under `set -e` a failing command in the EXIT trap would become the script's exit status.
        rm = os.path.join(self.bin, "rm")
        with open(rm, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(rm, 0o755)
        reply = '{"risk":"low","verdict":"PASS","reason":"r"}'
        self.assertEqual(self.rate(envelope(reply))["verdict"], "PASS")
        self.assertFallback(self.rate(envelope(reply), rc=2), "CLI exit 2")

    def test_bad_replies_fail_closed(self):
        cases = {
            "error envelope": envelope('{"risk":"low","verdict":"PASS","reason":"r"}', is_error=True),
            "not json": "not json at all",
            "empty output": "",
            "envelope is a list": "[]",
            "null result": json.dumps({"is_error": False, "result": None}),
            "no object in reply": envelope("I think it is low."),
            "reply is an array": envelope("[1, 2]"),
            "two objects": envelope('{"risk":"low","verdict":"PASS","reason":"a"} {"risk":"high"}'),
        }
        for name, out in cases.items():
            with self.subTest(name):
                self.assertFallback(self.rate(out), "no valid reply")

    def test_invalid_ratings_fail_closed(self):
        cases = {
            "unknown risk": {"risk": "none", "verdict": "PASS", "reason": "r"},
            "uppercase risk": {"risk": "LOW", "verdict": "PASS", "reason": "r"},
            "missing verdict": {"risk": "low", "reason": "r"},
            "lowercase verdict": {"risk": "low", "verdict": "pass", "reason": "r"},
            "reason not a string": {"risk": "low", "verdict": "PASS", "reason": {"a": 1}},
            "missing reason": {"risk": "low", "verdict": "PASS"},
        }
        for name, reply in cases.items():
            with self.subTest(name):
                self.assertFallback(self.rate(envelope(json.dumps(reply))), "invalid rating")


if __name__ == "__main__":
    unittest.main()
