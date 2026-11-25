import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, SCRIPTS)

import risk

# Mirrors policy/policy.json (test_shipped_policy_matches keeps the path rules in sync).
POLICY = {
    "size": {"medium_lines": 300, "high_lines": 1000, "medium_files": 10, "high_files": 30},
    "path_rules": [
        {"risk": "high", "reason": "CI or workflow file", "globs": [".github/**"]},
        {"risk": "high", "reason": "Git plumbing file",
         "globs": ["**/.gitmodules", "**/.gitattributes", "**/CODEOWNERS"]},
        {"risk": "high", "reason": "Infrastructure as code",
         "globs": ["**/*.tf", "**/*.tfvars", "**/*.tf.json", "**/*.hcl"]},
        {"risk": "high", "reason": "Auth, crypto, secrets, or IAM",
         "globs": ["**/auth/**", "**/*auth*", "**/*auth*/**", "**/crypto/**", "**/secrets/**",
                   "**/*iam*", "**/*iam*/**", "**/*kms*", "**/*kms*/**",
                   "**/*security_group*", "**/*security_group*/**"]},
        {"risk": "medium", "reason": "Dependency or build file",
         "globs": ["**/package-lock.json", "**/package.json", "**/yarn.lock", "**/pnpm-lock.yaml",
                   "**/poetry.lock", "**/pyproject.toml", "**/requirements*.txt", "**/Dockerfile*",
                   "**/go.mod", "**/go.sum", "**/Cargo.toml", "**/Cargo.lock", "**/Gemfile",
                   "**/Gemfile.lock", "**/pom.xml", "**/*.gradle*"]},
    ],
    "deleted_test_risk": "high",
    "secret_patterns": [
        {"name": "AWS access key id", "regex": "AKIA[0-9A-Z]{16}"},
        {"name": "private key block", "regex": "-----BEGIN [A-Z ]*PRIVATE KEY-----"},
        {"name": "generic token assignment",
         "regex": "(?i)(api[_-]?key|secret|token|password)\\s*[:=]\\s*['\"][^'\"\\s]{12,}['\"]"},
    ],
}

# Built at runtime so no secret-shaped literal sits in this file.
FAKE_KEY = "AKIA" + "Q" * 16


def classify(changes, added=(), deleted=None):
    return risk.classify(list(changes), list(added), POLICY, deleted)


class GlobTest(unittest.TestCase):
    def test_globs(self):
        cases = [
            ("main.tf", "**/*.tf", True),                 # **/x matches at the root
            ("a/b/main.tf", "**/*.tf", True),
            ("main.tfx", "**/*.tf", False),
            (".github/workflows/ci.yml", ".github/**", True),
            (".github", ".github/**", False),
            ("x/.github/ci.yml", ".github/**", False),    # anchored at the root
            ("auth/login.py", "**/auth/**", True),
            ("src/auth/a/b.py", "**/auth/**", True),
            ("src/author/b.py", "**/auth/**", False),
            ("a/b", "a/**/b", True),                      # ** is zero segments
            ("a/x/y/b", "a/**/b", True),
            ("ab", "a/**/b", False),
            ("src/app.py", "*.py", False),                # * does not cross /
            ("app.py", "*.py", True),
            ("Main.TF", "**/*.tf", False),                # match_glob itself is case-sensitive
            ("mainxtf", "**/*.tf", False),                # . is literal
            ("anything/at/all", "**", True),
        ]
        for path, pattern, want in cases:
            with self.subTest(path=path, pattern=pattern):
                self.assertIs(risk.match_glob(path, pattern), want)


class ClassifyTest(unittest.TestCase):
    def test_empty_diff_is_low(self):
        self.assertEqual(classify([]), {"risk": "low", "reasons": [], "files": 0, "lines": 0})

    def test_plain_change_is_low(self):
        r = classify([("M", "src/app.py")], [("src/app.py", 3, "x = 1")], {"src/app.py": 1})
        self.assertEqual((r["risk"], r["reasons"], r["files"], r["lines"]), ("low", [], 1, 2))

    def test_path_rules(self):
        cases = [
            (".github/workflows/ci.yml", "high", "CI or workflow file"),
            ("infra/main.tf", "high", "Infrastructure as code"),
            ("prod.tfvars", "high", "Infrastructure as code"),
            ("infra/x.tf.json", "high", "Infrastructure as code"),
            ("src/auth/login.py", "high", "Auth, crypto, secrets, or IAM"),
            ("crypto/aes.py", "high", "Auth, crypto, secrets, or IAM"),
            ("deploy/secrets/a.yaml", "high", "Auth, crypto, secrets, or IAM"),
            ("modules/iam_roles.py", "high", "Auth, crypto, secrets, or IAM"),
            ("kms.py", "high", "Auth, crypto, secrets, or IAM"),
            ("net/security_group_rules.py", "high", "Auth, crypto, secrets, or IAM"),
            ("package-lock.json", "medium", "Dependency or build file"),
            ("api/poetry.lock", "medium", "Dependency or build file"),
            ("requirements-dev.txt", "medium", "Dependency or build file"),
            ("docker/Dockerfile.prod", "medium", "Dependency or build file"),
            ("go.sum", "medium", "Dependency or build file"),
            # a. sensitive directory names, not only file names
            ("terraform/iam/roles.json", "high", "Auth, crypto, secrets, or IAM"),
            ("iam/policy.json", "high", "Auth, crypto, secrets, or IAM"),
            ("modules/security_group/rules.json", "high", "Auth, crypto, secrets, or IAM"),
            ("keys/kms_prod/key.json", "high", "Auth, crypto, secrets, or IAM"),
            ("services/authz/x.py", "high", "Auth, crypto, secrets, or IAM"),
            ("src/oauth_client.py", "high", "Auth, crypto, secrets, or IAM"),
            # b. path rules ignore case; the reason keeps the path as git reports it
            ("infra/IAM_roles.json", "high", "Auth, crypto, secrets, or IAM"),
            ("Auth/login.py", "high", "Auth, crypto, secrets, or IAM"),
            ("src/Kms.py", "high", "Auth, crypto, secrets, or IAM"),
            ("infra/MAIN.TF", "high", "Infrastructure as code"),
            ("dockerfile", "medium", "Dependency or build file"),
            # c. git plumbing
            (".gitmodules", "high", "Git plumbing file"),
            (".gitattributes", "high", "Git plumbing file"),
            ("sub/.gitattributes", "high", "Git plumbing file"),
            ("CODEOWNERS", "high", "Git plumbing file"),
            ("docs/CODEOWNERS", "high", "Git plumbing file"),
            # d. HCL
            ("live/prod/terragrunt.hcl", "high", "Infrastructure as code"),
            (".terraform.lock.hcl", "high", "Infrastructure as code"),
            # e. dependency and build files
            ("package.json", "medium", "Dependency or build file"),
            ("web/package.json", "medium", "Dependency or build file"),
            ("go.mod", "medium", "Dependency or build file"),
            ("svc/go.sum", "medium", "Dependency or build file"),
            ("Cargo.toml", "medium", "Dependency or build file"),
            ("crates/a/Cargo.lock", "medium", "Dependency or build file"),
            ("pyproject.toml", "medium", "Dependency or build file"),
            ("yarn.lock", "medium", "Dependency or build file"),
            ("pnpm-lock.yaml", "medium", "Dependency or build file"),
            ("Gemfile", "medium", "Dependency or build file"),
            ("Gemfile.lock", "medium", "Dependency or build file"),
            ("pom.xml", "medium", "Dependency or build file"),
            ("build.gradle", "medium", "Dependency or build file"),
            ("app/build.gradle.kts", "medium", "Dependency or build file"),
            ("settings.gradle", "medium", "Dependency or build file"),
        ]
        for path, want, reason in cases:
            with self.subTest(path=path):
                r = classify([("M", path)])
                self.assertEqual(r["risk"], want)
                self.assertEqual(r["reasons"], [f"{reason}: {path}"])

    def test_codeowners_under_github_hits_both_rules(self):
        r = classify([("M", ".github/CODEOWNERS")])
        self.assertEqual(r["risk"], "high")
        self.assertEqual(r["reasons"], ["CI or workflow file: .github/CODEOWNERS",
                                        "Git plumbing file: .github/CODEOWNERS"])

    def test_shipped_policy_matches(self):
        with open(os.path.join(SCRIPTS, "..", "policy", "policy.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["path_rules"], POLICY["path_rules"])

    def test_highest_floor_wins_and_reason_per_rule(self):
        r = classify([("M", "go.sum"), ("A", "a.tf"), ("A", "b.tf")])
        self.assertEqual(r["risk"], "high")
        self.assertEqual(r["reasons"], ["Infrastructure as code: a.tf (+1 more)",
                                        "Dependency or build file: go.sum"])

    def test_renamed_and_copied_paths_count(self):
        self.assertEqual(classify([("R", "docs/a.md"), ("R", ".github/a.md")])["risk"], "high")
        self.assertEqual(classify([("R", ".github/a.md"), ("R", "docs/a.md")])["risk"], "high")
        self.assertEqual(classify([("C", "infra/copy.tf")])["risk"], "high")

    def test_size_thresholds(self):
        def lines(n):
            return classify([("M", "a.py")], [("a.py", i, "x") for i in range(n)])

        self.assertEqual(lines(300)["risk"], "low")          # "over", not "at"
        self.assertEqual(lines(301)["risk"], "medium")
        self.assertEqual(lines(1000)["risk"], "medium")
        self.assertEqual(lines(1001)["risk"], "high")
        self.assertEqual(lines(1001)["reasons"], ["1001 lines changed (over 1000)"])
        # deleted lines count too
        r = classify([("M", "a.py")], [("a.py", 1, "x")], {"a.py": 200, "/dev/null": 100})
        self.assertEqual((r["risk"], r["lines"]), ("medium", 301))

        def files(n):
            return classify([("M", f"src/f{i}.py") for i in range(n)])

        self.assertEqual(files(10)["risk"], "low")
        self.assertEqual(files(11)["risk"], "medium")
        self.assertEqual(files(30)["risk"], "medium")
        self.assertEqual(files(31)["risk"], "high")
        self.assertEqual(files(31)["files"], 31)

    def test_deleted_tests(self):
        for path in ("tests/test_a.py", "test/a.js", "pkg/tests/data.json", "src/test_util.py",
                     "pkg/thing_test.go", "web/app.spec.ts"):
            with self.subTest(path=path):
                r = classify([("D", path)])
                self.assertEqual(r["risk"], "high")
                self.assertEqual(r["reasons"], [f"deleted test file: {path}"])
        self.assertEqual(classify([("D", "src/app.py")])["risk"], "low")
        self.assertEqual(classify([("M", "tests/test_a.py")])["risk"], "low")
        self.assertEqual(classify([("D", "src/contest/a.py")])["risk"], "low")

    def test_deleted_test_risk_comes_from_policy(self):
        policy = dict(POLICY, deleted_test_risk="medium")
        self.assertEqual(risk.classify([("D", "tests/test_a.py")], [], policy)["risk"], "medium")
        r = risk.classify([("M", "tests/test_a.py")], [], policy, {"tests/test_a.py": 1})
        self.assertEqual(r["risk"], "medium")

    def test_shrunk_tests(self):
        t = "tests/test_a.py"
        one = [(t, 1, "pass")]
        r = classify([("M", t)], one, {t: 2})                     # 1 added, 2 deleted
        self.assertEqual((r["risk"], r["reasons"]), ("high", [f"test file shrunk: {t}"]))
        r = classify([("M", t)], [], {t: 40})                     # emptied
        self.assertEqual(r["reasons"], [f"test file shrunk: {t}"])
        # renamed inside tests/ and gutted on the way
        r = classify([("R", "tests/test_old.py"), ("R", t)], [], {t: 5})
        self.assertEqual(r["reasons"], [f"test file shrunk: {t}"])
        self.assertEqual(classify([("M", t)], one, {t: 1})["risk"], "low")      # same size
        self.assertEqual(classify([("M", t)], one * 3, {t: 1})["risk"], "low")  # only grows
        self.assertEqual(classify([("M", t)], one)["risk"], "low")
        # deletions in another file, or in a non-test file, do not count
        self.assertEqual(classify([("M", t), ("M", "src/a.py")], one, {"src/a.py": 9})["risk"], "low")
        self.assertEqual(classify([("M", "src/a.py")], [], {"src/a.py": 9})["risk"], "low")
        # a deleted test is reported once, as deleted
        self.assertEqual(classify([("D", t)], [], {"/dev/null": 9})["reasons"],
                         [f"deleted test file: {t}"])

    def test_secret_hits_do_not_leak_the_value(self):
        token = "tok" + "9" * 20
        added = [
            ("src/a.py", 7, f"key = '{FAKE_KEY}'"),
            ("src/a.py", 9, "-----BEGIN RSA " + "PRIVATE KEY-----"),
            ("conf/app.yml", 2, f'password: "{token}"'),
            ("src/a.py", 10, "password = input()"),
        ]
        r = classify([("M", "src/a.py"), ("M", "conf/app.yml")], added)
        self.assertEqual(r["risk"], "high")
        self.assertEqual(r["reasons"], [
            "possible secret in src/a.py:7",
            "possible secret in src/a.py:9",
            "possible secret in conf/app.yml:2",
        ])
        out = json.dumps(r)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn(token, out)

    def test_unknown_risk_in_policy_raises(self):
        policy = dict(POLICY, path_rules=[{"risk": "none", "reason": "x", "globs": ["**"]}])
        with self.assertRaises(ValueError):
            risk.classify([("M", "a.py")], [], policy)


class ParseTest(unittest.TestCase):
    def test_name_status(self):
        out = "M\0a.py\0R100\0old.py\0new.py\0C75\0x.tf\0y.tf\0D\0gone.py\0"
        self.assertEqual(risk.parse_name_status(out), [
            ("M", "a.py"), ("R", "old.py"), ("R", "new.py"), ("C", "y.tf"), ("D", "gone.py")])
        self.assertEqual(risk.parse_name_status(""), [])

    def test_test_renamed_out_of_tests_is_a_deletion(self):
        self.assertEqual(risk.parse_name_status("R100\0tests/test_a.py\0attic/a.txt\0"),
                         [("D", "tests/test_a.py"), ("R", "attic/a.txt")])
        self.assertEqual(risk.parse_name_status("R090\0tests/test_a.py\0tests/test_b.py\0"),
                         [("R", "tests/test_a.py"), ("R", "tests/test_b.py")])

    def test_name_status_errors(self):
        for bad in ("X\0a.py\0", "M\0", "R100\0only-one\0"):
            with self.subTest(bad=bad), self.assertRaises((ValueError, IndexError)):
                risk.parse_name_status(bad)

    def test_patch(self):
        out = (
            "diff --git a/a.py b/a.py\n"
            "index 111..222 100644\n"
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -3,2 +3 @@ def f():\n"
            "-old one\n"
            "-old two\n"
            "+new\n"
            "@@ -9,0 +9,2 @@\n"
            "+++ b/not-a-header\n"       # added line whose text starts with "++ "
            "+last\n"
            "\\ No newline at end of file\n"
            "diff --git a/gone.py b/gone.py\n"
            "--- a/gone.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-bye\n"
        )
        added, deleted = risk.parse_patch(out)
        self.assertEqual(added, [("a.py", 3, "new"), ("a.py", 9, "++ b/not-a-header"),
                                 ("a.py", 10, "last")])
        self.assertEqual(deleted, {"a.py": 2, "/dev/null": 1})
        self.assertEqual(risk.parse_patch(""), ([], {}))

    def test_unquote_git(self):
        cases = [
            ("tests/test_a.py", "tests/test_a.py"),                    # plain
            ('"b/tests/test_a\\"b.py"', 'b/tests/test_a"b.py'),
            ('"a\\\\b\\tc"', "a\\b\tc"),
            ('"infra/\\303\\251t\\303\\251.tf"', "infra/été.tf"),      # octal UTF-8 bytes
            ('"infra/été\\"x.tf"', 'infra/été"x.tf'),                  # raw non-ASCII inside quotes
            ('"\\1341"', "\\1"),                                       # \134 is a backslash, not an escape
            ('a"b', 'a"b'),                                            # not wrapped: unchanged
            ('"open', '"open'),
            ('"', '"'),
            ("a\\303b", "a\\303b"),
        ]
        for s, want in cases:
            with self.subTest(s=s):
                self.assertEqual(risk.unquote_git(s), want)
        with self.assertRaises(KeyError):
            risk.unquote_git('"a\\qb"')

    def test_quoted_test_path_shrunk(self):
        path = 'tests/test_a"b.py'
        out = (
            'diff --git "a/tests/test_a\\"b.py" "b/tests/test_a\\"b.py"\n'
            '--- "a/tests/test_a\\"b.py"\n'
            '+++ "b/tests/test_a\\"b.py"\n'
            "@@ -2,2 +1,0 @@\n"
            "-one\n"
            "-two\n"
        )
        added, deleted = risk.parse_patch(out)
        self.assertEqual((added, deleted), ([], {path: 2}))
        r = classify(risk.parse_name_status(f"M\0{path}\0"), added, deleted)
        self.assertEqual((r["risk"], r["reasons"]), ("high", [f"test file shrunk: {path}"]))

    def test_patch_errors(self):
        with self.assertRaises(ValueError):
            risk.parse_patch("+++ b/a\n@@ -0,0 +1,2 @@\n+one\n")        # truncated
        with self.assertRaises(ValueError):
            risk.parse_patch("+++ b/a\n@@ -0,0 +1,2 @@\n+one\n context\n")


@unittest.skipUnless(shutil.which("git"), "git not installed")
class CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.policy = os.path.join(self.dir, "policy.json")
        self.repo = os.path.join(self.dir, "repo")
        os.mkdir(self.repo)
        with open(self.policy, "w", encoding="utf-8") as f:
            json.dump(POLICY, f)
        self.git("init", "-q")
        self.write("src/app.py", "a\nb\nc\n")
        self.write("tests/test_app.py", "t\n")
        self.base = self.commit()

    def git(self, *args):
        cmd = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args]
        return subprocess.run(cmd, cwd=self.repo, check=True, capture_output=True, text=True).stdout

    def write(self, path, text):
        full = os.path.join(self.repo, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "--no-verify", "-m", "c")
        return self.git("rev-parse", "HEAD").strip()

    def run_cli(self, base, head):
        return subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "risk.py"), "--policy", self.policy,
             f"--base={base}", f"--head={head}"],
            cwd=self.repo, capture_output=True, text=True, check=False)

    def test_end_to_end(self):
        self.write("src/app.py", "a\nB\nc\nkey = '" + FAKE_KEY + "'\n")
        self.write("infra/été.tf", "x\n")                 # non-ASCII path must still match
        self.write(".gitattributes", "* -diff\n")         # must not hide lines from the scan
        os.remove(os.path.join(self.repo, "tests", "test_app.py"))
        head = self.commit()

        p = self.run_cli(self.base, head)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(FAKE_KEY, p.stdout + p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual(r["risk"], "high")
        self.assertEqual(r["files"], 4)
        self.assertEqual(r["lines"], 6)                   # 4 added + 2 deleted
        self.assertEqual(sorted(r["reasons"]), sorted([
            "Git plumbing file: .gitattributes",
            "Infrastructure as code: infra/été.tf",
            "deleted test file: tests/test_app.py",
            "possible secret in src/app.py:4",
        ]))

    def test_shrunk_test_end_to_end(self):
        self.write("tests/test_app.py", "t\n1\n2\n3\n")
        grown = self.commit()
        self.assertEqual(json.loads(self.run_cli(self.base, grown).stdout)["risk"], "low")
        self.write("tests/test_app.py", "x\n")
        r = json.loads(self.run_cli(grown, self.commit()).stdout)
        self.assertEqual((r["risk"], r["lines"]), ("high", 5))
        self.assertEqual(r["reasons"], ["test file shrunk: tests/test_app.py"])

    def test_empty_diff_is_low(self):
        p = self.run_cli(self.base, self.base)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {"risk": "low", "reasons": [], "files": 0, "lines": 0})

    def test_errors_exit_1(self):
        for base, head in (("0" * 40, self.base), ("--output=x", self.base)):
            with self.subTest(base=base):
                p = self.run_cli(base, head)
                self.assertEqual(p.returncode, 1)
                self.assertEqual(p.stdout, "")
                self.assertTrue(p.stderr.startswith("risk.py: "))
        self.policy = os.path.join(self.dir, "missing.json")
        self.assertEqual(self.run_cli(self.base, self.base).returncode, 1)


if __name__ == "__main__":
    unittest.main()
