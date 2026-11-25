# Release checklist: v1.1.0

Release branch: `release/v1.1.0`. Baseline: `main` at `337dd59` (v1.0.0 at `121ffc9` plus #8-#11).

## Scope and assumptions

- The product is the reusable workflow `.github/workflows/pr-gate.yml` plus `scripts/`, `policy/`, `prompts/` and the two example workflows that target repos copy. A release is a git tag whose full SHA target repos pin in `examples/caller.yml`.
- v1.0.0 is tagged. This release ships what merged since (#8-#11) plus the fixes below. No open issues or PRs exist; no Dependabot or code-scanning alerts are open.
- Supported environment: GitHub-hosted `ubuntu-latest` runners (bash, jq, python3, gh, node/npm), Claude Code CLI 2.1.317. Local verification runs in an `ubuntu:24.04` container from a fresh clone of the branch (the scripts need bash and jq; the Windows host is not a supported environment).
- Behaviour baseline: README.md and SPEC.md. SPEC "Out of scope for v1" stays out of scope.
- Live checks run on `DustyStudy/factory-test-target` with the real App and key. They cannot run from this session (no App key, no second collaborator), so they stay open.

## Criteria

Status: PASS, FIXED (was failing, fixed on this branch), OPEN (needs a live run, an approval, or a decision).

| # | Criterion (expected behaviour) | Status | Evidence or blocker |
|---|---|---|---|
| 1 | Unit tests pass: `python3 -m unittest discover -s tests` | PASS | 74 OK on a fresh clone at `2caa813` (ubuntu:24.04, Python 3.12). Baseline 68 at `337dd59`. |
| 2 | Lint: ruff 0.16.9 (hash-pinned), `py_compile`, shellcheck `--severity=style` | PASS | Fresh clone in ubuntu:24.04 |
| 3 | Workflow security: zizmor 1.30.1 `--min-severity medium` over `.github` and both examples | PASS (offline) | 0 findings locally (offline); CI runs online on the PR |
| 4 | Secret scan (gitleaks, full history) and Trivy fs scan | PASS (CI) | Green on `main` at `337dd59`; CI reruns both on the release PR |
| 5 | A submodule pointer change rates high (supply-chain change the diff does not show) | FIXED | Was `low`: `risk.py` read `--name-status`, which has no modes. Now reads `--raw` and floors any 160000-mode change at high. Regressions `test_raw_records_and_submodule_pointers`, `test_submodule_pointer_bump_is_high` (both fail on the old code). |
| 6 | A gate upgrade with a different policy re-rates open PRs | FIXED | Was: cached rating keyed on PR and head SHA only, reused until the next push. Marker now carries `policy_id`; mismatch is a miss. Regression in `test_cache_get_newest_run_wins_and_misses_are_silent`. One extra AI call per open PR after an upgrade. |
| 6a | A gate upgrade that changes only rating code or the prompt also re-rates | FIXED | Codex confirm pass: `policy_id` hashed the policy only. It now also hashes `risk.py`, `ai_rate.sh`, `json_field.py`, `prompts/risk.md`. Test `test_policy_id_covers_policy_and_rating_code`. |
| 7f | The base commit from the lookup is in the target clone | FIXED (code), OPEN (live) | Codex confirm pass: the target was checked out before the base lookup, so a base that moved in between was missing (false failure, fail-closed). Checkout now runs after the lookup. |
| 7a | A `.gitmodules` `ignore = all` cannot hide a submodule pointer change | FIXED | Found by Codex, reproduced: the bump vanished from both diffs (`files: 0`, low, empty AI input). All three diffs now pass `--ignore-submodules=none`. Regression `test_ignored_submodule_is_still_seen`. |
| 7b | A test file replaced by a symlink counts as a removed test | FIXED | Found by Codex: a type change (`T`) skipped the floor. Regression `test_test_replaced_by_symlink_is_a_deletion`. |
| 7c | A rename counts as one changed file (SPEC size rule) | FIXED | Found by Codex: six doc renames counted as 12 files (medium). Regression `test_rename_counts_as_one_file_and_keeps_both_paths_for_rules`, which also checks a renamed `.github/` path stays high. |
| 7d | A re-run cannot rate against a stale base | FIXED (code), OPEN (live) | Found by Codex (plausible), attack confirmed by reading: retarget to the default branch, cancel the new run, re-run an old run from the other base; the old event's `base.sha` gave a smaller diff and `gate.py` checks only the base ref name. The gate now reads the base from the PR with the App token and fails unless open, at the head SHA, into the default branch. Inline workflow bash: no unit test; needs a live run. |
| 7e | Codex finding "failure posted on the wrong commit" | REJECTED | Live data: pr-trigger run 45304003512 (`pull_request_target`) has `head_sha` 56a8a83, PR #40's head, and the App's success check is on 56a8a83. |
| 7 | README security model states the low-tier trust accurately | FIXED (docs) | Said a hostile diff can at most make the model say "low"; it can also yield PASS, so a rules-low diff merges with no human. Kept open for review as residual risk R1. |
| 8 | Medium passes with 1 approval, high with 2 (live) | OPEN | Needs a second GitHub account. Unit tests cover the counting. |
| 9 | Non-default base, fork PR, shared head commit, cancelled run each leave a failing check (live) | OPEN | Unit-tested; needs live runs on the test repo |
| 10 | Pusher lookup with the App token; low-tier merge under the full ruleset (live) | OPEN | Needs a live run |
| 11 | End to end on the test repo with the release candidate SHA | OPEN | Needs the release candidate pinned in the test repo's caller and one low and one medium PR, as for v1.0.0 |
| 12 | v1.1.0 tag and release | OPEN | Needs Dusty's go-ahead after the PR merges |

## Residual risks for review

- **R1. Low tier trusts the model.** A diff the rules rate low (small, no sensitive path) merges with 0 humans if the model says low and PASS. Prompt injection can push the model there. This is the documented product design (README tiers); changing it is a product decision.

## Checks that used mocks

Unit tests use a fake `claude` (tests/test_ai_rate.py) and a mocked `gh_api` (tests/test_gate.py). No live App, key, or paid model call was used in this session.

## Verification runs

| When | Commit | Where | Result |
|---|---|---|---|
| Baseline | `337dd59` | ubuntu:24.04 container, fresh clone | 68 tests OK, shellcheck ok. Main CI (lint, tests, gitleaks, zizmor, Trivy, CodeQL) green. Windows host: 22 test failures, all bash/jq/symlink tests that need Linux; not a supported environment. |
| After fixes | `ce3bc80` | ubuntu:24.04 container, fresh clone, `scratchpad/verify.sh` mirroring ci.yml | 73 tests OK; shellcheck ok; ruff 0.16.9 (hash-pinned) clean; py_compile ok; zizmor 1.30.1 offline 0 findings; no event interpolation in `run:` |
| After Codex confirm pass | `2caa813` | same | 74 tests OK; shellcheck, ruff, py_compile, zizmor (offline), interpolation check all clean |

## Review

- Fable (the required reviewer tier for CI and security) was rate-limited until Nov 28; the independent review went to Codex (GPT-6 Astra, read-only), which reported five findings: one rejected with live evidence, four fixed (7a-7d). Its one confirm pass found two more, both fixed in `2caa813` (rows 6a, 7f); it withdrew the rejected finding.

