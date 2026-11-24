# Release checklist: v1.0.0 (first tagged release)

Release candidate branch: `claude/project-thread-lgayde`. Baseline: `main` at `bcf8b55`.

## Scope and assumptions

- The product is the reusable workflow `.github/workflows/pr-gate.yml` plus `scripts/`, `policy/`, `prompts/` and the two example workflows that target repos copy. There is no package or build; a "release" is a git tag whose full SHA target repos pin in `examples/caller.yml`.
- No tag exists yet. `SECURITY.md` supports only the latest tagged release and `examples/caller.yml` asks for a reviewed release SHA, so the release needs a first tag (assumed `v1.0.0`).
- Supported environment: GitHub-hosted `ubuntu-latest` runners (bash, jq, python3, gh, node/npm), Claude Code CLI 2.1.317. Python checked locally on 3.11, 3.12 and 3.13.
- Baseline for behaviour: README.md and SPEC.md. Items in SPEC "Out of scope for v1" stay out of scope.
- Live checks run on `DustyStudy/factory-test-target` with a real App and key. They cannot run from this session (no App key, no second collaborator, no paid calls), so they stay open below.

## Criteria

Status: PASS, FIXED (was failing, fixed on this branch), OPEN (needs a live run or a decision).

| # | Criterion (expected behaviour) | Status | Evidence or blocker |
|---|---|---|---|
| 1 | Unit tests pass: `python -m unittest discover -s tests -v` | PASS | 68 tests OK on Python 3.11, 3.12, 3.13, from a fresh clone of the branch. Baseline was 54. |
| 2 | Lint: ruff, `py_compile`, shellcheck `--severity=style` | PASS | ruff 0.16.9 (CI pin) clean; shellcheck clean; compile OK |
| 3 | Workflow security: zizmor 1.30.1 `--min-severity medium`, no `github.event` interpolation in `run:` | PASS | 0 findings over `.github` and both examples (offline mode locally; CI runs online). CI now audits the examples too. |
| 4 | Secret scan: gitleaks over full history | PASS (CI) | Green on `main` at `bcf8b55`; rerun by CI on the release PR |
| 5 | `ai_rate.sh` fails closed: every error prints `high`/`CHANGES`, exactly one JSON line, exit 0 | FIXED | A failing EXIT-trap cleanup under `set -e` replaced the exit status (127 seen), so the AI step failed instead of printing the fallback. Fixed with `|| true`; regression `test_failed_cleanup_does_not_change_the_exit_status`. The script had no tests; `tests/test_ai_rate.py` now covers 20+ fail-closed paths with a fake CLI (mocked). |
| 6 | Pinned Claude CLI 2.1.317 accepts every flag `ai_rate.sh` passes | PASS | Installed with `--ignore-scripts` + `install.cjs` as in the workflow; a call with a fake key returned an auth error envelope and exit 1 (flags accepted; unknown flags are rejected). No paid call. |
| 7 | `risk.py` CLI rates a real git range and fails closed on bad input | PASS | Smoke on a scratch repo: docs change -> low; workflow + auth path + deleted test + token -> high with 4 reasons, no secret value printed; bad revision -> exit 1; option-like base -> exit 2 |
| 8 | `gate.py run` / `rating-cache get` through a real `gh` subprocess | PASS (mocked gh) | Fake `gh` on PATH: medium, 0 approvals -> failure check, exit 1; 1 write-access approval -> success, exit 0; cache returns the posted marker for the App's ID and nothing for another App ID |
| 9 | Documented tiers hold under the documented setup: low needs 0 humans | FIXED (docs), OPEN (live) | `CODEOWNERS.example` had a catch-all `*` owner and README told users to enable "Require review from Code Owners" and "Require approval of the most recent reviewable push". GitHub documents both as requiring an approval, so low-risk PRs could not merge without a human. Removed the `*` owner, set last-push approval to off with the reason. A ruleset cannot scope that setting per tier, so the gate now enforces it itself (row 15). Needs one live low-tier merge under the full ruleset. |
| 10 | SPEC matches the code | FIXED | `--base-ref` and the base check, `author_association` in rule 7, `failure() || cancelled()`, Metadata read permission, and the out-of-scope line that contradicted rule 11. |
| 11 | End to end on the test repo: trigger, caller, gate, App check | PASS (live) | Release candidate `f0a7f15`: low-tier PR #40 posted success 0/0; medium PR #41 posted failure 0/1 with AI PASS; `.github` PR #39 rated high. At `20f232f`: PR #40 (head `56a8a83`) passed 0/0; PR #41 failed 0/1 with AI PASS, verdict kept newest. Later commits on this branch change docs only. |
| 17 | A failing verdict stays the newest check (the failure step does not post over it) | FIXED, PASS (live) | Live on PR #41: the failure step listed check runs 20 ms after the verdict POST, did not see it, and posted `pr-risk-gate: error` over it, dropping the reason and the cache marker. Now `gate.py run --verdict-posted` writes a file after the verdict POST and the step skips on it. Regression `test_verdict_posted_file_only_after_the_verdict_is_posted`. Reproduced again on test PR #42 under the old pin. At `20f232f`, PR #41 (head `d4fc92c`) posted only its verdict and the failure step was skipped. |
| 12 | Medium passes with 1 approval, high with 2 | OPEN (deferred) | Needs a second account; Dusty has one account only. Unit tests cover the counting. |
| 13 | Non-default base fails; fork PR fails; shared head commit fails | PASS (unit), OPEN (live) | Unit tests cover the gate logic; live runs not done |
| 14 | Cancelled or failed run leaves a failing check | OPEN | Workflow step present; not run live |
| 15 | The person who pushed the head commit cannot approve it (GitHub's last-push rule, per tier) | FIXED (unit), OPEN (live) | Was a README known limit: the gate excluded only commit author and committer, which the pusher sets. `gate.py` now reads the pusher from `repos/R/activity` and excludes them; unknown pusher -> no approval counts. 3 new tests. The endpoint returned the real pusher on this repo with a user token; needs a live run with the App token. |
| 16 | First release tag exists and `caller.yml` docs point at it | OPEN | Needs Dusty's go-ahead to tag after the PR merges |

## Checks that used mocks

Rows 5 and 8 used a fake `claude` and a fake `gh`. Row 6 used the real CLI with a fake key. No live App, key, or paid model call was used.
