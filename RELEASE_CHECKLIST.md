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
| 1 | Unit tests pass: `python -m unittest discover -s tests -v` | PASS | 64 tests OK on Python 3.11, 3.12, 3.13, from a fresh clone of the branch. Baseline was 54. |
| 2 | Lint: ruff, `py_compile`, shellcheck `--severity=style` | PASS | ruff 0.16.9 (CI pin) clean; shellcheck clean; compile OK |
| 3 | Workflow security: zizmor 1.30.1 `--min-severity medium`, no `github.event` interpolation in `run:` | PASS | 0 findings over `.github` and both examples (offline mode locally; CI runs online). CI now audits the examples too. |
| 4 | Secret scan: gitleaks over full history | PASS (CI) | Green on `main` at `bcf8b55`; rerun by CI on the release PR |
| 5 | `ai_rate.sh` fails closed: every error prints `high`/`CHANGES`, exactly one JSON line, exit 0 | FIXED | A failing EXIT-trap cleanup under `set -e` replaced the exit status (127 seen), so the AI step failed instead of printing the fallback. Fixed with `|| true`; regression `test_failed_cleanup_does_not_change_the_exit_status`. The script had no tests; `tests/test_ai_rate.py` now covers 20+ fail-closed paths with a fake CLI (mocked). |
| 6 | Pinned Claude CLI 2.1.317 accepts every flag `ai_rate.sh` passes | PASS | Installed with `--ignore-scripts` + `install.cjs` as in the workflow; a call with a fake key returned an auth error envelope and exit 1 (flags accepted; unknown flags are rejected). No paid call. |
| 7 | `risk.py` CLI rates a real git range and fails closed on bad input | PASS | Smoke on a scratch repo: docs change -> low; workflow + auth path + deleted test + token -> high with 4 reasons, no secret value printed; bad revision -> exit 1; option-like base -> exit 2 |
| 8 | `gate.py run` / `rating-cache get` through a real `gh` subprocess | PASS (mocked gh) | Fake `gh` on PATH: medium, 0 approvals -> failure check, exit 1; 1 write-access approval -> success, exit 0; cache returns the posted marker for the App's ID and nothing for another App ID |
| 9 | Documented tiers hold under the documented setup: low needs 0 humans | FIXED (docs), OPEN (live) | `CODEOWNERS.example` had a catch-all `*` owner and README told users to enable "Require review from Code Owners" and "Require approval of the most recent reviewable push". GitHub documents both as requiring an approval, so low-risk PRs could not merge without a human. Removed the `*` owner, set last-push approval to off with the reason. Needs one live low-tier merge under the full ruleset. |
| 10 | SPEC matches the code | FIXED | `--base-ref` and the base check, `author_association` in rule 7, `failure() || cancelled()`, Metadata read permission, and the out-of-scope line that contradicted rule 11. |
| 11 | End to end on the test repo: trigger, caller, gate, App check | PASS (live, earlier) | PR #36 on the test repo (README Test status). Re-test with the release SHA: OPEN |
| 12 | Medium passes with 1 approval, high with 2 | OPEN | Needs a second collaborator on the test repo |
| 13 | Non-default base fails; fork PR fails; shared head commit fails | PASS (unit), OPEN (live) | Unit tests cover the gate logic; live runs not done |
| 14 | Cancelled or failed run leaves a failing check | OPEN | Workflow step present; not run live |
| 15 | First release tag exists and `caller.yml` docs point at it | OPEN | Needs Dusty's go-ahead to tag after the PR merges |

## Checks that used mocks

Rows 5 and 8 used a fake `claude` and a fake `gh`. Row 6 used the real CLI with a fake key. No live App, key, or paid model call was used.
