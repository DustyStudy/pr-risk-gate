# pr-risk-gate

A merge gate that rates each pull request's risk and sets how many human approvals it needs.

| Risk tier | Human approvals | Typical change or additional requirement |
|---|---:|---|
| Low | 0 | Small changes such as a typo or lint fix |
| Medium | 1 | Most changes |
| High | 2 | Requires CODEOWNERS sign-off on security-owned paths |

Every tier requires an AI review verdict of PASS. The review is one Claude call per PR, with no tools, that judges correctness and security as well as risk.

Because low-risk changes need no human, the ruleset's native "required approving reviews" must be **0**. The gate enforces the counts, not GitHub.

The rating comes from two sources, and the higher one wins:

1. **Deterministic rules** (`policy/policy.json`): path rules for CI, infrastructure, auth, crypto, IAM, git plumbing and dependencies; diff size; deleted or shrunk tests; and a scan of added lines for secrets.
2. **Claude**, with no tools, reading the diff once. It can only raise the rating.

The result is posted as a required status check named `pr-risk-gate`, by a dedicated GitHub App. No PR, workflow or personal token can post it.

## Design

```
pull_request_target / pull_request_review  ->  pr-trigger workflow (base-branch file, no secrets, no code)
                                                  |
                                                  v  workflow_run (runs the DEFAULT branch's caller)
                                           gate job, in environment pr-risk-gate  ->  rate, count approvals, post check as the App
```

- The `pr-trigger` workflow runs the default branch's copy of its file, for PR events, because it uses `pull_request_target`. It has no secrets and runs no code. It exists only to fire the `workflow_run` caller.
- The App key and the Anthropic key live in a **GitHub environment**, `pr-risk-gate`. Its deployment branch rule allows only the default branch. A PR or branch job cannot read them, and neither can a workflow from a branch that is not the default branch.
- The gate reads the PR, rates the diff at the head commit, counts approvals and posts the check.
- A PR into any branch other than the default branch fails its check.
- The rating is cached per PR and head commit. Review events reuse it, so an approval cannot change the rating.

## Security model

- **Only the App can post the check.** The cache trusts only check runs made by the App's ID, so a forged check from a workflow or a personal token does not count.
- **The keys are only in the environment.** Repository secrets with the same names must not exist, or a branch workflow could read them. Setup below.
- **PR code never runs in a trusted job.** The trigger job has no checkout, and the gate checks out the PR only to read git objects.
- **The AI can only raise risk.** Final risk is the higher of the rule result and the AI result. An AI error, timeout, oversized diff, or unparseable reply counts as high.
- **Prompt injection is contained, not solved.** The diff is untrusted. The model has no tools and runs with `--bare`, and its reply is parsed strictly. A hostile diff can at most make the model say "low", and the rules still apply.
- **Approvals count only from people with write access.** An approval counts only if it is the reviewer's latest submitted review, is on the current head commit, is not from the PR author, the head commit's author or committer, or whoever pushed the head commit, is not from a bot, and comes from a user whose repository permission is admin, maintain or write.
- **A reply in a review thread counts as a new review.** GitHub records a comment reply as a COMMENTED review, so a reviewer who approves and then replies "thanks" loses the approval until they approve again. This is stricter than GitHub's own branch protection, on purpose.
- **Fail closed.** A rule error posts a failing check. A missing API key rates the PR high.
- **Same-repository PRs only, into the default branch only.** Fork PRs are refused, and so are runs with no PR attached and PRs into other branches.
- **A commit that heads more than one open PR is refused.** Otherwise one PR's approvals could satisfy another PR on the same commit.
- **Cancellation still posts a failure.** A writer who cancels a run cannot leave an earlier success standing.

## Known limits

- **Partly tested.** The main path runs live on the test repo (see Test status). Not yet confirmed: review-triggered runs (no review was submitted in testing), and everything listed as not tested there.
- **A PR can edit its own review trigger.** `pull_request_review` runs the PR's copy of the trigger file, and there is no `pull_request_review_target`. A PR that removes that trigger keeps its earlier check result until its next push. CODEOWNERS on `.github/workflows/` and "Require review from Code Owners" on the ruleset make that edit visible and need security approval before merge.
- **A failed mint leaves the earlier result standing.** If the App token cannot be minted (App outage, rotated key, wrong App ID), no failing check can be posted, and an older success on the SHA stays. Watch for `pr-risk-gate` runs that fail at the mint step.
- **The pusher comes from the repository activity log.** The gate excludes whoever moved the PR branch to the head commit (`repos/R/activity`), since commit author and committer are set by the pusher. If no activity entry names the push (lookup error, or the log lags just after a push), no approval counts: medium and high fail until the next review event re-runs the gate, and low is unaffected.
- **The App key is the root of trust.** Anyone with admin on the target repo can read environment secrets. Rotate the App key in GitHub and in the environment if it leaks.
- **Workflows that run in the trusted context stay trusted.** Protect the default branch: changes to the trigger, the caller or the gate must go through reviewed merges.
- **Rating re-rolls.** A marker-less failure as the newest App check forces a fresh AI rating. The deterministic floor still applies.
- **Dependabot PRs.** It is not known whether a Dependabot run can read the App key. If it cannot, its check fails at the mint step, which is fail-closed. Verify this on a live run.
- **Environments need a plan.** Environments with branch rules on private repos require a paid GitHub plan.
- **Gate repo visibility.** The caller checks this repo out with the default token, so this repo must be public, the same as issue-factory.

## Test status

Live-tested on the test repo `DustyStudy/factory-test-target`, which is public, with the gate at the commits listed. Re-test after any change to the gate, the policy, or the caller.

| What | Result |
|---|---|
| Unit tests (68) and CI on the gate repo (lint, gitleaks, zizmor) | Pass on every merged gate PR |
| Trigger, caller, gate and App check, end to end | Pass: PR #36 (low tier) posted `pr-risk-gate` success as the App |
| Environment secrets reach the reusable gate (App key and Anthropic key), with no repository-level copies | Pass: PR #36 mint and AI rating both succeeded |
| High tier with AI review CHANGES | Fail as designed: PR #37 (dependency pin), 0 of 2 approvals |
| Release candidate, low tier (docs only) | Pass: PR #40 posted success, 0 of 0 approvals, at `f0a7f15` and again at `20f232f` |
| Release candidate, medium tier with AI PASS and 0 approvals | Fail as designed: PR #41, 0 of 1 approvals. The first run found the failure step posting a generic error over the verdict (a listing race). Fixed with `--verdict-posted`; the re-run at the fix kept the verdict newest |
| Medium tier with AI PASS and 0 approvals (solo mode, since replaced) | Pass: PR #38. Current policy needs 1 human approval for medium, so this result no longer applies |

**Not tested live:**
- A PR approved by a second person: medium passing with 1 approval, and high passing with 2. Needs a second collaborator.
- A PR into a non-default base (should fail), and a fork PR (should fail).
- A cancelled or failed run leaving a failing check rather than an earlier success.
- The shared-commit refusal (two open PRs with the same head commit).
- A mint failure, which posts nothing (see Known limits).
- A PR that drops its review trigger, and a retarget that re-runs the gate.
- Rotating the App key.
- A low-risk PR merging with 0 approvals under the full ruleset from Setup step 6 (code owners on security paths only, last-push approval off).
- The pusher lookup with the App's token (`repos/R/activity`, Metadata read), and an approval by the person who pushed the head commit not counting.

## Setup

1. **Create the GitHub App** in the organisation or account that owns the target repos. Permissions: Checks read and write, Pull requests read, Contents read, Metadata read. No webhook. Install it on the target repos only.
2. **Create the environment** `pr-risk-gate` in each target repo. Under deployment branches, allow only the default branch.
3. **Store the secrets in the environment**, not as repository secrets: `PR_RISK_APP_KEY` (the App's private key) and `ANTHROPIC_API_KEY`. Store the App ID as the repository variable `PR_RISK_APP_ID`. Remove any repository secrets with these names.
   The gate job sets `environment: pr-risk-gate` and reads both secrets by these names. The caller job passes both by name (`PR_RISK_APP_KEY: ${{ secrets.PR_RISK_APP_KEY }}`, `ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}`), and the gate job's environment supplies the values. No repository-level secret may exist with either name. Verified on the test repo: PR #36 rated low with an AI PASS and posted its check through the App.
4. **Copy the workflows** to the target repo's default branch:
   - `examples/pr-trigger.yml` as `.github/workflows/pr-trigger.yml`.
   - `examples/caller.yml` as `.github/workflows/pr-risk-gate.yml`. Replace the placeholder SHA with the full commit SHA of the gate release you have reviewed.
5. **Add CODEOWNERS.** Copy `CODEOWNERS.example` to `.github/CODEOWNERS` and fill in the owners. List only security-owned paths. A catch-all `*` owner makes every PR need a code owner's approval, so low-risk PRs could no longer merge without a human.
6. **Add a branch ruleset** on the default branch:
   - Require status check `pr-risk-gate`, with its source pinned to the App.
   - Require your existing CI checks too. The gate does not replace tests.
   - Require approving reviews: **0**. The gate sets the human count per tier (0, 1 or 2).
   - Require review from Code Owners.
   - Dismiss stale approvals on new pushes.
   - Leave "Require approval of the most recent reviewable push" **off**. GitHub documents it as requiring someone other than the last pusher to approve, so it would give low-risk PRs a human requirement, and a ruleset cannot scope it by risk tier (rulesets target branches, and bypass lists name actors, not PRs). The gate enforces the same rule on the tiers that need humans: an approval counts only on the head commit and never from the person who pushed it.
   - Block bypass for everyone, including admins.

## Tests

```
python -m unittest discover -s tests -v
```
