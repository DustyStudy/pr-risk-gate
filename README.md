# pr-risk-gate

A merge gate that rates each pull request's risk and sets how many human approvals it needs.

Tiers follow Anthropic's own review model:

- **Low** risk (smaller changes, like a typo or lint fix): no human approval. The AI review must return PASS.
- **Medium** risk (most changes): 1 human approval, plus the AI review PASS.
- **High** risk (riskiest changes): 2 human approvals, plus the AI review PASS and CODEOWNERS sign-off on security-owned paths.

Every tier also requires the AI review verdict PASS. The review is one Claude call per PR, with no tools, that judges correctness and security as well as risk.

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
- **Approvals count only from people with write access.** An approval counts only if it is the reviewer's latest submitted review, is on the current head commit, is not from the PR author or the head commit's author or committer, is not from a bot, and comes from a user whose repository permission is admin, maintain or write.
- **A reply in a review thread counts as a new review.** GitHub records a comment reply as a COMMENTED review, so a reviewer who approves and then replies "thanks" loses the approval until they approve again. This is stricter than GitHub's own branch protection, on purpose.
- **Fail closed.** A rule error posts a failing check. A missing API key rates the PR high.
- **Same-repository PRs only, into the default branch only.** Fork PRs are refused, and so are runs with no PR attached and PRs into other branches.
- **A commit that heads more than one open PR is refused.** Otherwise one PR's approvals could satisfy another PR on the same commit.
- **Cancellation still posts a failure.** A writer who cancels a run cannot leave an earlier success standing.

## Known limits

- **Not yet run on GitHub.** The workflows and the App flow are unverified until a live run. Test on a throwaway target repo first. The assumptions to check first: `workflow_run.pull_requests` is filled for review-triggered runs, and `job.workflow_sha` resolves inside the called workflow.
- **A PR can edit its own review trigger.** `pull_request_review` runs the PR's copy of the trigger file, and there is no `pull_request_review_target`. A PR that removes that trigger keeps its earlier check result until its next push. CODEOWNERS on `.github/workflows/` and "Require review from Code Owners" on the ruleset make that edit visible and need security approval before merge.
- **A failed mint leaves the earlier result standing.** If the App token cannot be minted (App outage, rotated key, wrong App ID), no failing check can be posted, and an older success on the SHA stays. Watch for `pr-risk-gate` runs that fail at the mint step.
- **A pusher can approve their own commit.** The commit API reports the commit's author and committer, which the pusher can set to someone else. It does not say who pushed. Closing this needs another source for the pusher.
- **The App key is the root of trust.** Anyone with admin on the target repo can read environment secrets. Rotate the App key in GitHub and in the environment if it leaks.
- **Workflows that run in the trusted context stay trusted.** Protect the default branch: changes to the trigger, the caller or the gate must go through reviewed merges.
- **Rating re-rolls.** A marker-less failure as the newest App check forces a fresh AI rating. The deterministic floor still applies.
- **Dependabot PRs.** It is not known whether a Dependabot run can read the App key. If it cannot, its check fails at the mint step, which is fail-closed. Verify this on a live run.
- **Environments need a plan.** Environments with branch rules on private repos require a paid GitHub plan.
- **Gate repo visibility.** The caller checks this repo out with the default token, so this repo must be public, the same as issue-factory.

## Setup

1. **Create the GitHub App** in the organisation or account that owns the target repos. Permissions: Checks read and write, Pull requests read, Contents read, Metadata read. No webhook. Install it on the target repos only.
2. **Create the environment** `pr-risk-gate` in each target repo. Under deployment branches, allow only the default branch.
3. **Store the secrets in the environment**, not as repository secrets: `PR_RISK_APP_KEY` (the App's private key) and `ANTHROPIC_API_KEY`. Store the App ID as the repository variable `PR_RISK_APP_ID`. Remove any repository secrets with these names.
4. **Copy the workflows** to the target repo's default branch:
   - `examples/pr-trigger.yml` as `.github/workflows/pr-trigger.yml`.
   - `examples/caller.yml` as `.github/workflows/pr-risk-gate.yml`. Replace the placeholder SHA with the full commit SHA of the gate release you have reviewed.
5. **Add CODEOWNERS.** Copy `CODEOWNERS.example` to `.github/CODEOWNERS` and fill in the owners.
6. **Add a branch ruleset** on the default branch:
   - Require status check `pr-risk-gate`, with its source pinned to the App.
   - Require your existing CI checks too. The gate does not replace tests.
   - Require approving reviews: **0**. The gate sets the human count per tier (0, 1 or 2).
   - Require review from Code Owners.
   - Dismiss stale approvals on new pushes.
   - Require approval of the most recent reviewable push.
   - Block bypass for everyone, including admins.

## Tests

```
python -m unittest discover -s tests -v
```
