#!/usr/bin/env bash
# AI rating: one tool-less Claude call over the PR diff. Prints one JSON line: {"risk","verdict","reason"}.
# Fails closed: every failure path prints risk "high", verdict "CHANGES" and exits 0 (SPEC security rule 3).
set -euo pipefail

here="$(dirname "$0")"
model="${RISK_MODEL:-claude-sonnet-5-5}"
effort="${RISK_EFFORT:-medium}"
budget="${RISK_BUDGET:-0.25}"

# Callers pass fixed text only, never model output, so printf is safe here.
fallback() {
  printf '{"risk":"high","verdict":"CHANGES","reason":"%s"}\n' "$1"
  exit 0
}

diff_file="${DIFF_FILE:-}"
[ -f "$diff_file" ] || fallback "AI rating unavailable: no diff file"
# Bytes, not characters: bytes >= characters, so the cap can only be stricter.
[ "$(wc -c < "$diff_file")" -le 60000 ] || fallback "diff too large to rate"
[ -n "${ANTHROPIC_API_KEY:-}" ] || fallback "AI rating disabled (no key)"

work="$(mktemp -d)" || fallback "AI rating unavailable: no temp dir"
trap 'rm -rf "$work"' EXIT

# No tools and --bare, so the model cannot read the runner's files or environment.
rc=0
env -u GH_TOKEN claude -p "$(cat "$here/../prompts/risk.md")" --bare \
  --model "$model" --effort "$effort" --tools "" \
  --max-turns 2 --max-budget-usd "$budget" \
  --output-format json < "$diff_file" > "$work/out.json" || rc=$?
jq -c '{is_error, subtype, num_turns, total_cost_usd}' "$work/out.json" >&2 2>/dev/null || true
# A nonzero exit is never trusted, even if it left output behind.
[ "$rc" -eq 0 ] || fallback "AI rating unavailable: CLI exit $rc"

reply="$(python3 "$here/json_field.py" "$work/out.json")" || fallback "AI rating unavailable: no valid reply"
# jq rebuilds the object, so only the three validated fields reach stdout, on one line.
jq -ce 'select((.risk | IN("low", "medium", "high")) and (.verdict | IN("PASS", "CHANGES")) and (.reason | type == "string")) | {risk, verdict, reason}' <<<"$reply" \
  || fallback "AI rating unavailable: invalid rating"
