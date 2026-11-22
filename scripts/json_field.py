"""Read a `claude -p --output-format json` envelope and print the JSON object in its reply.

Usage: json_field.py ENVELOPE.json

Prints the parsed object as one JSON line on stdout. Prints the run cost to stderr.
Exits 1 when the run errored or the reply holds no valid JSON object; callers
treat that as NEEDS-HUMAN.
"""

import json
import re
import sys


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as fh:
        envelope = json.load(fh)

    print(f"cost_usd={envelope.get('total_cost_usd', 0)}", file=sys.stderr)
    if envelope.get("is_error"):
        return 1

    match = re.search(r"\{.*\}", envelope.get("result") or "", re.DOTALL)
    if not match:
        return 1
    try:
        obj = json.loads(match.group(0))
    except json.JSONDecodeError:
        return 1
    if not isinstance(obj, dict):
        return 1

    print(json.dumps(obj))
    return 0


if __name__ == "__main__":
    sys.exit(main())
