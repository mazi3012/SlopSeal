#!/usr/bin/env bash
# End-to-end demo path (PRD: Demo Scripts, fallback/deterministic version).
#
# Runs against the signed offline snapshot in a throwaway state directory. Every beat asserts
# the exit code and the key fields of the output, so a regression fails the script.
#
# This is the Phase 3 gate: the path must run cleanly against the offline snapshot.
# Requires the package installed: pip install -e ".[dev]".

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export SLOPSEAL_OFFLINE_SNAPSHOT=1
state_dir="$(mktemp -d)"
work="$(mktemp -d)"
export SLOPSEAL_STATE_DIR="$state_dir"
trap 'rm -rf "$state_dir" "$work"' EXIT

failures=0

# expect <expected-exit> <label> <command...>
# Captures stdout to $work/out and stderr to $work/err. Prints the label and result.
expect() {
    local expected="$1" label="$2"
    shift 2
    local code=0
    "$@" >"$work/out" 2>"$work/err" || code=$?
    if [ "$code" -eq "$expected" ]; then
        echo "PASS  $label (exit $code)"
    else
        echo "FAIL  $label: expected exit $expected, got $code"
        cat "$work/err" >&2
        failures=$((failures + 1))
    fi
}

# check_json <python-expression-over-d> <label>
# Parses $work/out (stdout) or $work/err (stderr) and asserts the expression is true.
assert_json() {
    local source="$1" expression="$2" label="$3"
    if python3 - "$work/$source" "$expression" <<'PYEOF'
import json, sys
path, expression = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as handle:
    d = json.loads(handle.read().strip().splitlines()[-1])
sys.exit(0 if eval(expression, {"d": d}) else 1)
PYEOF
    then
        echo "PASS  $label"
    else
        echo "FAIL  $label: assertion failed: $expression"
        cat "$work/$source" >&2
        failures=$((failures + 1))
    fi
}

echo "== Beat 1: an agent installs a package that does not exist (slopsquat)"
expect 1 "csv-parser-pro is blocked at the existence check" \
    slopseal check csv-parser-pro --ecosystem pypi --version 0.1.0
assert_json err "d['check'] == 'existence' and d['remedy'] == 'Did you mean csv-parser?'" \
    "typed DependencyViolation names the existence check and the remedy"

echo "== Beat 2: an existing package whose API does not match the declared intent"
expect 75 "csv-parser with csv.reader is quarantined" \
    slopseal check csv-parser --ecosystem pypi --version 1.2.0 \
        --expected-api csv.reader --purpose "parse CSV"
assert_json out "d['verdict'] == 'QUARANTINE' and d['mismatch_type'] == 'api_absent' and d['retry_budget_remaining'] == 1" \
    "payload has api_absent, budget 1, and no confidence field"
assert_json out "'confidence' not in d and d['found_apis'] == ['parse', 'parse_file']" \
    "payload lists the real exports and carries no confidence number"
assert_json out "any(a['package'] == 'csv' for a in d['suggested_alternatives'])" \
    "payload suggests csv, which exports csv.reader"
qid="$(python3 -c "import json,sys; print(json.loads(open('$work/out').read())['quarantine_id'])")"

echo "== Beat 3: the agent retries once with a refined intent"
expect 0 "retry with expected_api parse is allowed" \
    slopseal check csv-parser --ecosystem pypi --version 1.2.0 \
        --expected-api parse --purpose "parse CSV" --quarantine-id "$qid"

echo "== Beat 4: the audit log is intact"
expect 0 "audit chain and seals verify" slopseal audit verify

echo "== Beat 5: tampering with the audit log is detected"
cp "$state_dir/audit.jsonl" "$work/tampered.jsonl"
python3 - "$work/tampered.jsonl" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
lines = p.read_text(encoding="utf-8").splitlines()
index = next(i for i, line in enumerate(lines) if '"outcome": "ALLOW"' in line)
lines[index] = lines[index].replace('"outcome": "ALLOW"', '"outcome": "BLOCK"', 1)
p.write_text("\n".join(lines) + "\n", encoding="utf-8")
PYEOF
expect 1 "a flipped verdict fails verification" slopseal audit verify --log "$work/tampered.jsonl"

echo "== Beat 6: a weakened policy is rejected by the policy guard"
weakened="$work/dependency-trust.md"
sed 's/typosquat_max_distance = 2/typosquat_max_distance = 1/' \
    .kiro/steering/dependency-trust.md >"$weakened"
expect 1 "typosquat_max_distance = 1 fails the floor" slopseal policy check "$weakened"

echo
if [ "$failures" -eq 0 ]; then
    echo "demo: PASS (all beats)"
else
    echo "demo: FAIL ($failures assertion(s) failed)"
    exit 1
fi
