#!/usr/bin/env bash
# End-to-end demo path (PRD: Demo Scripts, fallback/deterministic version).
#
# Runs against the checksummed offline snapshot in a throwaway state directory. Every beat asserts
# the exit code and the key fields of the output, so a regression fails the script.
#
# Beats 1-3 use the CLI. Beat 4 runs pip and npm through the PATH shim with stub real tools,
# so nothing is installed. Beats 5-7 check the audit log and the policy floors.
#
# Run from a checkout with the venv active:
#   python3 -m venv .venv && source .venv/bin/activate
#   pip install -e ".[dev]"
#   bash scripts/demo.sh
# Exit 0 means every beat passed. Any failed beat exits 1 and prints the failing assertion.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Preflight: the beats need the slopseal command and the package importable from python3.
if ! command -v slopseal >/dev/null 2>&1 || ! python3 -c "import slopseal" >/dev/null 2>&1; then
    echo "demo: slopseal is not installed for this python3." >&2
    echo "demo: activate the venv and run: pip install -e \".[dev]\"" >&2
    exit 78
fi

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

echo "== Beat 4: pip and npm run through the PATH shim (stub real tools record what runs)"
shim_dir="$work/shims"
stub_dir="$work/real"
mkdir -p "$stub_dir"
for tool in pip npm; do
    printf '#!/bin/sh\necho "%s $*" >>"%s/ran.log"\n' "$tool" "$work" >"$stub_dir/$tool"
    chmod 755 "$stub_dir/$tool"
done
python3 -m slopseal.intercept.shims "$shim_dir" >/dev/null
export PATH="$shim_dir:$stub_dir:$PATH"

expect 1 "pip install csv-parser-pro==0.1.0 is blocked by the shim" \
    pip install csv-parser-pro==0.1.0
assert_json err "d['check'] == 'existence' and d['package'] == 'csv-parser-pro'" \
    "the shim reports the existence violation"

expect 0 "pip install tinyfmt-kit==0.4.0 is allowed by the shim" \
    pip install tinyfmt-kit==0.4.0
if grep -qx "pip install tinyfmt-kit==0.4.0" "$work/ran.log" \
    && ! grep -q "csv-parser-pro" "$work/ran.log"; then
    echo "PASS  the real pip ran for the allowed install only"
else
    echo "FAIL  ran.log does not show exactly the allowed install"
    cat "$work/ran.log" >&2 || true
    failures=$((failures + 1))
fi

expect 1 "npm install react-codeshift@1.0.0 is blocked by the shim" \
    npm install react-codeshift@1.0.0
assert_json err "d['package'] == 'react-codeshift'" \
    "the shim names the blocked npm package"

expect 1 "an unpinned pip install is refused without running pip" \
    pip install tinyfmt-kit
assert_json err "d['check'] == 'shim'" \
    "the shim refuses the unpinned install before verification"

echo "== Beat 5: the audit log is intact"
expect 0 "audit chain and seals verify" slopseal audit verify

echo "== Beat 6: tampering with the audit log is detected"
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

echo "== Beat 7: a weakened policy is rejected by the policy guard"
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
