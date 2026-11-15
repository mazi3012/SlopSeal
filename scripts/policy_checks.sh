#!/usr/bin/env bash
# Policy checks: validate the trust policy, then run the property suite.
#
# Single entry point for the pre-commit hook (.pre-commit-config.yaml) and the Kiro hook
# (.kiro/hooks/on-steering-change.json). Both call this script, so they cannot disagree.
#
# Both steps always run, so a weakened policy reports the floor violation and the property
# failures together. The exit code is the first non-zero step result: 78 for a malformed
# policy, 1 for a weakened floor, 1 for a failing property. Requires the package installed:
# pip install -e ".[dev]".

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

status=0

echo "== policy guard"
python scripts/policy_guard.py .kiro/steering/dependency-trust.md
guard_status=$?
[ "$guard_status" -eq 0 ] || status="$guard_status"

echo "== property suite (policy and invariants)"
python -m pytest src/tests/properties -q -p no:cacheprovider
suite_status=$?
if [ "$status" -eq 0 ] && [ "$suite_status" -ne 0 ]; then
    status="$suite_status"
fi

if [ "$status" -eq 0 ]; then
    echo "policy checks: PASS"
else
    echo "policy checks: FAIL (exit $status)"
fi
exit "$status"
