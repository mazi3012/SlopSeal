#!/usr/bin/env bash
# Policy checks: validate the trust policy, then run the property suite.
#
# Single entry point for the pre-commit hook (.pre-commit-config.yaml) and the Kiro hook
# (.kiro/hooks/on-steering-change.json). Both call this script, so they cannot disagree.
#
# Fails (non-zero) when the policy is malformed (78), weakens a floor (1), or any property
# fails. Requires the package to be installed: pip install -e ".[dev]".

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "== policy guard"
python scripts/policy_guard.py .kiro/steering/dependency-trust.md

echo "== property suite (policy and invariants)"
python -m pytest src/tests/properties -q -p no:cacheprovider
