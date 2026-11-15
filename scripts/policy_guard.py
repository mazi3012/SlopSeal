"""Policy guard: validate the trust policy and enforce its invariant floors.

Usage: python scripts/policy_guard.py [PATH ...]   (default: .kiro/steering/dependency-trust.md)

Exit codes:
  0   every policy file parses and meets every floor
  1   a file parses but weakens a floor (R-PBT-2)
  78  a file is missing, unreadable, or malformed (R-1.4, fail closed)

This is the only place the guard's exit codes are defined. The parser and floors live in
src/slopseal/policy/, so this script never duplicates them.
"""

from __future__ import annotations

import sys

from slopseal.policy.invariants import enforce_floors
from slopseal.policy.loader import PolicyError, load_policy

DEFAULT_POLICY = ".kiro/steering/dependency-trust.md"
EXIT_OK = 0
EXIT_FLOOR_VIOLATED = 1
EXIT_POLICY_ERROR = 78


def main(argv: list[str]) -> int:
    paths = argv or [DEFAULT_POLICY]
    status = EXIT_OK
    for path in paths:
        try:
            policy = load_policy(path)
        except PolicyError as exc:
            print(f"policy-guard: {path}: {exc}", file=sys.stderr)
            return EXIT_POLICY_ERROR
        for violation in enforce_floors(policy):
            print(f"policy-guard: {path}: {violation}", file=sys.stderr)
            status = EXIT_FLOOR_VIOLATED
        if status == EXIT_OK:
            print(f"policy-guard: {path}: ok (hash {policy.policy_hash[:12]})")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
