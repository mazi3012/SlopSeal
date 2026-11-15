"""Check 2.9: license policy.

Input is the declared license expression from the registry:
- a string: an SPDX id, or a chain joined by ` OR ` or ` AND ` (no parentheses);
- None or blank: undeclared. Reported at `undeclared_level` (WARN or BLOCK, per policy);
- `LicenseUnknown`: the registry could not say. BLOCK (fail closed).

A term is acceptable when it is not on the deny list and, if an allow list is set, it is on
the allow list. A chain is acceptable when any term is acceptable (OR) or all are (AND).

Expressions with parentheses, WITH exceptions, or mixed AND and OR are not supported in v1.
Their meaning is ambiguous, so the check BLOCKs them. The policy can list the exact
expression as allowed-by-id if a package must pass.

Requirements: R-2.9, R-P-1. Layer 2. Pure.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from slopseal.core.types import CheckResult, Level

CHECK_ID = "license"
_CONFIGURABLE_LEVELS = frozenset({Level.WARN, Level.BLOCK})


@dataclass(frozen=True)
class LicenseUnknown:
    reason: str


LicenseInput = str | None | LicenseUnknown


def _parse(expression: str) -> tuple[str, tuple[str, ...]] | None:
    """Return (operator, terms), or None when the expression is not supported."""
    if any(token in expression for token in ("(", ")", " WITH ")):
        return None
    has_or = " OR " in expression
    has_and = " AND " in expression
    if has_or and has_and:
        return None
    if has_or:
        operator, parts = "OR", expression.split(" OR ")
    elif has_and:
        operator, parts = "AND", expression.split(" AND ")
    else:
        operator, parts = "SINGLE", [expression]
    terms = tuple(part.strip() for part in parts)
    if not all(terms):
        return None
    return operator, terms


def check_license(
    expression: LicenseInput,
    *,
    allow: Collection[str] = (),
    deny: Collection[str] = (),
    level: Level = Level.BLOCK,
    undeclared_level: Level = Level.WARN,
) -> CheckResult:
    if level not in _CONFIGURABLE_LEVELS or undeclared_level not in _CONFIGURABLE_LEVELS:
        raise ValueError("license levels must be WARN or BLOCK")

    if isinstance(expression, LicenseUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"license unknown: {expression.reason}")
    if expression is None or not expression.strip():
        return CheckResult(CHECK_ID, undeclared_level, "no license declared")

    parsed = _parse(expression.strip())
    if parsed is None:
        return CheckResult(
            CHECK_ID,
            Level.BLOCK,
            f"license expression not supported in v1: '{expression}'",
        )

    operator, terms = parsed
    allowed = {term.lower() for term in allow}
    denied = {term.lower() for term in deny}

    def acceptable(term: str) -> bool:
        lowered = term.lower()
        if lowered in denied:
            return False
        return not allowed or lowered in allowed

    verdicts = [acceptable(term) for term in terms]
    passes = any(verdicts) if operator == "OR" else all(verdicts)
    if passes:
        return CheckResult(CHECK_ID, Level.PASS, f"license '{expression}' is acceptable")

    return CheckResult(
        CHECK_ID,
        level,
        f"license '{expression}' is not acceptable by policy",
        evidence=(("license", expression),),
    )
