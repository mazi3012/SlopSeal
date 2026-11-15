"""Invariant floors for the trust policy.

The policy file may tighten a value. It may not loosen a value past the bound set here. The
bounds come from the PRD and live in code, not in the policy file, so an edit to the policy
cannot change them. A weakening edit therefore fails, and the property suite and the
pre-commit guard both report it.

Each bound is the value at which the check still meets its PRD definition. For example, a
typosquat distance below 2 no longer matches the PRD's distance-2 rule.

Requirements: R-1.4, R-PBT-2. Properties: P-FC-7, P-FC-8. Layer 2. Pure.
"""

from __future__ import annotations

from dataclasses import dataclass

from slopseal.policy.loader import Policy


@dataclass(frozen=True)
class Floor:
    attribute: str
    minimum: float | None = None
    maximum: float | None = None


FLOORS: tuple[Floor, ...] = (
    # Check 2.2: typosquat window from the PRD (distance 2, age 30 days).
    Floor("typosquat_max_distance", minimum=2),
    Floor("typosquat_max_age_days", minimum=30),
    # Check 2.4: new-package window from the PRD (age 7 days, fewer than 3 releases).
    Floor("new_package_max_age_days", minimum=7),
    Floor("new_package_max_releases", minimum=3),
    # Check 2.11: near-name window from the PRD (distance 3; Jaro-Winkler at most 0.92).
    Floor("levenshtein_max", minimum=3),
    Floor("jaro_winkler_min", maximum=0.92),
    Floor("keyboard_distance_max", minimum=1),
    # Check 2.3: slopsquat signatures match within distance 1. A larger tolerance matches more.
    Floor("slopsquat_max_distance", minimum=1),
    # Quarantine: the PRD sets one automated retry. A larger budget lengthens quarantine.
    Floor("retry_budget", minimum=0, maximum=1),
    # Rate limit (PRD 4.7): at least one install per window. Zero would block every install.
    Floor("max_installs_per_minute", minimum=1),
    # P-SM-1: every quarantine terminates in bounded time, so the window must be positive.
    Floor("max_seconds", minimum=1),
)


def enforce_floors(policy: Policy) -> tuple[str, ...]:
    """Return one message per violated floor. An empty tuple means the policy is acceptable."""
    violations: list[str] = []
    for floor in FLOORS:
        value = getattr(policy, floor.attribute)
        if floor.minimum is not None and value < floor.minimum:
            violations.append(f"{floor.attribute} = {value} is below the floor {floor.minimum}")
        if floor.maximum is not None and value > floor.maximum:
            violations.append(f"{floor.attribute} = {value} is above the ceiling {floor.maximum}")
    return tuple(violations)
