"""Check 2.2: typosquat.

HARD_BLOCK only when BOTH hold:
  - the package name is within `max_distance` edits of a top-N package, and
  - the package is younger than `max_age_days`.

The conjunction is deliberate (PRD, Resolved Decision 1). Distance alone blocks well-known
names. Age alone blocks every new package. Only the intersection is the slopsquat pattern.

Fail closed: an unknown registry state, unknown package age, or an empty top-N list is BLOCK.
A package whose name equals a top-N name is that package, not a typosquat, so it passes.

Requirements: R-2.2, R-2.2a, R-P-1. Properties: P-TY-1, P-FC-2.
Layer 2. Pure: `now` is injected, so the age is deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from slopseal.core.age import age_days
from slopseal.core.distance import levenshtein
from slopseal.core.names import normalize_name
from slopseal.core.types import (
    CheckResult,
    Ecosystem,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)

CHECK_ID = "typosquat"


def check_typosquat(
    result: RegistryResult,
    top_n: Sequence[str],
    now: datetime,
    *,
    max_distance: int,
    max_age_days: int,
) -> CheckResult:
    if max_distance < 0 or max_age_days < 0:
        raise ValueError("typosquat thresholds must be non-negative")

    if isinstance(result, RegistryUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"registry state unknown: {result.reason}")
    if isinstance(result, RegistryMissing):
        # Nothing to measure. The existence check (2.1) already reports a missing package.
        return CheckResult(CHECK_ID, Level.PASS, "not applicable: package does not exist")
    if not isinstance(result, RegistryRecord):
        raise AssertionError("unreachable: RegistryResult is exhaustive")

    if not top_n:
        return CheckResult(CHECK_ID, Level.BLOCK, "top-N list is empty or unavailable")
    if result.first_published is None:
        return CheckResult(CHECK_ID, Level.BLOCK, "package publish time is unknown")

    ecosystem: Ecosystem = result.ecosystem
    name = normalize_name(ecosystem, result.name)
    candidates = {normalize_name(ecosystem, top) for top in top_n}
    if name in candidates:
        return CheckResult(CHECK_ID, Level.PASS, "name is itself a top-N package")

    nearest, distance = min(
        ((candidate, levenshtein(name, candidate)) for candidate in candidates),
        key=lambda pair: (pair[1], pair[0]),
    )
    # A negative age means the publish time is ahead of `now` (clock skew). It counts as young.
    age = age_days(now, result.first_published)

    if distance <= max_distance and age < max_age_days:
        return CheckResult(
            CHECK_ID,
            Level.HARD_BLOCK,
            f"'{result.name}' is {distance} edit(s) from popular package '{nearest}' "
            f"and was published {age:.1f} days ago",
            remedy=f"Did you mean {nearest}?",
            evidence=(
                ("distance", distance),
                ("matched", nearest),
                ("age_days", round(age, 2)),
            ),
        )
    return CheckResult(CHECK_ID, Level.PASS, "no young package within typosquat distance")
