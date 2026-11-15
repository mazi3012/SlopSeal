"""Check 2.4: new package.

A package younger than `max_age_days` AND with fewer than `max_releases` releases is flagged
at the configured level. The default is HARD_BLOCK (PRD check 2.4, "configurable").

Fail closed: unknown registry state, unknown publish time, and an invalid release count
BLOCK. A missing package passes here, because the existence check (2.1) reports it.

Requirements: R-2.4, R-P-1. Layer 2. Pure: `now` is injected.
"""

from __future__ import annotations

from datetime import datetime

from slopseal.core.age import age_days
from slopseal.core.types import (
    CheckResult,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)

CHECK_ID = "new_package"
_CONFIGURABLE_LEVELS = frozenset({Level.WARN, Level.BLOCK, Level.HARD_BLOCK})


def check_new_package(
    result: RegistryResult,
    now: datetime,
    *,
    max_age_days: int,
    max_releases: int,
    level: Level = Level.HARD_BLOCK,
) -> CheckResult:
    if max_age_days < 0 or max_releases < 0:
        raise ValueError("new-package thresholds must be non-negative")
    if level not in _CONFIGURABLE_LEVELS:
        raise ValueError("new-package level must be WARN, BLOCK, or HARD_BLOCK")

    if isinstance(result, RegistryUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"registry state unknown: {result.reason}")
    if isinstance(result, RegistryMissing):
        return CheckResult(CHECK_ID, Level.PASS, "not applicable: package does not exist")
    if not isinstance(result, RegistryRecord):
        raise AssertionError("unreachable: RegistryResult is exhaustive")

    if result.release_count < 0:
        return CheckResult(CHECK_ID, Level.BLOCK, "registry reported a negative release count")
    if result.first_published is None:
        return CheckResult(CHECK_ID, Level.BLOCK, "package publish time is unknown")

    # Negative age (publish time ahead of `now`) is young, which fails closed.
    age = age_days(now, result.first_published)
    releases = result.release_count

    if age < max_age_days and releases < max_releases:
        return CheckResult(
            CHECK_ID,
            level,
            f"'{result.name}' was published {age:.1f} days ago with {releases} release(s)",
            evidence=(("age_days", round(age, 2)), ("releases", releases)),
        )
    return CheckResult(CHECK_ID, Level.PASS, "package is not new by policy")
