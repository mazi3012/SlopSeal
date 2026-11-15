"""Check 2.1: registry existence.

HARD_BLOCK when the registry says the package does not exist (slopsquatting). BLOCK when
the registry state is unknown, because a failed lookup must never pass (R-P-1, P-FC-2).

Requirements: R-2.1, R-P-1. Properties: P-FC-2.
Layer 2. Pure: no I/O.
"""

from __future__ import annotations

from slopseal.core.types import (
    CheckResult,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)

CHECK_ID = "existence"


def check_existence(result: RegistryResult) -> CheckResult:
    """Classify a registry lookup. Exhaustive over RegistryResult."""
    if isinstance(result, RegistryRecord):
        return CheckResult(CHECK_ID, Level.PASS, "package exists in the registry")
    if isinstance(result, RegistryMissing):
        return CheckResult(
            CHECK_ID,
            Level.HARD_BLOCK,
            f"package '{result.name}' does not exist in the {result.ecosystem.value} registry",
        )
    if isinstance(result, RegistryUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"registry state unknown: {result.reason}")
    raise AssertionError("unreachable: RegistryResult is exhaustive")
