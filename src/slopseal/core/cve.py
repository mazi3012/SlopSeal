"""Check 2.6: CVE lookup for the exact version.

BLOCK when any advisory for the exact version has a severity in `block_severities`
(default: critical and high, per PRD). Advisories below that bar do not block.

Fail closed: an unknown advisory source, or an advisory with unknown severity, is BLOCK.
Malware advisories (MAL- ids) are check 2.7's job and are excluded here, so a malware
record is reported once, at HARD_BLOCK.

Requirements: R-2.6, R-P-1. Layer 2. Pure.
"""

from __future__ import annotations

from collections.abc import Collection

from slopseal.core.advisory import (
    MALWARE_ID_PREFIX,
    Advisories,
    AdvisoryResult,
    AdvisoryUnknown,
    Severity,
)
from slopseal.core.types import CheckResult, Level

CHECK_ID = "cve"
DEFAULT_BLOCK_SEVERITIES: frozenset[Severity] = frozenset({Severity.CRITICAL, Severity.HIGH})


def check_cve(
    result: AdvisoryResult,
    *,
    block_severities: Collection[Severity] = DEFAULT_BLOCK_SEVERITIES,
) -> CheckResult:
    if isinstance(result, AdvisoryUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"advisory source unknown: {result.reason}")
    if not isinstance(result, Advisories):
        raise AssertionError("unreachable: AdvisoryResult is exhaustive")

    # Collect everything first, then report in sorted order, so the result does not depend
    # on the order the source returned the advisories.
    non_malware = [a for a in result.items if not a.advisory_id.startswith(MALWARE_ID_PREFIX)]
    unknown = sorted(a.advisory_id for a in non_malware if a.severity is Severity.UNKNOWN)
    if unknown:
        return CheckResult(
            CHECK_ID,
            Level.BLOCK,
            f"advisories with unknown severity: {', '.join(unknown)}",
        )

    blocking = [a.advisory_id for a in non_malware if a.severity in block_severities]
    if not blocking:
        return CheckResult(CHECK_ID, Level.PASS, "no blocking advisory for this version")

    ids = ", ".join(sorted(blocking))
    return CheckResult(
        CHECK_ID,
        Level.BLOCK,
        f"blocking advisories for this version: {ids}",
        evidence=(("advisories", ids), ("count", len(blocking))),
    )
