"""Advisory types shared by checks 2.6 (CVE) and 2.7 (malware feed).

The caller is responsible for querying OSV for the exact package version and for mapping
the vendor's severity data to `Severity`. Anything the adapter cannot map becomes
`Severity.UNKNOWN`, which the checks treat as BLOCK (fail closed).

Requirements: R-2.6, R-2.7, R-P-1. Layer 2. Pure.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

MALWARE_ID_PREFIX = "MAL-"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Advisory:
    """One advisory for one exact package version. `advisory_id` is the OSV id (for example
    GHSA-..., PYSEC-..., or MAL-...)."""

    advisory_id: str
    severity: Severity
    summary: str


@dataclass(frozen=True)
class Advisories:
    items: tuple[Advisory, ...]


@dataclass(frozen=True)
class AdvisoryUnknown:
    """The advisory source could not answer (fail closed)."""

    reason: str


AdvisoryResult = Advisories | AdvisoryUnknown
