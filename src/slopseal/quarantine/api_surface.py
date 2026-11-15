"""API-surface check for a declared intent.

The agent declares the API it expects, for example `csv.reader`. The check compares that
name with the package's exported symbols for the exact version. The agent cannot make a
missing API appear: the check reads the exports, not the intent (design section 9).

Outcomes:
- UNKNOWN: the exports are not known. BLOCK, never QUARANTINE (R-Q-2).
- ABSENT: the declared API is not exported. QUARANTINE with mismatch_type api_absent (R-Q-1).
- PRESENT: the declared API is exported. Passes this check.

Requirements: R-Q-1, R-Q-2. Properties: P-FC-3, P-FC-4. Layer 3. Pure.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ApiSurface(Enum):
    UNKNOWN = "unknown"
    ABSENT = "absent"
    PRESENT = "present"


@dataclass(frozen=True)
class ApiSurfaceResult:
    outcome: ApiSurface
    declared_api: str
    found_apis: tuple[str, ...]


def check_api_surface(exports: tuple[str, ...] | None, declared_api: str) -> ApiSurfaceResult:
    if exports is None:
        return ApiSurfaceResult(ApiSurface.UNKNOWN, declared_api, ())
    found = tuple(sorted(set(exports)))
    if declared_api in found:
        return ApiSurfaceResult(ApiSurface.PRESENT, declared_api, found)
    return ApiSurfaceResult(ApiSurface.ABSENT, declared_api, found)
