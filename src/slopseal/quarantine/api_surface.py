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

from slopseal.contract.types import (
    ContractComplete,
    ContractDigestMismatch,
    ContractUnknown,
    UnknownReason,
)
from slopseal.core.types import CheckResult, Level


class ApiSurface(Enum):
    UNKNOWN = "unknown"
    ABSENT = "absent"
    PRESENT = "present"


@dataclass(frozen=True)
class ApiSurfaceResult:
    outcome: ApiSurface
    declared_api: str
    found_apis: tuple[str, ...]
    # Set only for UNKNOWN from a typed contract (R-C-5). None for the v1 path.
    reason: UnknownReason | None = None


def check_api_surface(exports: tuple[str, ...] | None, declared_api: str) -> ApiSurfaceResult:
    if exports is None:
        return ApiSurfaceResult(ApiSurface.UNKNOWN, declared_api, ())
    found = tuple(sorted(set(exports)))
    if declared_api in found:
        return ApiSurfaceResult(ApiSurface.PRESENT, declared_api, found)
    return ApiSurfaceResult(ApiSurface.ABSENT, declared_api, found)


def check_contract(
    result: ContractComplete | ContractUnknown, declared_api: str
) -> ApiSurfaceResult:
    """Map a contract to PRESENT, ABSENT, or UNKNOWN with its typed reason (R-C-5).

    ABSENT is returned only for a complete contract. UNKNOWN never becomes PRESENT or ABSENT.
    """
    if isinstance(result, ContractUnknown):
        if declared_api in result.partial:
            # Two entry points (R-C-3): a complete entry point lists the API. Never ABSENT.
            return ApiSurfaceResult(ApiSurface.PRESENT, declared_api, result.partial)
        return ApiSurfaceResult(ApiSurface.UNKNOWN, declared_api, (), result.reason)
    outcome = ApiSurface.PRESENT if declared_api in result.exports else ApiSurface.ABSENT
    return ApiSurfaceResult(outcome, declared_api, result.exports)


def unknown_block(surface: ApiSurfaceResult) -> CheckResult:
    """The BLOCK for an UNKNOWN surface. Exit 1 at the verdict. Never QUARANTINE (R-Q-2, R-C-5).

    With no typed reason (the v1 path) the text is unchanged.
    """
    if surface.outcome is not ApiSurface.UNKNOWN:
        raise ValueError("unknown_block is only for an UNKNOWN surface")
    text = "exported symbols for this version are unknown"
    if surface.reason is not None:
        text += f" (reason: {surface.reason.value})"
    return CheckResult("api_surface", Level.BLOCK, text)


def mismatch_block(result: ContractDigestMismatch) -> CheckResult:
    """The HARD_BLOCK for a digest mismatch (T23, R-C-1). Exit 1 at the verdict."""
    return CheckResult(
        "contract_digest",
        Level.HARD_BLOCK,
        f"the artifact does not match the registry digest ({result.algorithm})",
    )
