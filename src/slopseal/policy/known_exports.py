"""Reviewed known exports for an allowlisted compiled wheel (R-CW-2, ADR 0005).

A package whose exports cannot be read statically (`dynamic_exports`) blocks any intent that
names an API. For a package on the R-CW-1 allowlist, the owner may review one symbol and record
it as a known export of one exact version. This module returns the recorded symbols.

The package and version must be on the allowlist in code (`invariants.ALLOWED_COMPILED_WHEELS`).
The policy cannot widen that list. A missing record, another version, or a package not on the
list gives an empty set, so the caller keeps the block.

Requirements: R-CW-2. Layer 2. Pure.
"""

from __future__ import annotations

from slopseal.policy.invariants import ALLOWED_COMPILED_WHEELS
from slopseal.policy.loader import KnownExport, Policy


def reviewed_symbols(policy: Policy, name: str, version: str) -> frozenset[str]:
    """The symbols recorded for this exact version. Empty when the package is not allowed."""
    if (name, version) not in ALLOWED_COMPILED_WHEELS:
        return frozenset()
    return frozenset(
        record.symbol
        for entry in policy.compiled_wheels
        if entry.name == name
        for record in entry.known_exports
        if record.version == version
    )


def reviewed_record(policy: Policy, name: str, version: str, symbol: str) -> KnownExport | None:
    """The record for one symbol of this exact version, with its reviewer and date (R-CW-3).

    None when the package is not allowed or no record names the symbol.
    """
    if (name, version) not in ALLOWED_COMPILED_WHEELS:
        return None
    for entry in policy.compiled_wheels:
        if entry.name != name:
            continue
        for record in entry.known_exports:
            if record.version == version and record.symbol == symbol:
                return record
    return None
