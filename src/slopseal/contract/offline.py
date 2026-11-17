"""Offline contract: the checksummed snapshot as a contract source (R-C-8, design 2.2).

A package or version the snapshot does not cover is UNKNOWN with reason not_in_snapshot (R-C-5).
The snapshot is read and never changed here.

Requirements: R-C-5, R-C-8. Layer 1 (adapter).
"""

from __future__ import annotations

from slopseal.contract.types import ContractComplete, ContractUnknown, UnknownReason
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import Snapshot


def offline_contract(
    snapshot: Snapshot, ecosystem: Ecosystem, name: str, version: str
) -> ContractComplete | ContractUnknown:
    exports = snapshot.exports(ecosystem, name, version)
    if exports is None:
        return ContractUnknown(
            UnknownReason.NOT_IN_SNAPSHOT,
            "package or version is not covered by the offline snapshot",
        )
    return ContractComplete(tuple(exports))
