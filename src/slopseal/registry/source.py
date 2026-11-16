"""Registry adapter: turns registry data into the strict types the L1 checks consume.

This is the seam the Phase 1 review asked for. Every method returns an explicit value, and
an answer the source cannot give is an explicit unknown. Nothing is returned as an empty
"safe" default.

- `OfflineSource` reads a verified snapshot. It is what the demo and the tests use.
- `LiveSource` (registry/live.py) queries PyPI, npm, and OSV. Its failures are unknown values.

Requirements: R-P-1, R-P-3. Layer 1 (adapter). Pure reads.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from slopseal.core.advisory import AdvisoryResult
from slopseal.core.install_scripts import ScriptInventory
from slopseal.core.license import LicenseInput
from slopseal.core.maintainer import MaintainerInput
from slopseal.core.types import Ecosystem, RegistryResult
from slopseal.fixtures.loader import Snapshot


class RegistrySource(Protocol):
    snapshot_id: str | None
    as_of: datetime | None

    def registry_result(self, eco: Ecosystem, name: str) -> RegistryResult: ...
    def latest_version(self, eco: Ecosystem, name: str) -> str | None: ...
    def exports(self, eco: Ecosystem, name: str, version: str) -> tuple[str, ...] | None: ...
    def install_scripts(self, eco: Ecosystem, name: str, version: str) -> ScriptInventory: ...
    def advisories(self, eco: Ecosystem, name: str, version: str) -> AdvisoryResult: ...
    def license(self, eco: Ecosystem, name: str) -> LicenseInput: ...
    def maintainers(self, eco: Ecosystem, name: str) -> MaintainerInput: ...
    def top_n(self, eco: Ecosystem) -> tuple[str, ...]: ...
    def known_names(self, eco: Ecosystem) -> tuple[str, ...]: ...
    def absent_names(self, eco: Ecosystem) -> tuple[str, ...]: ...
    def alternatives(self, eco: Ecosystem, api: str, exclude: str) -> tuple[str, ...]: ...


class OfflineSource:
    """Adapter over a verified snapshot. Answers come from the snapshot or are unknown."""

    def __init__(self, snapshot: Snapshot) -> None:
        self._snapshot = snapshot
        self.snapshot_id: str | None = snapshot.snapshot_id
        self.as_of: datetime | None = snapshot.as_of

    def registry_result(self, eco: Ecosystem, name: str) -> RegistryResult:
        return self._snapshot.registry_result(eco, name)

    def latest_version(self, eco: Ecosystem, name: str) -> str | None:
        return self._snapshot.latest_version(eco, name)

    def exports(self, eco: Ecosystem, name: str, version: str) -> tuple[str, ...] | None:
        return self._snapshot.exports(eco, name, version)

    def install_scripts(self, eco: Ecosystem, name: str, version: str) -> ScriptInventory:
        return self._snapshot.install_scripts(eco, name, version)

    def advisories(self, eco: Ecosystem, name: str, version: str) -> AdvisoryResult:
        return self._snapshot.advisories(eco, name, version)

    def license(self, eco: Ecosystem, name: str) -> LicenseInput:
        return self._snapshot.license(eco, name)

    def maintainers(self, eco: Ecosystem, name: str) -> MaintainerInput:
        return self._snapshot.maintainers(eco, name)

    def top_n(self, eco: Ecosystem) -> tuple[str, ...]:
        return self._snapshot.top_n(eco)

    def known_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return self._snapshot.known_names(eco)

    def absent_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return self._snapshot.absent_names(eco)

    def alternatives(self, eco: Ecosystem, api: str, exclude: str) -> tuple[str, ...]:
        return self._snapshot.alternatives(eco, api, exclude)
