"""Registry adapter: turns registry data into the strict types the L1 checks consume.

This is the seam the Phase 1 review asked for. Every method returns an explicit value, and
an answer the source cannot give is an explicit unknown. Nothing is returned as an empty
"safe" default.

- `OfflineSource` reads a verified snapshot. It is the only fully working source in this
  release, and it is what the demo and the tests use.
- `LiveSource` is a stub. Every query returns unknown, so every check blocks. Live PyPI, npm,
  and OSV access is not built yet. Until it is, live mode fails closed.

Requirements: R-P-1. Layer 1 (adapter). Pure reads, no network in this release.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from slopseal.core.advisory import AdvisoryResult, AdvisoryUnknown
from slopseal.core.install_scripts import ScriptInventory, ScriptsUnknown
from slopseal.core.license import LicenseInput, LicenseUnknown
from slopseal.core.maintainer import MaintainerInput, MaintainersUnknown
from slopseal.core.types import Ecosystem, RegistryResult, RegistryUnknown
from slopseal.fixtures.loader import Snapshot

_LIVE_UNAVAILABLE = "live registry access is not built in this release"


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


class LiveSource:
    """Stub for live mode. Every answer is unknown, so every check blocks (fail closed)."""

    snapshot_id: str | None = None
    as_of: datetime | None = None

    def registry_result(self, eco: Ecosystem, name: str) -> RegistryResult:
        return RegistryUnknown(eco, name, _LIVE_UNAVAILABLE)

    def latest_version(self, eco: Ecosystem, name: str) -> str | None:
        return None

    def exports(self, eco: Ecosystem, name: str, version: str) -> tuple[str, ...] | None:
        return None

    def install_scripts(self, eco: Ecosystem, name: str, version: str) -> ScriptInventory:
        return ScriptsUnknown(_LIVE_UNAVAILABLE)

    def advisories(self, eco: Ecosystem, name: str, version: str) -> AdvisoryResult:
        return AdvisoryUnknown(_LIVE_UNAVAILABLE)

    def license(self, eco: Ecosystem, name: str) -> LicenseInput:
        return LicenseUnknown(_LIVE_UNAVAILABLE)

    def maintainers(self, eco: Ecosystem, name: str) -> MaintainerInput:
        return MaintainersUnknown(_LIVE_UNAVAILABLE)

    def top_n(self, eco: Ecosystem) -> tuple[str, ...]:
        return ()

    def known_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return ()

    def absent_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return ()

    def alternatives(self, eco: Ecosystem, api: str, exclude: str) -> tuple[str, ...]:
        return ()
