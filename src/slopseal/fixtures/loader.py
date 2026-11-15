"""Offline snapshot: integrity check and read-only queries.

Integrity (Open Decision 6, resolved): a static SHA-256 checksum manifest, `manifest.json`,
lists the sha256 of every data file. Loading recomputes every hash, and any mismatch, missing
file, or unlisted data file raises `SnapshotIntegrityError`. The pipeline turns that into
BLOCK (P-SN-1). The manifest does not stop someone who can write to the repo from changing a
file and its manifest together (THREAT_MODEL section 6).

Queries never guess. A package or version the snapshot does not list gives an explicit
unknown value, never an empty answer that reads as "safe" (fail closed).

Requirements: R-P-1, R-P-2. Properties: P-SN-1, P-SN-2. Layer 1.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from slopseal.core.advisory import Advisories, Advisory, AdvisoryResult, AdvisoryUnknown, Severity
from slopseal.core.install_scripts import InstallScript, ScriptInventory, ScriptsUnknown
from slopseal.core.license import LicenseInput, LicenseUnknown
from slopseal.core.maintainer import MaintainerInput, Maintainers, MaintainersUnknown
from slopseal.core.names import normalize_name
from slopseal.core.types import (
    Ecosystem,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)

MANIFEST_NAME = "manifest.json"
DATA_FILES = ("registry_snapshot.json", "osv_snapshot.json", "topn_snapshot.json")
_ECOSYSTEMS = {eco.value: eco for eco in Ecosystem}


class SnapshotIntegrityError(Exception):
    """The snapshot does not match its checksum manifest. The verdict must be BLOCK."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(directory: Path) -> dict[str, Any]:
    """Compute the manifest for the data files in `directory`. Used by scripts/build_snapshot.py."""
    files = {name: sha256_file(directory / name) for name in DATA_FILES}
    registry = json.loads((directory / "registry_snapshot.json").read_text(encoding="utf-8"))
    return {
        "snapshot_id": registry["snapshot_id"],
        "as_of": registry["as_of"],
        "files": files,
    }


def _read_verified(directory: Path) -> dict[str, dict[str, Any]]:
    manifest_path = directory / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotIntegrityError(f"manifest unreadable: {exc}") from exc

    listed = manifest.get("files")
    if not isinstance(listed, dict) or set(listed) != set(DATA_FILES):
        raise SnapshotIntegrityError("manifest must list exactly the data files")

    unlisted = sorted(
        path.name
        for path in directory.glob("*.json")
        if path.name not in DATA_FILES and path.name != MANIFEST_NAME
    )
    if unlisted:
        raise SnapshotIntegrityError(f"unlisted data file(s) in snapshot: {', '.join(unlisted)}")

    documents: dict[str, dict[str, Any]] = {}
    for name in DATA_FILES:
        path = directory / name
        if not path.is_file():
            raise SnapshotIntegrityError(f"missing data file: {name}")
        if sha256_file(path) != listed[name]:
            raise SnapshotIntegrityError(f"checksum mismatch: {name}")
        try:
            documents[name] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SnapshotIntegrityError(f"malformed JSON in {name}: {exc}") from exc
    return documents


@dataclass(frozen=True)
class _Version:
    exports: tuple[str, ...]
    scripts: tuple[InstallScript, ...]


@dataclass
class _Package:
    ecosystem: Ecosystem
    name: str
    first_published: datetime
    release_count: int
    latest: str
    license: str | None
    maintainers: Maintainers
    versions: dict[str, _Version]
    advisories: dict[str, tuple[Advisory, ...]] = field(default_factory=dict)


class Snapshot:
    """Read-only view of a verified snapshot. Construct with `load_snapshot`."""

    def __init__(self, documents: dict[str, dict[str, Any]]) -> None:
        registry = documents["registry_snapshot.json"]
        osv = documents["osv_snapshot.json"]
        topn = documents["topn_snapshot.json"]

        self.snapshot_id: str = registry["snapshot_id"]
        self.as_of: datetime = datetime.fromisoformat(registry["as_of"])
        self._packages: dict[tuple[Ecosystem, str], _Package] = {}
        self._absent: set[tuple[Ecosystem, str]] = set()
        self._top_n: dict[Ecosystem, tuple[str, ...]] = {}

        for eco_name, names in registry["packages"].items():
            eco = _eco(eco_name)
            for raw_name, data in names.items():
                key = (eco, normalize_name(eco, raw_name))
                self._packages[key] = _package(eco, raw_name, data)

        for eco_name, names in registry["absent"].items():
            eco = _eco(eco_name)
            for raw_name in names:
                self._absent.add((eco, normalize_name(eco, raw_name)))

        for eco_name, names in osv["advisories"].items():
            eco = _eco(eco_name)
            for raw_name, by_version in names.items():
                package = self._packages.get((eco, normalize_name(eco, raw_name)))
                if package is None:
                    continue
                for version, items in by_version.items():
                    package.advisories[version] = tuple(
                        Advisory(item["id"], _severity(item["severity"]), item["summary"])
                        for item in items
                    )

        for eco_name, names in topn["ecosystems"].items():
            eco = _eco(eco_name)
            self._top_n[eco] = tuple(names)

    # ---- queries ----------------------------------------------------------------------

    def _key(self, eco: Ecosystem, name: str) -> tuple[Ecosystem, str]:
        return (eco, normalize_name(eco, name))

    def registry_result(self, eco: Ecosystem, name: str) -> RegistryResult:
        key = self._key(eco, name)
        package = self._packages.get(key)
        if package is not None:
            return RegistryRecord(eco, name, package.first_published, package.release_count)
        if key in self._absent:
            return RegistryMissing(eco, name)
        return RegistryUnknown(eco, name, "package is not covered by this snapshot")

    def exports(self, eco: Ecosystem, name: str, version: str) -> tuple[str, ...] | None:
        """Exported symbols for an exact version, or None when the snapshot does not know."""
        package = self._packages.get(self._key(eco, name))
        if package is None or version not in package.versions:
            return None
        return package.versions[version].exports

    def install_scripts(self, eco: Ecosystem, name: str, version: str) -> ScriptInventory:
        package = self._packages.get(self._key(eco, name))
        if package is None or version not in package.versions:
            return ScriptsUnknown("version is not covered by this snapshot")
        return package.versions[version].scripts

    def advisories(self, eco: Ecosystem, name: str, version: str) -> AdvisoryResult:
        package = self._packages.get(self._key(eco, name))
        if package is None or version not in package.versions:
            return AdvisoryUnknown("version is not covered by this snapshot")
        return Advisories(package.advisories.get(version, ()))

    def license(self, eco: Ecosystem, name: str) -> LicenseInput:
        package = self._packages.get(self._key(eco, name))
        if package is None:
            return LicenseUnknown("package is not covered by this snapshot")
        return package.license

    def maintainers(self, eco: Ecosystem, name: str) -> MaintainerInput:
        package = self._packages.get(self._key(eco, name))
        if package is None:
            return MaintainersUnknown("package is not covered by this snapshot")
        return package.maintainers

    def latest_version(self, eco: Ecosystem, name: str) -> str | None:
        package = self._packages.get(self._key(eco, name))
        return None if package is None else package.latest

    def top_n(self, eco: Ecosystem) -> tuple[str, ...]:
        """The reference list for near-name checks. Empty means unknown to the checks (BLOCK)."""
        return self._top_n.get(eco, ())

    def known_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return tuple(sorted(name for (e, name) in self._packages if e is eco))

    def absent_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return tuple(sorted(name for (e, name) in self._absent if e is eco))

    def alternatives(self, eco: Ecosystem, api: str, exclude: str) -> tuple[str, ...]:
        """Other packages whose latest version exports `api`. Used for suggested alternatives."""
        excluded = normalize_name(eco, exclude)
        found: list[str] = []
        for (package_eco, name), package in sorted(self._packages.items(), key=lambda kv: kv[0][1]):
            if package_eco is not eco or name == excluded:
                continue
            latest = package.versions.get(package.latest)
            if latest is not None and api in latest.exports:
                found.append(name)
        return tuple(found)


def _eco(value: str) -> Ecosystem:
    if value not in _ECOSYSTEMS:
        raise SnapshotIntegrityError(f"unknown ecosystem in snapshot: {value}")
    return _ECOSYSTEMS[value]


def _severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.UNKNOWN


def _package(eco: Ecosystem, name: str, data: dict[str, Any]) -> _Package:
    versions: dict[str, _Version] = {}
    for version, body in data["versions"].items():
        scripts = tuple(
            InstallScript(item["hook"], item["body"]) for item in body.get("install_scripts", [])
        )
        versions[version] = _Version(tuple(body["exports"]), scripts)
    maintainers = data["maintainers"]
    return _Package(
        ecosystem=eco,
        name=name,
        first_published=datetime.fromisoformat(data["first_published"]),
        release_count=int(data["release_count"]),
        latest=data["latest"],
        license=data["license"],
        maintainers=Maintainers(
            count=int(maintainers["count"]),
            newest_account_age_days=(
                None
                if maintainers.get("newest_account_age_days") is None
                else float(maintainers["newest_account_age_days"])
            ),
        ),
        versions=versions,
    )


def load_snapshot(directory: Path) -> Snapshot:
    """Verify every checksum, then return the snapshot. Raises SnapshotIntegrityError."""
    return Snapshot(_read_verified(directory))
