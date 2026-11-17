"""Live registry adapter: PyPI JSON API, npm registry, and OSV, over `urllib` (R-P-3).

Every answer is either a value read from the registry response or an explicit unknown. A
network error, timeout, non-200 status (other than 404 for existence), oversized or malformed
body, or a missing field becomes an unknown value. Checks treat unknown as BLOCK. Nothing is
filled in with a "safe" default.

Limits, stated in docs/THREAT_MODEL.md:
- No retries. A failed request is reported as unknown.
- Responses are untrusted input. They are parsed, not executed.
- Exports come from the Contract Check (`contract()`, R-C-8). Until the extractor lands, the
  extraction step is a stub, so every live export answer is unknown.
- Maintainer account age is not published, so the maintainer check is always unknown.
- The top-N list comes from the checksummed snapshot. It is not a live ranking.
- Install-time code is ruled out only for a version with a universal (`none-any`) wheel on
  PyPI. npm lifecycle scripts are read from the version metadata.

Requirements: R-P-1, R-P-3. Layer 1 (adapter). Standard library only.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from slopseal.contract.digest import (
    PublishedDigest,
    published_from_npm_integrity,
    published_from_pypi,
)
from slopseal.contract.pipeline import fetch_artifact, obtain_contract
from slopseal.contract.runner import run_extract
from slopseal.contract.types import (
    ContractComplete,
    ContractResult,
    ContractUnknown,
    UnknownReason,
)
from slopseal.core.advisory import (
    Advisories,
    Advisory,
    AdvisoryResult,
    AdvisoryUnknown,
    Severity,
)
from slopseal.core.install_scripts import InstallScript, ScriptInventory, ScriptsUnknown
from slopseal.core.license import LicenseInput, LicenseUnknown
from slopseal.core.maintainer import MaintainerInput, MaintainersNotPublished
from slopseal.core.types import (
    Ecosystem,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)

PYPI_BASE = "https://pypi.org/pypi"
NPM_BASE = "https://registry.npmjs.org"
OSV_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "slopseal/1.0.0 (+https://github.com/mazi3012/SlopSeal)"
DEFAULT_TIMEOUT = 10.0
MAX_BYTES = 10 * 1024 * 1024
INSTALL_HOOKS = frozenset({"preinstall", "install", "postinstall", "prepare"})
OSV_ECOSYSTEM = {Ecosystem.PYPI: "PyPI", Ecosystem.NPM: "npm"}
_UNIVERSAL_WHEEL = re.compile(r"-py\d(?:\.py\d)*-none-any\.whl$")
_CLASSIFIER_LICENSES = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
}
_OSV_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class LiveFailure(Exception):
    """A registry or OSV response that cannot be used. Converted to an explicit unknown."""


# A failure in one query. Network errors and timeouts are OSError. Bad JSON is ValueError. A
# missing field or wrong shape is KeyError, TypeError, IndexError, or AttributeError.
_FAILURES = (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, LiveFailure)

Fetch = Callable[[str, bytes | None], bytes | None]
ArtifactFetch = Callable[[str, Ecosystem], bytes | ContractUnknown]

# Marks a 404. Kept apart from None, which is what a body of `null` parses to.
_NOT_FOUND: Final = object()


def _http(url: str, body: bytes | None, timeout: float) -> bytes | None:
    """GET (or POST when body is given). Returns None for 404, the body for 200, else raises."""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise LiveFailure("only http and https registry URLs are allowed")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, data=body, headers=headers, method="GET" if body is None else "POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            status = response.status
            data: bytes = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and body is None:
            return None
        raise LiveFailure(f"HTTP {exc.code}") from exc
    if status != 200:
        raise LiveFailure(f"HTTP {status}")
    if len(data) > MAX_BYTES:
        raise LiveFailure("response is larger than the size limit")
    return data


def _time(text: object) -> datetime:
    if not isinstance(text, str):
        raise LiveFailure("publish time is missing")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise LiveFailure("publish time has no timezone")
    return parsed


def _extract(artifact: Path, kind: str, root: str) -> ContractComplete | ContractUnknown:
    """The extraction step of R-C-8: the wheel extractor (R-C-2), or the npm stub until R-C-3."""
    if kind == "wheel":
        return run_extract(artifact, kind)
    return ContractUnknown(UnknownReason.PARSE_ERROR, "extractor not implemented")


def _npm_path(name: str) -> str:
    # Scoped names keep "@" and encode "/" as %2F, as the npm registry expects.
    return urllib.parse.quote(name, safe="@")


class LiveSource:
    """Live answers from PyPI, npm, and OSV. Any failure is an explicit unknown (fail closed)."""

    snapshot_id: str | None = None
    as_of: datetime | None = None

    def __init__(
        self,
        *,
        top_n: Mapping[Ecosystem, tuple[str, ...]] | None = None,
        fetch: Fetch | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        pypi_base: str = PYPI_BASE,
        npm_base: str = NPM_BASE,
        osv_url: str = OSV_URL,
        artifact_fetch: ArtifactFetch | None = None,
        cache_root: Path | None = None,
    ) -> None:
        self._top: dict[Ecosystem, tuple[str, ...]] = dict(top_n or {})
        self._artifact_fetch: ArtifactFetch = (
            artifact_fetch if artifact_fetch is not None else fetch_artifact
        )
        self._cache_root = cache_root
        self._fetch: Fetch = (
            fetch if fetch is not None else (lambda url, body: _http(url, body, timeout))
        )
        self._pypi = pypi_base.rstrip("/")
        self._npm = npm_base.rstrip("/")
        self._osv = osv_url
        self._cache: dict[tuple[str, bytes | None], Any] = {}

    # ---- fetching -----------------------------------------------------------------------

    def _json(self, url: str, body: bytes | None = None) -> Any:
        """Parsed JSON for url, or None for 404. Successful responses are cached per run."""
        key = (url, body)
        if key not in self._cache:
            raw = self._fetch(url, body)
            self._cache[key] = _NOT_FOUND if raw is None else json.loads(raw)
        return self._cache[key]

    def _pypi_url(self, name: str) -> str:
        return f"{self._pypi}/{urllib.parse.quote(name, safe='')}/json"

    def _pypi_version_url(self, name: str, version: str) -> str:
        quoted_name = urllib.parse.quote(name, safe="")
        quoted_version = urllib.parse.quote(version, safe="")
        return f"{self._pypi}/{quoted_name}/{quoted_version}/json"

    def _npm_url(self, name: str) -> str:
        return f"{self._npm}/{_npm_path(name)}"

    # ---- existence and versions --------------------------------------------------------

    def registry_result(self, eco: Ecosystem, name: str) -> RegistryResult:
        if eco is Ecosystem.PYPI:
            url = self._pypi_url(name)
        elif eco is Ecosystem.NPM:
            url = self._npm_url(name)
        else:
            return RegistryUnknown(eco, name, f"live registry is not supported for {eco.value}")
        try:
            data = self._json(url)
            if data is _NOT_FOUND:
                return RegistryMissing(eco, name)
            if eco is Ecosystem.PYPI:
                releases = data["releases"]
                published = [
                    _time(file["upload_time_iso_8601"])
                    for files in releases.values()
                    for file in files
                ]
                first = min(published) if published else None
                count = sum(1 for files in releases.values() if files)
            else:
                first = _time(data["time"]["created"])
                count = len(data["versions"])
        except _FAILURES as exc:
            return RegistryUnknown(eco, name, f"registry query failed: {type(exc).__name__}")
        return RegistryRecord(eco, name, first, count)

    def latest_version(self, eco: Ecosystem, name: str) -> str | None:
        try:
            if eco is Ecosystem.PYPI:
                data = self._json(self._pypi_url(name))
                return None if data is _NOT_FOUND else str(data["info"]["version"])
            if eco is Ecosystem.NPM:
                data = self._json(self._npm_url(name))
                return None if data is _NOT_FOUND else str(data["dist-tags"]["latest"])
        except _FAILURES:
            return None
        return None

    def exports(self, eco: Ecosystem, name: str, version: str) -> tuple[str, ...] | None:
        result = self.contract(eco, name, version)
        return result.exports if isinstance(result, ContractComplete) else None

    # ---- contract (R-C-8) --------------------------------------------------------------

    def _artifact_plan(
        self, eco: Ecosystem, name: str, version: str
    ) -> tuple[str, str, PublishedDigest | ContractUnknown] | ContractUnknown:
        """The artifact URL, its kind, and its published digest, from the registry metadata."""
        if eco is Ecosystem.PYPI:
            data = self._json(self._pypi_version_url(name, version))
            if data is _NOT_FOUND:
                return ContractUnknown(UnknownReason.PARSE_ERROR, "version is not in the registry")
            files = data["urls"]
            wheels = sorted(
                (f for f in files if str(f["filename"]).endswith(".whl")),
                key=lambda f: str(f["filename"]).encode("utf-8"),
            )
            if not wheels:
                if any(f.get("packagetype") == "sdist" for f in files):
                    return ContractUnknown(
                        UnknownReason.SDIST_ONLY, "version has only an sdist, not a wheel"
                    )
                return ContractUnknown(UnknownReason.PARSE_ERROR, "version has no wheel or sdist")
            universal = [f for f in wheels if _UNIVERSAL_WHEEL.search(str(f["filename"]))]
            chosen = (universal or wheels)[0]
            digests = chosen.get("digests") or {}
            return str(chosen["url"]), "wheel", published_from_pypi(digests)
        if eco is Ecosystem.NPM:
            data = self._json(self._npm_url(name))
            if data is _NOT_FOUND:
                return ContractUnknown(UnknownReason.PARSE_ERROR, "package is not in the registry")
            manifest = data["versions"].get(version)
            if manifest is None:
                return ContractUnknown(UnknownReason.PARSE_ERROR, "version is not in the registry")
            dist = manifest["dist"]
            return str(dist["tarball"]), "npm", published_from_npm_integrity(dist.get("integrity"))
        return ContractUnknown(UnknownReason.PARSE_ERROR, "no contract source for this ecosystem")

    def contract(self, eco: Ecosystem, name: str, version: str) -> ContractResult:
        """Complete exports, or UNKNOWN with a typed reason, or a digest mismatch (R-C-8)."""
        if eco not in (Ecosystem.PYPI, Ecosystem.NPM):
            return ContractUnknown(
                UnknownReason.PARSE_ERROR, "no contract source for this ecosystem"
            )
        try:
            plan = self._artifact_plan(eco, name, version)
        except (OSError, LiveFailure):
            return ContractUnknown(UnknownReason.NETWORK, "registry metadata is unavailable")
        except _FAILURES:
            return ContractUnknown(
                UnknownReason.PARSE_ERROR, "registry metadata has an unexpected shape"
            )
        if isinstance(plan, ContractUnknown):
            return plan
        url, kind, published = plan
        return obtain_contract(
            eco,
            url,
            published,
            kind=kind,
            cache_root=self._cache_root,
            extract=_extract,
            fetch=self._artifact_fetch,
        )

    # ---- install-time code -------------------------------------------------------------

    def install_scripts(self, eco: Ecosystem, name: str, version: str) -> ScriptInventory:
        try:
            if eco is Ecosystem.PYPI:
                url = self._pypi_version_url(name, version)
                data = self._json(url)
                if data is _NOT_FOUND:
                    return ScriptsUnknown("version not found in the registry")
                files = data["urls"]
                if not files:
                    return ScriptsUnknown("version has no files")
                if any(_UNIVERSAL_WHEEL.search(str(f["filename"])) for f in files):
                    # pip installs the universal wheel for every Python, so no setup.py runs.
                    return ()
                return ScriptsUnknown(
                    "no universal wheel: install-time code (setup.py) cannot be ruled out"
                )
            if eco is Ecosystem.NPM:
                data = self._json(self._npm_url(name))
                if data is _NOT_FOUND:
                    return ScriptsUnknown("package not found in the registry")
                manifest = data["versions"].get(version)
                if manifest is None:
                    return ScriptsUnknown("version not found in the registry")
                scripts = manifest.get("scripts") or {}
                if not isinstance(scripts, dict):
                    return ScriptsUnknown("scripts field has an unexpected shape")
                return tuple(
                    InstallScript(hook=hook, body=str(scripts[hook]))
                    for hook in sorted(scripts)
                    if hook in INSTALL_HOOKS
                )
        except _FAILURES as exc:
            return ScriptsUnknown(f"registry query failed: {type(exc).__name__}")
        return ScriptsUnknown("ecosystem is not supported by the live registry")

    # ---- advisories --------------------------------------------------------------------

    def advisories(self, eco: Ecosystem, name: str, version: str) -> AdvisoryResult:
        if eco not in OSV_ECOSYSTEM:
            return AdvisoryUnknown(f"OSV has no mapping for {eco.value}")
        body = json.dumps(
            {"package": {"name": name, "ecosystem": OSV_ECOSYSTEM[eco]}, "version": version}
        ).encode("utf-8")
        try:
            data = self._json(self._osv, body)
            if data is _NOT_FOUND:
                return AdvisoryUnknown("OSV returned no body")
            if data.get("next_page_token"):
                return AdvisoryUnknown("OSV returned a paged result; not followed in v1")
            items = []
            for vuln in data.get("vulns", []):
                advisory_id = str(vuln["id"])
                summary = str(vuln.get("summary") or "")
                db = vuln.get("database_specific") or {}
                severity_text = str(db.get("severity", "")).upper() if isinstance(db, dict) else ""
                severity = _OSV_SEVERITY.get(severity_text, Severity.UNKNOWN)
                items.append(Advisory(advisory_id, severity, summary))
        except _FAILURES as exc:
            return AdvisoryUnknown(f"OSV query failed: {type(exc).__name__}")
        return Advisories(tuple(items))

    # ---- license and maintainers -------------------------------------------------------

    def license(self, eco: Ecosystem, name: str) -> LicenseInput:
        try:
            if eco is Ecosystem.PYPI:
                info = self._json(self._pypi_url(name))["info"]
                declared = info.get("license")
                if (
                    isinstance(declared, str)
                    and declared.strip()
                    and len(declared) <= 64
                    and "\n" not in declared
                ):
                    return declared.strip()
                for classifier in info.get("classifiers") or []:
                    if classifier in _CLASSIFIER_LICENSES:
                        return _CLASSIFIER_LICENSES[classifier]
                return (
                    None
                    if not declared
                    else LicenseUnknown("license text is not a recognized identifier")
                )
            if eco is Ecosystem.NPM:
                data = self._json(self._npm_url(name))
                latest = data["dist-tags"]["latest"]
                declared = data["versions"][latest].get("license")
                if declared is None:
                    return None
                if isinstance(declared, str):
                    return declared.strip() or None
                return LicenseUnknown("license field has an unexpected shape")
        except _FAILURES as exc:
            return LicenseUnknown(f"registry query failed: {type(exc).__name__}")
        return LicenseUnknown(f"license lookup is not supported for {eco.value}")

    def maintainers(self, eco: Ecosystem, name: str) -> MaintainerInput:
        # The public registries do not publish maintainer account ages. This is reported as
        # "not published" (WARN), not as unknown data (BLOCK). No lookup is attempted.
        return MaintainersNotPublished("the public registry does not report maintainer account age")

    # ---- lists -------------------------------------------------------------------------

    def top_n(self, eco: Ecosystem) -> tuple[str, ...]:
        return self._top.get(eco, ())

    def known_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return self._top.get(eco, ())

    def absent_names(self, eco: Ecosystem) -> tuple[str, ...]:
        return ()

    def alternatives(self, eco: Ecosystem, api: str, exclude: str) -> tuple[str, ...]:
        return ()
