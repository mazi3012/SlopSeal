"""test_contract_plumbing_snapshot_parity (R-C-8, design 2.9): live agrees with the snapshot.

For each of the 23 snapshot versions, the test builds an artifact (a wheel for PyPI, a tarball for
npm) from that version's snapshot exports. It serves the registry metadata and the artifact
through fakes, so no test touches the network. The whole live path then runs, with the real
digest check, the archive check in the worker, and the extraction in the worker.

It requires two things:
- The live contract is complete and contains every snapshot export.
- For every probe, live and offline give the same outcome (PRESENT or ABSENT). The probes are each
  snapshot export, each export with `_x` added, and one name that exists nowhere.

This proves the plumbing from artifact to verdict. It does not measure accuracy on real packages;
that is the labelled run (docs/CONTRACT_EVAL.md).

Requirements: R-C-8. Properties: P-C-3 (the digest check runs first), P-C-5, P-C-6 along the path.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

import pytest

from slopseal.contract.types import ContractComplete
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.quarantine.api_surface import ApiSurface, check_contract
from slopseal.registry.live import LiveSource
from slopseal.registry.source import OfflineSource

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
PYPI_BASE = "https://parity.invalid/pypi"
NPM_BASE = "https://parity.invalid/npm"
NOWHERE = "zz_nowhere_probe"


def _snapshot_versions() -> list[tuple[Ecosystem, str, str, list[str]]]:
    document = json.loads((FIXTURES / "registry_snapshot.json").read_text(encoding="utf-8"))
    found: list[tuple[Ecosystem, str, str, list[str]]] = []
    for eco_name, packages in document["packages"].items():
        eco = Ecosystem.PYPI if eco_name == "pypi" else Ecosystem.NPM
        for name, meta in packages.items():
            for version, version_meta in meta.get("versions", {}).items():
                found.append((eco, name, version, list(version_meta["exports"])))
    return found


VERSIONS = _snapshot_versions()


def _wheel(dist: str, version: str, exports: list[str]) -> tuple[str, bytes]:
    """A wheel whose importable names are the exports. `pkg.sym` makes module pkg with def sym."""
    packages: dict[str, list[str]] = {}
    for export in exports:
        if "." in export:
            package, symbol = export.split(".", 1)
        else:
            package, symbol = dist.replace("-", "_"), export
        packages.setdefault(package, []).append(symbol)
    files = {
        f"{package}/__init__.py": "".join(f"def {symbol}():\n    pass\n" for symbol in symbols)
        for package, symbols in packages.items()
    }
    dist_info = f"{dist.replace('-', '_')}-{version}.dist-info"
    record = "".join(f"{name},,\n" for name in files) + f"{dist_info}/RECORD,,\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
        archive.writestr(f"{dist_info}/RECORD", record)
    filename = f"{dist.replace('-', '_')}-{version}-py3-none-any.whl"
    return filename, buffer.getvalue()


def _npm_tarball(name: str, version: str, exports: list[str]) -> bytes:
    manifest = {"name": name, "version": version, "main": "index.js"}
    index = "".join(f"exports.{export} = 0;\n" for export in exports)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for member, body in (
            ("package/package.json", json.dumps(manifest)),
            ("package/index.js", index),
        ):
            data = body.encode("utf-8")
            info = tarfile.TarInfo(member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _build(eco: Ecosystem, name: str, version: str, exports: list[str]):
    """The artifact bytes, the registry metadata documents, and the URL each one is served at."""
    artifacts: dict[str, bytes] = {}
    documents: dict[str, bytes] = {}
    if eco is Ecosystem.PYPI:
        filename, data = _wheel(name, version, exports)
        url = f"https://files.pythonhosted.org/packages/parity/{filename}"
        digest = hashlib.sha256(data).hexdigest()
        artifacts[url] = data
        document = {
            "urls": [
                {
                    "filename": filename,
                    "url": url,
                    "packagetype": "bdist_wheel",
                    "digests": {"sha256": digest},
                }
            ]
        }
        version_path = f"{PYPI_BASE}/{quote(name, safe='')}/{quote(version, safe='')}/json"
        documents[version_path] = json.dumps(document).encode("utf-8")
    else:
        data = _npm_tarball(name, version, exports)
        url = f"https://registry.npmjs.org/parity/{name}-{version}.tgz"
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
        artifacts[url] = data
        packument = {
            "dist-tags": {"latest": version},
            "versions": {version: {"dist": {"tarball": url, "integrity": integrity}}},
        }
        documents[f"{NPM_BASE}/{quote(name, safe='@')}"] = json.dumps(packument).encode("utf-8")
    return artifacts, documents


@pytest.mark.parametrize(
    ("eco", "name", "version", "exports"),
    VERSIONS,
    ids=[f"{eco.value}:{name}@{version}" for eco, name, version, _ in VERSIONS],
)
def test_contract_plumbing_snapshot_parity(
    eco: Ecosystem, name: str, version: str, exports: list[str]
) -> None:
    artifacts, documents = _build(eco, name, version, exports)

    def fetch(url: str, _body: bytes | None) -> bytes | None:
        if url in documents:
            return documents[url]
        raise OSError(f"no fixture for {url}")

    snapshot = load_snapshot(FIXTURES)
    with tempfile.TemporaryDirectory() as state:
        live = LiveSource(
            pypi_base=PYPI_BASE,
            npm_base=NPM_BASE,
            fetch=fetch,
            artifact_fetch=lambda url, _eco: artifacts[url],
            cache_root=Path(state),
        )
        live_result = live.contract(eco, name, version)
    offline_result = OfflineSource(snapshot).contract(eco, name, version)

    assert isinstance(live_result, ContractComplete), live_result
    assert isinstance(offline_result, ContractComplete), offline_result
    assert set(exports) <= set(live_result.exports), "the live contract must contain every export"

    probes = [*exports, *(f"{export}_x" for export in exports), NOWHERE]
    for probe in probes:
        live_outcome = check_contract(live_result, probe).outcome
        offline_outcome = check_contract(offline_result, probe).outcome
        assert live_outcome is not ApiSurface.UNKNOWN
        assert live_outcome is offline_outcome, (probe, live_outcome, offline_outcome)
