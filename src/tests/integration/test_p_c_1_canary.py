"""P-C-1: the extractor never executes package code (canary, real subprocess).

Requirements: R-C-1, R-C-2, R-C-4. Each place that could run code makes a marker directory if it
runs: a wheel's setup.py, its package __init__.py, its .pth file, and an npm package's install
script and index.js. The marker is a directory made with os.mkdir, not a file: the worker's
RLIMIT_FSIZE of 0 blocks writing a file, and that would hide a mutant that runs the canary. The
worker runs in a subprocess under the owner's limits. The marker must never appear, whatever the
extractor returns.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from slopseal.contract.runner import ArchiveOk, run_archive_check, run_extract
from slopseal.contract.types import ContractComplete, ContractUnknown

pytestmark = pytest.mark.skipif(os.name != "posix", reason="archive checks need POSIX limits")


def _canary(marker: Path) -> str:
    return f"import os\nos.mkdir({str(marker)!r})\n"


def _canary_wheel(path: Path, marker: Path) -> Path:
    code = _canary(marker)
    files = {
        "setup.py": code,
        "pkg/__init__.py": code,
        "canary.pth": code,
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
        record = "".join(f"{name},,\n" for name in files) + "pkg-1.0.dist-info/RECORD,,\n"
        archive.writestr("pkg-1.0.dist-info/RECORD", record)
    return path


def _canary_npm(path: Path, marker: Path) -> Path:
    code = _canary(marker).encode()
    manifest = json.dumps(
        {
            "name": "pkg",
            "version": "1.0.0",
            "scripts": {
                "preinstall": f"python3 -c {code!r}",
                "postinstall": f"python3 -c {code!r}",
            },
        }
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, body in [("package/package.json", manifest), ("package/index.js", code)]:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    path.write_bytes(buffer.getvalue())
    return path


def test_p_c_1_a_wheel_with_canaries_never_runs_them() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        marker = directory / "MARKER"
        wheel = _canary_wheel(directory / "pkg.whl", marker)
        result = run_archive_check(wheel, "wheel")
        assert result == ArchiveOk("")
        assert not marker.exists()


def test_p_c_1_extraction_of_a_wheel_with_canaries_never_runs_them() -> None:
    """The extract mode parses the same canaries and returns a result without running them."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        marker = directory / "MARKER"
        wheel = _canary_wheel(directory / "pkg.whl", marker)
        result = run_extract(wheel, "wheel")
        assert isinstance(result, ContractComplete)  # the canaries are plain modules
        assert not marker.exists()


def test_p_c_1_an_npm_package_with_canaries_never_runs_them() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        marker = directory / "MARKER"
        tarball = _canary_npm(directory / "pkg.tgz", marker)
        result = run_archive_check(tarball, "npm")
        assert result == ArchiveOk("package")
        assert not marker.exists()


def test_p_c_1_npm_extraction_never_runs_the_canaries() -> None:
    """The npm extract mode reads the manifest and index.js. Nothing in them runs."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        marker = directory / "MARKER"
        tarball = _canary_npm(directory / "pkg.tgz", marker)
        result = run_extract(tarball, "npm", "package")
        assert isinstance(result, ContractComplete | ContractUnknown)
        assert not marker.exists()
