"""P-C-1: the extractor never executes package code (canary, real subprocess).

Requirements: R-C-1, R-C-4. Each place that could run code writes a marker file if it runs: a
wheel's setup.py, its package __init__.py, its .pth file, and an npm package's install script and
index.js. The worker runs in a subprocess under the owner's limits. The marker must never appear.
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

from slopseal.contract.runner import ArchiveOk, run_archive_check

pytestmark = pytest.mark.skipif(os.name != "posix", reason="archive checks need POSIX limits")


def _canary(marker: Path) -> str:
    return f"open({str(marker)!r}, 'w').write('ran')\n"


def _canary_wheel(path: Path, marker: Path) -> Path:
    code = _canary(marker)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("setup.py", code)
        archive.writestr("pkg/__init__.py", code)
        archive.writestr("canary.pth", code)
        archive.writestr("pkg-1.0.dist-info/RECORD", "")
    return path


def _canary_npm(path: Path, marker: Path) -> Path:
    code = _canary(marker).encode()
    manifest = json.dumps(
        {"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": f"python3 -c {code!r}"}}
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


def test_p_c_1_an_npm_package_with_canaries_never_runs_them() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        marker = directory / "MARKER"
        tarball = _canary_npm(directory / "pkg.tgz", marker)
        result = run_archive_check(tarball, "npm")
        assert result == ArchiveOk("package")
        assert not marker.exists()
