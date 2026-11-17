"""The archive worker as a real subprocess with resource limits (R-C-4, POSIX).

Requirements: R-C-4. Property: P-C-5 (the subprocess path). Skipped on non-POSIX systems.
"""

from __future__ import annotations

import io
import os
import stat
import tempfile
import zipfile
from pathlib import Path

import pytest

from slopseal.contract.limits import MAX_COMPRESSED_BYTES
from slopseal.contract.runner import ArchiveOk, run_archive_check
from slopseal.contract.types import ContractUnknown, UnknownReason

pytestmark = pytest.mark.skipif(os.name != "posix", reason="archive checks need POSIX limits")


def _wheel(path: Path, members: list[tuple[str, bytes, int | None]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data)
    return path


def test_r_c_4_a_valid_wheel_passes_in_the_subprocess() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "pkg.whl", [("pkg/__init__.py", b"x = 1\n", None)])
        result = run_archive_check(path, "wheel")
        assert result == ArchiveOk("")


def test_r_c_4_a_hostile_wheel_is_parse_error_from_the_subprocess() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "bad.whl", [("pkg/link", b"/etc/passwd", stat.S_IFLNK | 0o777)])
        result = run_archive_check(path, "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.PARSE_ERROR


def test_r_c_4_the_wall_time_limit_is_limit() -> None:
    """A timeout kills the worker and reports limit. A tiny timeout forces it on any machine."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "pkg.whl", [("pkg/__init__.py", b"x = 1\n", None)])
        result = run_archive_check(path, "wheel", timeout=0.0001)
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.LIMIT


def test_r_c_4_an_artifact_over_the_compressed_limit_is_limit_without_a_read() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "huge.whl"
        with path.open("wb") as handle:
            handle.truncate(MAX_COMPRESSED_BYTES + 1)
        result = run_archive_check(path, "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.LIMIT


def test_r_c_4_an_unknown_kind_is_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "pkg.whl", [("pkg/a.py", b"", None)])
        with pytest.raises(ValueError, match="unknown artifact kind"):
            run_archive_check(path, "sdist")


def test_r_c_4_the_worker_output_is_json_and_nothing_else() -> None:
    """Stdout carries one JSON object. Other output would be parse_error."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/a.py", b"x = 1\n")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg.whl"
        path.write_bytes(buffer.getvalue())
        assert run_archive_check(path, "wheel") == ArchiveOk("")
