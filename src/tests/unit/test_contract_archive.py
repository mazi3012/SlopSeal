"""Archive safety checks in the worker (R-C-4, R-C-3 root selection). Property: P-C-5.

The worker functions are called in-process on archives built in memory and written to a temporary
directory. The checks read members and never write them out. Requirements: R-C-4, R-C-3.
"""

from __future__ import annotations

import io
import json
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from slopseal.contract import worker


def _zip(members: list[tuple[str, bytes, int | None]], path: Path) -> Path:
    """Write a zip. Each member is (name, data, unix mode or None)."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if mode is not None:
                info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data)
    return path


def _tar(members: list[tuple[str, bytes, bytes]], path: Path) -> Path:
    """Write a gzip tarball. Each member is (name, type byte, data). Type b"0" is a regular file."""
    with tarfile.open(path, "w:gz") as archive:
        for name, kind, data in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    info.linkname = "target"
                archive.addfile(info)
    return path


MANIFEST = json.dumps({"name": "pkg", "version": "1.0.0"}).encode()
LIMITS = {"max_expanded": 10_000_000, "max_members": 5000, "max_package_json": 1_000_000}


def _check_zip(path: Path, **overrides: int) -> dict[str, str]:
    limits = {**LIMITS, **overrides}
    return worker.check_zip(
        str(path), limits["max_expanded"], limits["max_members"], limits["max_package_json"]
    )


def _check_npm(path: Path, **overrides: int) -> dict[str, str]:
    limits = {**LIMITS, **overrides}
    return worker.check_npm(
        str(path), limits["max_expanded"], limits["max_members"], limits["max_package_json"]
    )


def test_r_c_4_a_plain_wheel_passes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _zip(
            [("pkg/__init__.py", b"x = 1\n", None), ("pkg-1.0.dist-info/RECORD", b"", None)],
            Path(tmp) / "a.whl",
        )
        assert _check_zip(path) == {"status": "ok", "root": ""}


@pytest.mark.parametrize(
    "name",
    # A NUL byte is not tested here: zipfile cuts a name at NUL when it reads it back, so the
    # worker never sees one. The NUL check in the worker stays as defence in depth.
    ["/etc/passwd", "../escape.py", "pkg/../../escape.py", "pkg\\evil.py", ""],
)
def test_r_c_4_an_unsafe_name_is_parse_error(name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _zip([(name, b"x", None)], Path(tmp) / "a.whl")
        with pytest.raises(worker.Unsafe):
            _check_zip(path)


@pytest.mark.filterwarnings("ignore:Duplicate name")
def test_r_c_4_a_duplicate_member_name_is_parse_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _zip([("pkg/a.py", b"x", None), ("pkg/a.py", b"y", None)], Path(tmp) / "a.whl")
        with pytest.raises(worker.Unsafe):
            _check_zip(path)


def test_r_c_4_a_zip_symlink_member_is_parse_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _zip([("pkg/link", b"/etc/passwd", stat.S_IFLNK | 0o777)], Path(tmp) / "a.whl")
        with pytest.raises(worker.Unsafe):
            _check_zip(path)


def test_r_c_4_a_zip_member_count_over_the_limit_is_limit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _zip([(f"pkg/{i}.py", b"", None) for i in range(4)], Path(tmp) / "a.whl")
        with pytest.raises(worker.Limit):
            _check_zip(path, max_members=3)


def test_r_c_4_a_zip_bomb_is_limit_by_expanded_bytes_not_compressed_bytes() -> None:
    """A member that compresses to almost nothing still counts its expanded bytes (P-C-5)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _zip([("pkg/big.bin", b"\x00" * 5_000_000, None)], Path(tmp) / "a.whl")
        assert path.stat().st_size < 100_000  # the compressed file is small
        with pytest.raises(worker.Limit):
            _check_zip(path, max_expanded=1_000_000)


def test_r_c_4_an_npm_tarball_with_a_symlink_is_parse_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _tar(
            [
                ("package/package.json", tarfile.REGTYPE, MANIFEST),
                ("package/link", tarfile.SYMTYPE, b""),
            ],
            Path(tmp) / "a.tgz",
        )
        with pytest.raises(worker.Unsafe):
            _check_npm(path)


def test_r_c_4_an_npm_tarball_with_a_hardlink_is_parse_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _tar(
            [
                ("package/package.json", tarfile.REGTYPE, MANIFEST),
                ("package/hard", tarfile.LNKTYPE, b""),
            ],
            Path(tmp) / "a.tgz",
        )
        with pytest.raises(worker.Unsafe):
            _check_npm(path)


def test_r_c_4_an_npm_tarball_with_a_device_or_fifo_is_parse_error() -> None:
    for kind in (tarfile.CHRTYPE, tarfile.FIFOTYPE):
        with tempfile.TemporaryDirectory() as tmp:
            path = _tar(
                [("package/package.json", tarfile.REGTYPE, MANIFEST), ("package/odd", kind, b"")],
                Path(tmp) / "a.tgz",
            )
            with pytest.raises(worker.Unsafe):
                _check_npm(path)


def test_r_c_3_the_npm_root_is_the_shallowest_package_json() -> None:
    """A package whose package.json sits at `ms/`, not `package/`, is read from there."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _tar(
            [
                ("ms/package.json", tarfile.REGTYPE, MANIFEST),
                ("ms/README.md", tarfile.REGTYPE, b"readme"),
                ("ms/deep/other/package.json", tarfile.REGTYPE, b"{}"),
            ],
            Path(tmp) / "a.tgz",
        )
        assert _check_npm(path) == {"status": "ok", "root": "ms"}


def test_r_c_3_two_shallowest_package_json_files_are_parse_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _tar(
            [
                ("a/package.json", tarfile.REGTYPE, MANIFEST),
                ("b/package.json", tarfile.REGTYPE, MANIFEST),
            ],
            Path(tmp) / "a.tgz",
        )
        with pytest.raises(worker.Unsafe, match="ambiguous"):
            _check_npm(path)


def test_r_c_3_a_tarball_without_package_json_is_parse_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _tar([("package/index.js", tarfile.REGTYPE, b"x")], Path(tmp) / "a.tgz")
        with pytest.raises(worker.Unsafe, match="no package.json"):
            _check_npm(path)


def test_r_c_3_a_package_json_that_does_not_parse_is_parse_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _tar([("package/package.json", tarfile.REGTYPE, b"{not json")], Path(tmp) / "a.tgz")
        with pytest.raises(ValueError, match="Expecting"):
            _check_npm(path)


def test_r_c_4_nothing_is_written_next_to_the_archive() -> None:
    """The check reads members into memory and writes nothing. The directory is unchanged."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        path = _zip([("pkg/a.py", b"x = 1\n", None)], directory / "a.whl")
        before = sorted(p.name for p in directory.iterdir())
        _check_zip(path)
        assert sorted(p.name for p in directory.iterdir()) == before
