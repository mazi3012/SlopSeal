"""P-C-5: a limit break or a hostile archive gives UNKNOWN, and nothing is written.

Requirements: R-C-4. Hypothesis runs 500 examples per property (conftest.py profile).

The worker's checks run in-process, with small limits so that a limit break is cheap to build. The
owner limits are exercised by the subprocess tests (test_contract_runner.py). No member is written
out: the directory listing is compared before and after each check.
"""

from __future__ import annotations

import io
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from slopseal.contract import worker

SMALL = {"max_expanded": 200_000, "max_members": 8, "max_package_json": 100_000}
HOSTILE_NAMES = [
    "/abs/evil.py",
    "../escape.py",
    "pkg/../../escape.py",
    "pkg\\evil.py",
    "pkg/ok/../../../x.py",
]
SPECIAL_MODES = [
    stat.S_IFLNK | 0o777,
    stat.S_IFCHR | 0o644,
    stat.S_IFBLK | 0o644,
    stat.S_IFIFO | 0o644,
]


def _zip_bytes(members: list[tuple[str, bytes, int | None, int]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data, mode, compress in members:
            info = zipfile.ZipInfo(name)
            info.compress_type = compress
            if mode is not None:
                info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def _listing(directory: Path) -> list[str]:
    return sorted(str(p.relative_to(directory)) for p in directory.rglob("*"))


def _run_zip(data: bytes, limits: dict[str, int]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        path = directory / "a.whl"
        path.write_bytes(data)
        before = _listing(directory)
        try:
            worker.check_zip(
                str(path), limits["max_expanded"], limits["max_members"], limits["max_package_json"]
            )
        finally:
            assert _listing(directory) == before


@given(name=st.sampled_from(HOSTILE_NAMES), size=st.integers(min_value=0, max_value=64))
def test_p_c_5_a_hostile_name_is_parse_error_and_nothing_is_written(name: str, size: int) -> None:
    data = _zip_bytes(
        [
            ("pkg/ok.py", b"x" * size, None, zipfile.ZIP_STORED),
            (name, b"y", None, zipfile.ZIP_STORED),
        ]
    )
    try:
        _run_zip(data, SMALL)
    except worker.Unsafe:
        return
    raise AssertionError(f"the hostile name {name!r} was accepted")


@given(mode=st.sampled_from(SPECIAL_MODES))
def test_p_c_5_a_link_or_special_member_is_parse_error(mode: int) -> None:
    data = _zip_bytes(
        [
            ("pkg/ok.py", b"x", None, zipfile.ZIP_STORED),
            ("pkg/special", b"y", mode, zipfile.ZIP_STORED),
        ]
    )
    try:
        _run_zip(data, SMALL)
    except worker.Unsafe:
        return
    raise AssertionError("a link or special member was accepted")


@given(count=st.integers(min_value=9, max_value=20))
def test_p_c_5_too_many_members_is_limit(count: int) -> None:
    data = _zip_bytes([(f"pkg/{i}.py", b"", None, zipfile.ZIP_STORED) for i in range(count)])
    try:
        _run_zip(data, SMALL)
    except worker.Limit:
        return
    raise AssertionError("a member count over the limit was accepted")


@given(size=st.integers(min_value=300_000, max_value=2_000_000))
def test_p_c_5_a_bomb_is_limit_by_expanded_bytes(size: int) -> None:
    """A member that compresses to almost nothing is still counted by its expanded bytes."""
    data = _zip_bytes([("pkg/bomb.bin", b"\x00" * size, None, zipfile.ZIP_DEFLATED)])
    assert len(data) < size // 100
    try:
        _run_zip(data, SMALL)
    except worker.Limit:
        return
    raise AssertionError("an expanded size over the limit was accepted")


@given(name=st.sampled_from(["pkg/ok/../../escape.py", "/root/x.py"]))
def test_p_c_5_npm_hostile_names_are_parse_error(name: str) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("package/package.json")
        body = b'{"name": "pkg"}'
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
        evil = tarfile.TarInfo(name)
        evil.size = 1
        archive.addfile(evil, io.BytesIO(b"y"))
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "a.tgz"
        path.write_bytes(buffer.getvalue())
        try:
            worker.check_npm(
                str(path), SMALL["max_expanded"], SMALL["max_members"], SMALL["max_package_json"]
            )
        except worker.Unsafe:
            return
    raise AssertionError(f"the npm member {name!r} was accepted")
