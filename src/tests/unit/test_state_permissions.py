"""State directories are 0700 and state or lock files are 0600, whatever the umask (R-FS-1).

Each test runs with umask 0. Before the fix, directories came out 0777 and files 0666 under this
umask, so the assertions fail on the old code. One test covers each module that writes state.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.contract import cache
from slopseal.contract.digest import PublishedDigest, VerifiedDigest, verify_artifact
from slopseal.contract.types import ContractComplete
from slopseal.quarantine.rate_limit import RateLimiter
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id

TS = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
DATA = b"wheel bytes"
DIGEST_HEX = hashlib.sha256(DATA).hexdigest()
KEY = f"sha256-{DIGEST_HEX}"


@pytest.fixture
def permissive_umask() -> Iterator[None]:
    previous = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _assert_private_dir(path: Path) -> None:
    assert _mode(path) == 0o700, f"{path} is {oct(_mode(path))}, expected 0o700"


def _assert_private_files(directory: Path) -> None:
    files = [p for p in directory.iterdir() if p.is_file()]
    assert files, f"no files were written under {directory}"
    for path in files:
        assert _mode(path) == 0o600, f"{path} is {oct(_mode(path))}, expected 0o600"


def test_r_fs_1_seal_key_directory_and_key_are_private(
    tmp_path: Path, permissive_umask: None
) -> None:
    state = tmp_path / "state"
    load_or_create_key(state)
    _assert_private_dir(state)
    _assert_private_files(state)


def test_r_fs_1_audit_log_directory_and_file_are_private(
    tmp_path: Path, permissive_umask: None
) -> None:
    state = tmp_path / "state"
    log = AuditLog(state / "audit.log", key=b"\x01" * 32)
    log.append("verdict", ts=TS, fields={})
    _assert_private_dir(state)
    _assert_private_files(state)


def test_r_fs_1_contract_cache_directory_and_entries_are_private(
    tmp_path: Path, permissive_umask: None
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    result = verify_artifact(DATA, PublishedDigest("sha256", DIGEST_HEX))
    assert isinstance(result, VerifiedDigest)
    cache.store(root, result, ("parse",))
    assert cache.load(root, KEY) == ContractComplete(("parse",))
    contracts = root / cache.CACHE_DIR
    _assert_private_dir(contracts)
    _assert_private_files(contracts)


def test_r_fs_1_rate_limit_directory_and_lock_are_private(
    tmp_path: Path, permissive_umask: None
) -> None:
    state = tmp_path / "state"
    limiter = RateLimiter(state, limit=5, clock=lambda: TS)
    limiter.attempt()
    _assert_private_dir(state)
    _assert_private_files(state)


def test_r_fs_1_quarantine_store_directories_and_files_are_private(
    tmp_path: Path, permissive_umask: None
) -> None:
    state = tmp_path / "state"
    store = QuarantineStore(state)
    quarantine_id = new_quarantine_id(bytes(range(13)))
    store.write_artifact(quarantine_id, {"quarantine_id": quarantine_id})
    _assert_private_dir(state / "pending_approval")
    _assert_private_files(state / "pending_approval")
