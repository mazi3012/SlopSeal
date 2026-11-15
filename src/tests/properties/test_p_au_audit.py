"""Property tests for the audit log, the hash chain, and the seals.

Requirements: R-5.7.1, R-5.7.1a, R-5.7.2, R-1.5. Properties: P-AU-1, P-AU-2.
Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.audit.log import GENESIS_PREV, AuditLog
from slopseal.audit.seal import KEY_BYTES, SealKeyError, load_or_create_key

TS = datetime(2026, 11, 18, tzinfo=UTC)


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n", encoding="utf-8"
    )


def _rehash(records: list[dict[str, Any]]) -> None:
    """Recompute line hashes after an edit. An attacker without the key can do this, but the
    seal still fails, which is the point of the test."""
    prev = GENESIS_PREV
    for record in records:
        record["prev_hash"] = prev
        body = {k: v for k, v in record.items() if k != "line_hash"}
        payload = prev + json.dumps(body, sort_keys=True, separators=(",", ":"))
        record["line_hash"] = hashlib.sha256(payload.encode()).hexdigest()
        prev = record["line_hash"]


def _event(log: AuditLog, outcome: str, package: str) -> None:
    log.append(
        "verdict",
        ts=TS,
        fields={
            "ecosystem": "pypi",
            "package": package,
            "version": "1.0.0",
            "outcome": outcome,
            "exit_code": 0,
            "checks_run": ["existence"],
            "warnings": [],
            "policy_hash": "p" * 64,
            "snapshot_id": "s",
        },
    )


# ---- P-AU-1 -----------------------------------------------------------------------------


@given(events=st.lists(st.sampled_from(["ALLOW", "BLOCK", "QUARANTINE"]), min_size=1, max_size=6))
def test_p_au_1_lines_are_contiguous_and_one_per_event(events: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        log = AuditLog(path, load_or_create_key(Path(tmp)))
        for outcome in events:
            _event(log, outcome, "pkg")
        records = _lines(path)
        report = log.verify()
    assert [r["seq"] for r in records] == list(range(len(events) + 1))
    assert records[0]["event"] == "genesis"
    assert [r["outcome"] for r in records[1:]] == events
    assert report.ok


def test_first_event_is_never_lost_on_an_empty_log() -> None:
    """Regression: the first append on a new log once wrote only the genesis line."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        _event(AuditLog(path, load_or_create_key(Path(tmp))), "ALLOW", "first")
        records = _lines(path)
    assert len(records) == 2
    assert records[1]["package"] == "first"


# ---- P-AU-2: seals and the chain ------------------------------------------------------------


SEALED_FIELDS = ["outcome", "package", "version", "policy_hash", "ts"]


@given(field=st.sampled_from(SEALED_FIELDS), suffix=st.text(alphabet="xyz", min_size=1, max_size=4))
def test_p_au_2_changing_any_sealed_field_breaks_the_seal(field: str, suffix: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        log = AuditLog(path, load_or_create_key(Path(tmp)))
        _event(log, "ALLOW", "original")
        records = _lines(path)
        target = records[1]
        if field == "ts":
            target["ts"] = target["ts"] + suffix
        else:
            target[field] = str(target.get(field, "")) + suffix
        _rehash(records)
        _write(path, records)
        report = log.verify()
    assert not report.ok
    assert report.failure_seq == 1
    assert report.failure_check == "seal does not verify"


@given(index=st.integers(min_value=1, max_value=5))
def test_p_au_2_deleting_any_middle_line_is_detected(index: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        log = AuditLog(path, load_or_create_key(Path(tmp)))
        for n in range(6):
            _event(log, "ALLOW", f"pkg{n}")
        records = _lines(path)
        assume(index < len(records) - 1)
        del records[index]
        _write(path, records)
        assert not log.verify().ok


def test_a_different_key_fails_verification() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        AuditLog(path, load_or_create_key(Path(tmp))).append(
            "verdict",
            ts=TS,
            fields={
                "outcome": "ALLOW",
                "package": "p",
                "version": "1",
                "checks_run": [],
                "policy_hash": "x",
            },
        )
        other = AuditLog(path, bytes(KEY_BYTES))
        assert not other.verify().ok


def test_a_log_without_genesis_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        log = AuditLog(path, load_or_create_key(Path(tmp)))
        _event(log, "ALLOW", "a")
        records = _lines(path)[1:]
        _write(path, records)
        assert not log.verify().ok


def test_missing_log_is_reported_not_verified() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        report = AuditLog(Path(tmp) / "absent.jsonl", bytes(KEY_BYTES)).verify()
    assert not report.ok


# ---- Seal key lifecycle ----------------------------------------------------------------------


def test_seal_key_is_created_once_with_owner_only_permissions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        first = load_or_create_key(root)
        second = load_or_create_key(root)
        mode = (root / "secret.key").stat().st_mode & 0o777
    assert first == second
    assert len(first) == KEY_BYTES
    assert mode == 0o600


def test_seal_key_with_wrong_length_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "secret.key").write_bytes(b"short")
        with pytest.raises(SealKeyError, match="wrong length"):
            load_or_create_key(root)
