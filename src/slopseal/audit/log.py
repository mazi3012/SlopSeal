"""Append-only JSONL audit log with a hash chain and per-line seals (design section 10).

- Line 1 is a genesis entry: seq 0, event "genesis", prev_hash of 64 zeros.
- Each later line carries prev_hash (the previous line_hash) and line_hash
  = sha256(prev_hash + canonical JSON of the line without line_hash).
- Each non-genesis line carries an HMAC-SHA256 seal over its sealed fields (R-5.7.2).

Hash chain = ordering integrity. Seals = provenance. Both ship in Phase 4, and neither
substitutes for the other. A chain can be rebuilt end to end by anyone who can write the
file, and seals can be dropped, duplicated, or reordered without the chain.

Appends take an exclusive flock while they read the last line and write the next, so two
processes cannot fork the chain. On an empty file, the genesis line and the first event are
written in the same locked write, so the first event is never lost.

Requirements: R-5.7.1, R-5.7.1a, R-5.7.2. Properties: P-AU-1, P-AU-2. Layer 3.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from slopseal.audit.seal import canonical, seal_fields, sign, verify
from slopseal.fsutil import ensure_private_dir

GENESIS_PREV = "0" * 64
GENESIS_EVENT = "genesis"


def _line_hash(prev_hash: str, record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "line_hash"}
    payload = prev_hash + canonical(body).decode("utf-8")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sealed_fields(record: dict[str, Any]) -> dict[str, Any]:
    return seal_fields(
        package=str(record.get("package", "")),
        version=str(record.get("version", "")),
        checks_run=list(record.get("checks_run", [])),
        verdict=str(record.get("outcome", record.get("event", ""))),
        timestamp=str(record["ts"]),
        policy_hash=str(record.get("policy_hash", "")),
    )


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    lines: int
    head_seq: int | None
    head_hash: str | None
    failure_seq: int | None
    failure_check: str | None

    def describe(self) -> str:
        if self.ok:
            return (
                f"verified {self.lines} line(s); head seq {self.head_seq} "
                f"line_hash {self.head_hash}"
            )
        return f"FAILED at seq {self.failure_seq}: {self.failure_check}"


class AuditLog:
    def __init__(self, path: Path, key: bytes) -> None:
        self._path = path
        self._key = key

    @property
    def path(self) -> Path:
        return self._path

    def append(self, event: str, *, ts: datetime, fields: dict[str, Any]) -> dict[str, Any]:
        """Append one event line and return it. Raises OSError if it cannot be written.

        Callers treat a failed append as a failed verdict: an ALLOW that is not logged is not
        returned (fail closed).
        """
        ensure_private_dir(self._path.parent)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                existing = handle.read().splitlines()
                to_write: list[dict[str, Any]] = []
                if not existing:
                    genesis = self._genesis(ts)
                    to_write.append(genesis)
                    previous = genesis
                else:
                    previous = json.loads(existing[-1])
                event_line = self._event(event, ts, fields, previous)
                to_write.append(event_line)

                handle.seek(0, os.SEEK_END)
                for record in to_write:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return event_line

    def _genesis(self, ts: datetime) -> dict[str, Any]:
        body: dict[str, Any] = {
            "seq": 0,
            "event": GENESIS_EVENT,
            "ts": ts.isoformat(),
            "prev_hash": GENESIS_PREV,
        }
        body["line_hash"] = _line_hash(GENESIS_PREV, body)
        return body

    def _event(
        self, event: str, ts: datetime, fields: dict[str, Any], previous: dict[str, Any]
    ) -> dict[str, Any]:
        prev_hash = str(previous["line_hash"])
        body: dict[str, Any] = {
            "seq": int(previous["seq"]) + 1,
            "event": event,
            "ts": ts.isoformat(),
            "prev_hash": prev_hash,
        }
        body.update(
            {
                key: value
                for key, value in fields.items()
                if key not in ("seq", "prev_hash", "line_hash", "seal")
            }
        )
        body["seal"] = sign(self._key, _sealed_fields(body))
        body["line_hash"] = _line_hash(prev_hash, body)
        return body

    def verify(self) -> VerifyReport:
        """Check the genesis, contiguous seq, every prev_hash, every line_hash, and every seal."""
        try:
            raw = self._path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return VerifyReport(False, 0, None, None, None, "log file is missing")
        if not raw:
            return VerifyReport(False, 0, None, None, None, "log file is empty (no genesis)")

        previous_hash = GENESIS_PREV
        head_seq: int | None = None
        head_hash: str | None = None
        for index, text in enumerate(raw):
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                return _fail(raw, index, "line is not JSON")

            if record.get("seq") != index:
                return _fail(raw, index, "seq is not contiguous from 0")
            if index == 0:
                if record.get("event") != GENESIS_EVENT or record.get("prev_hash") != GENESIS_PREV:
                    return _fail(raw, index, "genesis entry is missing or malformed")
            elif record.get("event") == GENESIS_EVENT:
                return _fail(raw, index, "a second genesis entry was found")
            if record.get("prev_hash") != previous_hash:
                return _fail(raw, index, "prev_hash does not match the previous line")
            if _line_hash(previous_hash, record) != record.get("line_hash"):
                return _fail(raw, index, "line_hash does not match the line contents")
            if index > 0 and not _seal_ok(self._key, record):
                return _fail(raw, index, "seal does not verify")

            previous_hash = str(record["line_hash"])
            head_seq = int(record["seq"])
            head_hash = previous_hash

        return VerifyReport(True, len(raw), head_seq, head_hash, None, None)


def _seal_ok(key: bytes, record: dict[str, Any]) -> bool:
    seal = record.get("seal")
    return isinstance(seal, str) and verify(key, _sealed_fields(record), seal)


def _fail(raw: list[str], index: int, check: str) -> VerifyReport:
    return VerifyReport(False, len(raw), None, None, index, check)


@dataclass(frozen=True)
class LineCheck:
    """Checks on one line, independent of the others. `verify` stops at the first failure. This
    reports every line, so a receipt can show the state of each entry."""

    seq: int | None
    chain_ok: bool
    seal: str  # "ok", "invalid", "not applicable" (genesis), or "unreadable"
    problem: str | None


def line_checks(lines: list[str], key: bytes) -> list[LineCheck]:
    """Check every line's hash link, line hash, and seal. Read-only; never writes the log."""
    checks: list[LineCheck] = []
    previous_hash = GENESIS_PREV
    for index, text in enumerate(lines):
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            checks.append(LineCheck(None, False, "unreadable", "line is not JSON"))
            continue
        if not isinstance(record, dict):
            checks.append(LineCheck(None, False, "unreadable", "line is not an object"))
            continue
        seq = record.get("seq") if isinstance(record.get("seq"), int) else None
        problems: list[str] = []
        if record.get("prev_hash") != previous_hash:
            problems.append("prev_hash does not match the previous line")
        if _line_hash(previous_hash, record) != record.get("line_hash"):
            problems.append("line_hash does not match the line contents")
        if index == 0:
            seal = "not applicable"
        else:
            seal = "ok" if _seal_ok(key, record) else "invalid"
            if seal == "invalid":
                problems.append("seal does not verify")
        checks.append(LineCheck(seq, not problems, seal, "; ".join(problems) or None))
        previous_hash = str(record.get("line_hash", ""))
    return checks
