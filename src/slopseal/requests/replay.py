"""Request binding and replay (D2 section 8.4).

A request id is bound to the session token and to the exact content of the request that first
used it. The store keeps, per request id: the token id, the SHA-256 of the canonical request, and
the verdict id.

Decisions for an incoming request with a known id:

- Same token and same hash: return the cached verdict, with no new quota count (REPLAY_CACHED).
- Same token, different hash: refuse (REPLAY_CONFLICT). Nothing is evaluated.
- Different token: refuse (REPLAY_DENIED). Nothing is evaluated.

Freshness: a request whose timestamp is more than 2 minutes in the future, or more than 10 minutes
in the past, is refused (REQUEST_STALE). Because of this, a request id only has to be remembered for
the 10-minute window.

The store is file-backed and written atomically under a lock, so a restart keeps the replay record.
This is a building block. The verdict service (D2 milestone M1) is not built yet, so nothing in
the running code calls it.

Requirements: R-RB-1, R-RB-2. Covers AC-26 to AC-29. Layer 4. Stdlib only.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from slopseal.core.names import normalize_name
from slopseal.core.types import Ecosystem

FUTURE_SKEW = timedelta(minutes=2)
REPLAY_WINDOW = timedelta(minutes=10)
_FILE = "replay.json"


class Decision(Enum):
    EVALUATE = "EVALUATE"  # new request: evaluate it and count it once
    REPLAY_CACHED = "REPLAY_CACHED"  # identical replay: return the cached verdict, do not count
    REPLAY_CONFLICT = "REPLAY_CONFLICT"  # same token, altered content
    REPLAY_DENIED = "REPLAY_DENIED"  # different token
    REQUEST_STALE = "REQUEST_STALE"  # outside the freshness window


@dataclass(frozen=True)
class Admission:
    decision: Decision
    verdict_id: str | None = None  # set for REPLAY_CACHED


@dataclass(frozen=True)
class CanonicalRequest:
    """Every field that can change the verdict or the quota. Absent fields are None."""

    ecosystem: Ecosystem
    name: str
    version: str
    timestamp: str  # ISO-8601 with a UTC offset, as the client sent it
    token_id: str
    purpose: str | None = None
    expected_api: str | None = None
    quarantine_id: str | None = None

    def hash(self) -> str:
        """SHA-256 over the canonical JSON: sorted keys, no insignificant whitespace."""
        body: dict[str, Any] = {
            "ecosystem": self.ecosystem.value,
            "name": normalize_name(self.ecosystem, self.name),
            "version": self.version,
            "purpose": self.purpose,
            "expected_api": self.expected_api,
            "quarantine_id": self.quarantine_id,
            "token_id": self.token_id,
            "timestamp": self.timestamp,
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def parse_timestamp(text: str) -> datetime:
    """A timezone-aware UTC time. A timestamp without an offset is refused."""
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone offset")
    return parsed.astimezone(UTC)


def is_fresh(timestamp: datetime, now: datetime) -> bool:
    age = now - timestamp
    return -FUTURE_SKEW <= age <= REPLAY_WINDOW


class ReplayStore:
    """Per request id: token id, request hash, verdict id, and the time it was recorded."""

    def __init__(
        self, root: Path, clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ) -> None:
        self._path = root / _FILE
        self._clock = clock

    def _read(self) -> dict[str, dict[str, str]]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("unexpected replay store structure")
        return data

    def _write(self, entries: dict[str, dict[str, str]]) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=self._path.parent, prefix=".rp-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(entries, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self._path)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise

    def _locked(self) -> Any:
        """Open the lock file. Directory is 0700 and lock file is 0600, whatever the umask."""
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self._path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        return os.fdopen(fd, "a+", encoding="utf-8")

    def admit(self, request_id: str, request: CanonicalRequest) -> Admission:
        """Decide what to do with an incoming request. Records nothing."""
        now = self._clock()
        try:
            stamp = parse_timestamp(request.timestamp)
        except ValueError:
            return Admission(Decision.REQUEST_STALE)
        if not is_fresh(stamp, now):
            return Admission(Decision.REQUEST_STALE)
        lock = self._locked()
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            entries = self._prune(self._read(), now)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
        known = entries.get(request_id)
        if known is None:
            return Admission(Decision.EVALUATE)
        if known["token_id"] != request.token_id:
            return Admission(Decision.REPLAY_DENIED)
        if known["request_hash"] != request.hash():
            return Admission(Decision.REPLAY_CONFLICT)
        return Admission(Decision.REPLAY_CACHED, known["verdict_id"])

    def record(self, request_id: str, request: CanonicalRequest, verdict_id: str) -> None:
        """Remember a request that was evaluated. Call once, after the verdict is written."""
        now = self._clock()
        lock = self._locked()
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            entries = self._prune(self._read(), now)
            if request_id in entries:
                raise ValueError("request id is already recorded")
            entries[request_id] = {
                "token_id": request.token_id,
                "request_hash": request.hash(),
                "verdict_id": verdict_id,
                "recorded_at": now.isoformat(),
            }
            self._write(entries)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    @staticmethod
    def _prune(entries: dict[str, dict[str, str]], now: datetime) -> dict[str, dict[str, str]]:
        kept: dict[str, dict[str, str]] = {}
        for request_id, value in entries.items():
            recorded = datetime.fromisoformat(value["recorded_at"])
            if now - recorded <= REPLAY_WINDOW + FUTURE_SKEW:
                kept[request_id] = value
        return kept
