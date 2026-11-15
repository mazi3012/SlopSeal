"""Install rate limit (PRD 4.7): at most N install attempts in a rolling 60-second window.

State is one JSON file of attempt timestamps. Every attempt is recorded, including blocked
ones, so an agent that is blocked cannot reset the window by retrying.

Fail closed:
- A missing state file means no attempts yet, so the attempt is allowed.
- An unreadable or corrupt state file blocks the attempt and is left in place for an operator
  to inspect. Deleting it resets the window. Overwriting it does not happen automatically,
  because that would let a corrupted file reset the limit.

Writes are serialised with flock and replaced atomically.

Requirements: R-4.7. Layer 3. The clock is injected.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

WINDOW = timedelta(seconds=60)
_FILE = "ratelimit.json"


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    attempts_in_window: int
    limit: int
    reason: str


class RateLimiter:
    def __init__(
        self,
        root: Path,
        limit: int,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if limit < 1:
            raise ValueError("rate limit must be at least 1 install per minute")
        self._path = root / _FILE
        self._limit = limit
        self._clock = clock

    @property
    def path(self) -> Path:
        return self._path

    def attempt(self) -> RateDecision:
        """Record one attempt and say whether it is within the limit."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._path.with_suffix(".lock")
        with open(lock_path, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                return self._attempt_locked()
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _attempt_locked(self) -> RateDecision:
        now = self._clock()
        try:
            stamps = self._read()
        except (OSError, ValueError, TypeError) as exc:
            return RateDecision(
                allowed=False,
                attempts_in_window=self._limit,
                limit=self._limit,
                reason=f"rate limit state is unreadable ({type(exc).__name__}); "
                f"inspect or delete {self._path}",
            )

        recent = [stamp for stamp in stamps if now - stamp < WINDOW]
        allowed = len(recent) < self._limit
        recent.append(now)  # every attempt counts, allowed or not
        self._write(recent)
        reason = (
            f"{len(recent)} install attempt(s) in the last 60 seconds"
            if allowed
            else f"rate limit of {self._limit} installs per minute exceeded"
        )
        return RateDecision(allowed, len(recent), self._limit, reason)

    def _read(self) -> list[datetime]:
        if not self._path.exists():
            return []
        data = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("attempts"), list):
            raise ValueError("unexpected structure")
        return [datetime.fromisoformat(item) for item in data["attempts"]]

    def _write(self, stamps: list[datetime]) -> None:
        payload = {"attempts": [stamp.isoformat() for stamp in stamps[-1000:]]}
        handle, temp_name = tempfile.mkstemp(dir=self._path.parent, prefix=".rl-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self._path)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
