"""Install rate limit (PRD 4.7): at most N install attempts in a rolling 60-second window.

State is one JSON file, shared by every caller in the state directory:

- `attempts`: one timestamp per counted attempt.
- `hook_allows`: per install key, one timestamp per package the install hook allowed. Each
  entry is a credit. A PATH shim attempt for the same key within the window consumes one
  credit instead of counting again (R-G-11). The shim still verifies the install.

Every hook attempt counts, including blocked ones, so an agent cannot reset the window by
retrying. A missing state file means no attempts yet. An unreadable or corrupt state file
blocks the attempt and is left in place for an operator to inspect. Deleting it resets the
window. Overwriting it does not happen automatically, because that would let a corrupted
file reset the limit.

Writes are serialised with flock and replaced atomically.

Requirements: R-4.7, R-G-11. Property: P-G-2. Layer 3. The clock is injected.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path

from slopseal.core.names import normalize_name
from slopseal.core.types import Ecosystem

WINDOW = timedelta(seconds=60)
_FILE = "ratelimit.json"
_ATTEMPTS = "attempts"
_CREDITS = "hook_allows"


class Layer(Enum):
    """Which caller is verifying the install. Only the layers decide how a call is counted."""

    HOOK = "hook"
    SHIM = "shim"
    OTHER = "other"


def install_key(ecosystem: Ecosystem, name: str, version: str) -> str:
    """The identity of one install, the same from the hook and from the shim (R-G-11)."""
    return f"{ecosystem.value}:{normalize_name(ecosystem, name)}=={version}"


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    attempts_in_window: int
    limit: int
    reason: str
    counted: bool = True


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

    def attempt(self, key: str | None = None, layer: Layer = Layer.OTHER) -> RateDecision:
        """Record one attempt and say whether it is within the limit.

        A SHIM attempt for a key with a live hook credit consumes that credit and is not
        counted. It is allowed, because the hook already counted it within the limit.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._path.with_suffix(".lock")
        with open(lock_path, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                return self._attempt_locked(key, layer)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def note_hook_allow(self, key: str) -> None:
        """Save one credit after the hook allowed an install. Raises OSError or ValueError."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._path.with_suffix(".lock")
        with open(lock_path, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                now = self._clock()
                stamps, credits = self._read()
                recent = [stamp for stamp in stamps if now - stamp < WINDOW]
                credits = _live(credits, now)
                credits.setdefault(key, []).append(now)
                self._write(recent, credits)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _attempt_locked(self, key: str | None, layer: Layer) -> RateDecision:
        now = self._clock()
        try:
            stamps, credits = self._read()
        except (OSError, ValueError, TypeError) as exc:
            return RateDecision(
                allowed=False,
                attempts_in_window=self._limit,
                limit=self._limit,
                reason=f"rate limit state is unreadable ({type(exc).__name__}); "
                f"inspect or delete {self._path}",
            )

        recent = [stamp for stamp in stamps if now - stamp < WINDOW]
        credits = _live(credits, now)
        if layer is Layer.SHIM and key is not None and credits.get(key):
            # The hook already counted this install. Consume one credit, count nothing.
            credits[key].pop(0)
            if not credits[key]:
                del credits[key]
            self._write(recent, credits)
            return RateDecision(
                allowed=True,
                attempts_in_window=len(recent),
                limit=self._limit,
                reason="counted once by the install hook for this install",
                counted=False,
            )

        allowed = len(recent) < self._limit
        recent.append(now)  # every counted attempt counts, allowed or not
        self._write(recent, credits)
        reason = (
            f"{len(recent)} install attempt(s) in the last 60 seconds"
            if allowed
            else f"rate limit of {self._limit} installs per minute exceeded"
        )
        return RateDecision(allowed, len(recent), self._limit, reason)

    def _read(self) -> tuple[list[datetime], dict[str, list[datetime]]]:
        if not self._path.exists():
            return [], {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get(_ATTEMPTS), list):
            raise ValueError("unexpected structure")
        stamps = [datetime.fromisoformat(item) for item in data[_ATTEMPTS]]
        raw_credits = data.get(_CREDITS, {})
        if not isinstance(raw_credits, dict):
            raise ValueError("unexpected credit structure")
        credits: dict[str, list[datetime]] = {}
        for key, items in raw_credits.items():
            if not isinstance(key, str) or not isinstance(items, list):
                raise ValueError("unexpected credit entry")
            credits[key] = [datetime.fromisoformat(item) for item in items]
        return stamps, credits

    def _write(self, stamps: list[datetime], credits: dict[str, list[datetime]]) -> None:
        payload = {
            _ATTEMPTS: [stamp.isoformat() for stamp in stamps[-1000:]],
            _CREDITS: {key: [item.isoformat() for item in items] for key, items in credits.items()},
        }
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


def _live(credits: dict[str, list[datetime]], now: datetime) -> dict[str, list[datetime]]:
    """Keep credits that are 0 to 60 seconds old. Drop the rest and keys left with none.

    A credit stamped after `now` (the clock moved back) is dropped too. Keeping it would let
    a shim skip a count for longer than the window.
    """
    kept: dict[str, list[datetime]] = {}
    for key, items in credits.items():
        alive = [item for item in items if timedelta(0) <= now - item < WINDOW]
        if alive:
            kept[key] = alive
    return kept
