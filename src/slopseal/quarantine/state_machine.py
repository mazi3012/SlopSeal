"""Quarantine state machine: one JSON file per quarantine id.

States and transitions (design.md section 9):

    (none) --intent check fails--> OPEN (budget 1)
    OPEN --retry passes--> ALLOWED                       terminal
    OPEN --retry fails--> ESCALATED (budget 0), artifact written
    OPEN --retry blocked--> BLOCKED                      terminal
    OPEN --abandon--> ABANDONED                          terminal
    OPEN --window passes--> ESCALATED (treated as expired)
    ESCALATED --human approves--> APPROVED               terminal
    ESCALATED --abandon--> ABANDONED                     terminal
    ESCALATED --any retry--> ESCALATED (exit 75, no new check; P-SM-2)

A missing, unreadable, or corrupt state file is never ALLOWED. It starts a new quarantine
(design section 9). A retry for a different ecosystem, package, or version does not count
against the budget. It also starts a new quarantine.

Writes are atomic (temp file then os.replace), so a reader never sees a partial file.

Requirements: R-Q-5, R-Q-6, R-Q-7. Properties: P-SM-1, P-SM-2, P-SM-3, P-SM-5. Layer 3.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from slopseal.core.types import Ecosystem
from slopseal.fsutil import ensure_private_dir

_ID_PATTERN = re.compile(r"^qs_[0-9a-f]{26}$")


class QState:
    OPEN = "open"
    ALLOWED = "allowed"
    ESCALATED = "escalated"
    BLOCKED = "blocked"
    ABANDONED = "abandoned"
    APPROVED = "approved"


TERMINAL = frozenset({QState.ALLOWED, QState.BLOCKED, QState.ABANDONED, QState.APPROVED})


@dataclass(frozen=True)
class QuarantineState:
    quarantine_id: str
    state: str
    ecosystem: str
    package: str
    version: str
    declared_api: str
    created_at: datetime
    expires_at: datetime
    retry_budget_remaining: int
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "quarantine_id": self.quarantine_id,
            "state": self.state,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "declared_api": self.declared_api,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "retry_budget_remaining": self.retry_budget_remaining,
            "reason": self.reason,
        }

    @staticmethod
    def from_json(data: dict[str, Any]) -> QuarantineState:
        return QuarantineState(
            quarantine_id=data["quarantine_id"],
            state=data["state"],
            ecosystem=data["ecosystem"],
            package=data["package"],
            version=data["version"],
            declared_api=data["declared_api"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            retry_budget_remaining=int(data["retry_budget_remaining"]),
            reason=data["reason"],
        )


def new_quarantine_id(entropy: bytes) -> str:
    """Build a `qs_` id from 13 bytes of entropy. Callers pass os.urandom(13) in production."""
    if len(entropy) != 13:
        raise ValueError("quarantine id needs exactly 13 bytes of entropy")
    return "qs_" + entropy.hex()


def is_valid_id(quarantine_id: str) -> bool:
    return bool(_ID_PATTERN.match(quarantine_id))


class QuarantineStore:
    """Persist quarantine states under `root/quarantine/<id>.json`."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._dir = root / "quarantine"
        self._approvals = root / "pending_approval"

    def artifact(self, quarantine_id: str) -> dict[str, Any] | None:
        if not is_valid_id(quarantine_id):
            return None
        try:
            data = json.loads(
                (self._approvals / f"{quarantine_id}.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def write_artifact(self, quarantine_id: str, artifact: dict[str, Any]) -> Path:
        """Write the pending-approval artifact atomically and return its path."""
        if not is_valid_id(quarantine_id):
            raise ValueError("malformed quarantine id")
        ensure_private_dir(self._approvals)
        target = self._approvals / f"{quarantine_id}.json"
        handle, temp_name = tempfile.mkstemp(dir=self._approvals, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(artifact, stream, sort_keys=True, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, target)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
        return target

    def _path(self, quarantine_id: str) -> Path:
        if not is_valid_id(quarantine_id):
            raise ValueError("malformed quarantine id")
        return self._dir / f"{quarantine_id}.json"

    def load(self, quarantine_id: str) -> QuarantineState | None:
        """Return the stored state, or None when it is missing, unreadable, or corrupt.

        None means "start a new quarantine". It never means "allowed".
        """
        if not is_valid_id(quarantine_id):
            return None
        try:
            data = json.loads(self._path(quarantine_id).read_text(encoding="utf-8"))
            state = QuarantineState.from_json(data)
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if state.quarantine_id != quarantine_id or state.state not in _KNOWN_STATES:
            return None
        return state

    def save(self, state: QuarantineState) -> None:
        ensure_private_dir(self._dir)
        target = self._path(state.quarantine_id)
        handle, temp_name = tempfile.mkstemp(dir=self._dir, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(state.to_json(), stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, target)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise

    def create(
        self,
        *,
        quarantine_id: str,
        ecosystem: Ecosystem,
        package: str,
        version: str,
        declared_api: str,
        now: datetime,
        max_seconds: int,
        retry_budget: int,
        reason: str,
    ) -> QuarantineState:
        state = QuarantineState(
            quarantine_id=quarantine_id,
            state=QState.OPEN,
            ecosystem=ecosystem.value,
            package=package,
            version=version,
            declared_api=declared_api,
            created_at=now,
            expires_at=now + timedelta(seconds=max_seconds),
            retry_budget_remaining=retry_budget,
            reason=reason,
        )
        self.save(state)
        return state


_KNOWN_STATES = frozenset(
    {
        QState.OPEN,
        QState.ALLOWED,
        QState.ESCALATED,
        QState.BLOCKED,
        QState.ABANDONED,
        QState.APPROVED,
    }
)


def effective_state(state: QuarantineState, now: datetime) -> str:
    """An OPEN quarantine whose window has passed counts as ESCALATED (P-SM-1)."""
    if state.state == QState.OPEN and now >= state.expires_at:
        return QState.ESCALATED
    return state.state


def matches(state: QuarantineState, ecosystem: Ecosystem, package: str, version: str) -> bool:
    return (
        state.ecosystem == ecosystem.value and state.package == package and state.version == version
    )


def transition(state: QuarantineState, new_state: str, *, reason: str) -> QuarantineState:
    return replace(state, state=new_state, reason=reason)
