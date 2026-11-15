"""Shared runtime setup: the CLI, the PATH shim, and the verify API build the same context here.

Environment (see .env.example):
  SLOPSEAL_OFFLINE_SNAPSHOT=1  use the checksummed offline snapshot and pin verdict time
                               to its as_of
  SLOPSEAL_SNAPSHOT_DIR        snapshot directory (default: src/slopseal/fixtures)
  SLOPSEAL_STATE_DIR           state directory (default: .slopseal)
  SLOPSEAL_POLICY_PATH         trust policy (default: .kiro/steering/dependency-trust.md)

The rate limit uses the wall clock even in offline mode. Pinning it would make a per-minute
limit permanent after the first N attempts. Verdicts keep the pinned clock, so they stay
deterministic.

Errors: PolicyError, SealKeyError, and SnapshotIntegrityError are raised to the caller, which
decides the exit code.

Requirements: R-1.4, R-P-2, R-4.7. Layer 4.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.policy.loader import load_policy
from slopseal.quarantine.rate_limit import RateLimiter
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id
from slopseal.registry.source import LiveSource, OfflineSource
from slopseal.verdict import Context

DEFAULT_STATE_DIR = ".slopseal"
DEFAULT_POLICY = ".kiro/steering/dependency-trust.md"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
ECOSYSTEMS = {eco.value: eco for eco in Ecosystem}


def env_flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def offline() -> bool:
    return env_flag("SLOPSEAL_OFFLINE_SNAPSHOT")


def state_dir() -> Path:
    return Path(os.environ.get("SLOPSEAL_STATE_DIR", DEFAULT_STATE_DIR))


def policy_path() -> Path:
    return Path(os.environ.get("SLOPSEAL_POLICY_PATH", DEFAULT_POLICY))


def snapshot_dir() -> Path:
    return Path(os.environ.get("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES)))


def now() -> datetime:
    """Verdict time: the snapshot's as_of in offline mode, otherwise the system clock."""
    if offline():
        return load_snapshot(snapshot_dir()).as_of
    return datetime.now(UTC)


def build_context(root: Path | None = None, *, rate_limited: bool = True) -> Context:
    """Load the policy, the seal key, and the source, and return a verdict context.

    Raises PolicyError, SealKeyError, or SnapshotIntegrityError. Each caller maps them to an
    exit code.
    """
    state = root if root is not None else state_dir()
    policy = load_policy(str(policy_path()))
    key = load_or_create_key(state)
    if offline():
        snapshot = load_snapshot(snapshot_dir())
        source: OfflineSource | LiveSource = OfflineSource(snapshot)
        clock = snapshot.as_of
    else:
        source = LiveSource()
        clock = datetime.now(UTC)
    limiter = RateLimiter(state, policy.max_installs_per_minute) if rate_limited else None
    return Context(
        policy=policy,
        source=source,
        store=QuarantineStore(state),
        log=AuditLog(state / "audit.jsonl", key),
        now=clock,
        new_id=lambda: new_quarantine_id(os.urandom(13)),
        limiter=limiter,
    )
