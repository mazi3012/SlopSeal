"""Shared runtime setup: the CLI, the PATH shim, and the verify API build the same context here.

Environment (see .env.example):
  SLOPSEAL_OFFLINE_SNAPSHOT    unset or 1: checksummed offline snapshot, clock pinned to its as_of.
                               0: live registries (PyPI, npm, OSV). Same as the CLI --live flag.
  SLOPSEAL_SNAPSHOT_DIR        snapshot directory (default: src/slopseal/fixtures)
  SLOPSEAL_STATE_DIR           state directory (default: .slopseal)
  SLOPSEAL_POLICY_PATH         trust policy (default: .kiro/steering/dependency-trust.md or bundled)

Policy loading order (R-1.4):
  1. SLOPSEAL_POLICY_PATH environment variable (if set).
  2. .kiro/steering/dependency-trust.md in the current workspace (if it exists).
  3. The bundled defaults/dependency-trust.md (Zero-config fallback).

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
from slopseal.policy.loader import load_policy_or_bundled_default
from slopseal.quarantine.rate_limit import RateLimiter
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id
from slopseal.registry.live import LiveSource
from slopseal.registry.source import OfflineSource
from slopseal.verdict import Context

DEFAULT_STATE_DIR = ".slopseal"
DEFAULT_POLICY = ".kiro/steering/dependency-trust.md"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
ECOSYSTEMS = {eco.value: eco for eco in Ecosystem}


def env_flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def offline() -> bool:
    """Offline unless SLOPSEAL_OFFLINE_SNAPSHOT is exactly "0". Unset means offline, so no
    package name leaves the machine by default (THREAT_MODEL section 5)."""
    return os.environ.get("SLOPSEAL_OFFLINE_SNAPSHOT", "1") != "0"


def state_dir() -> Path:
    return Path(os.environ.get("SLOPSEAL_STATE_DIR", DEFAULT_STATE_DIR))


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
    policy = load_policy_or_bundled_default()
    key = load_or_create_key(state)
    snapshot = load_snapshot(snapshot_dir())
    source: OfflineSource | LiveSource
    if offline():
        source = OfflineSource(snapshot)
        clock = snapshot.as_of
    else:
        # The top-N list comes from the checksummed snapshot. Live mode has no ranking source.
        top = {eco: snapshot.top_n(eco) for eco in (Ecosystem.PYPI, Ecosystem.NPM)}
        # The contract cache lives under the state directory (R-C-6).
        source = LiveSource(top_n=top, cache_root=state, compiled_wheels=policy.compiled_wheels)
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
