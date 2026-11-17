"""Property tests for the install rate limit (R-4.7).

The oracle is a plain list scan over attempt times. It does not use the limiter's code.
Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.quarantine.rate_limit import WINDOW, RateLimiter
from slopseal.registry.source import OfflineSource
from slopseal.verdict import Context, InstallRequest, Intent, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
BASE = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now


WINDOW_US = int(WINDOW.total_seconds() * 1_000_000)


def oracle_allowed(offsets_us: list[int], limit: int) -> list[bool]:
    """Allowed iff fewer than `limit` earlier attempts (allowed or not) lie inside the window.

    Offsets are integer microseconds, the resolution of the timestamps the limiter sees, so the
    window boundary is compared exactly. Float offsets could round across the boundary.
    """
    decisions: list[bool] = []
    for i, offset in enumerate(offsets_us):
        prior = sum(1 for other in offsets_us[:i] if offset - other < WINDOW_US)
        decisions.append(prior < limit)
    return decisions


@given(
    limit=st.integers(min_value=1, max_value=5),
    gaps=st.lists(st.integers(min_value=0, max_value=45_000_000), min_size=1, max_size=20),
)
def test_r_4_7_allowed_iff_fewer_than_limit_attempts_in_the_window(
    limit: int, gaps: list[int]
) -> None:
    offsets: list[int] = []
    total = 0
    for gap in gaps:
        total += gap
        offsets.append(total)
    with tempfile.TemporaryDirectory() as tmp:
        clock = FakeClock(BASE)
        limiter = RateLimiter(Path(tmp), limit, clock=clock)
        actual: list[bool] = []
        for offset in offsets:
            clock.now = BASE + timedelta(microseconds=offset)
            actual.append(limiter.attempt().allowed)
    assert actual == oracle_allowed(offsets, limit)


@given(limit=st.integers(min_value=1, max_value=5), count=st.integers(min_value=1, max_value=12))
def test_r_4_7_denied_attempts_still_count_so_retrying_does_not_reset(
    limit: int, count: int
) -> None:
    """Hammering the limiter inside one window keeps it blocked until the window passes."""
    with tempfile.TemporaryDirectory() as tmp:
        clock = FakeClock(BASE)
        limiter = RateLimiter(Path(tmp), limit, clock=clock)
        decisions = [limiter.attempt().allowed for _ in range(count)]
        clock.now = BASE + WINDOW + timedelta(seconds=1)
        after = limiter.attempt().allowed
    assert decisions == [i < limit for i in range(count)]
    assert after is True


@given(limit=st.integers(min_value=1, max_value=5))
def test_r_4_7_attempts_spaced_beyond_the_window_are_all_allowed(limit: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        clock = FakeClock(BASE)
        limiter = RateLimiter(Path(tmp), limit, clock=clock)
        decisions = []
        for n in range(limit * 3):
            clock.now = BASE + WINDOW * (n + 1)
            decisions.append(limiter.attempt().allowed)
    assert all(decisions)


def test_missing_state_file_allows_the_first_attempt() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        assert RateLimiter(Path(tmp), 1, clock=FakeClock(BASE)).attempt().allowed is True


def test_corrupt_state_blocks_and_is_left_in_place() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "ratelimit.json").write_text("{not json", encoding="utf-8")
        limiter = RateLimiter(root, 10, clock=FakeClock(BASE))
        decision = limiter.attempt()
        assert decision.allowed is False
        assert "unreadable" in decision.reason
        assert (root / "ratelimit.json").read_text(encoding="utf-8") == "{not json"


def test_limit_below_one_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp, pytest.raises(ValueError, match="at least 1"):
        RateLimiter(Path(tmp), 0)


def _context(state: Path, limiter: RateLimiter) -> Context:
    from slopseal.audit.log import AuditLog
    from slopseal.audit.seal import load_or_create_key
    from slopseal.policy.loader import load_policy
    from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id

    counter = iter(range(1, 10_000))
    return Context(
        policy=load_policy(str(POLICY)),
        source=OfflineSource(load_snapshot(FIXTURES)),
        store=QuarantineStore(state),
        log=AuditLog(state / "audit.jsonl", load_or_create_key(state)),
        now=datetime(2026, 11, 18, tzinfo=UTC),
        new_id=lambda: new_quarantine_id(next(counter).to_bytes(13, "big")),
        limiter=limiter,
    )


def test_pipeline_blocks_over_the_limit_before_any_check_and_logs_it() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = FakeClock(BASE)
        context = _context(state, RateLimiter(state, 2, clock=clock))
        request = InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0")
        outcomes = [verify_install(request, context) for _ in range(3)]
        lines = (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert [o.outcome for o in outcomes] == [Outcome.ALLOW, Outcome.ALLOW, Outcome.BLOCK]
    assert outcomes[2].violation is not None
    assert outcomes[2].violation.check == "rate_limit"
    assert outcomes[2].checks_run == ()
    assert '"blocked_by": "rate_limit"' in lines[-1]


def test_rate_limit_block_cannot_be_bypassed_with_allow_unsafe() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = FakeClock(BASE)
        context = _context(state, RateLimiter(state, 1, clock=clock))
        verify_install(InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0"), context)
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0", bypass_reason="override"),
            context,
        )
    assert decision.outcome is Outcome.BLOCK
    assert decision.bypassed is False


def test_retry_of_a_quarantine_also_counts_against_the_limit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = FakeClock(BASE)
        context = _context(state, RateLimiter(state, 1, clock=clock))
        first = verify_install(
            InstallRequest(
                Ecosystem.PYPI, "csv-parser", "1.2.0", intent=Intent("parse", "csv.reader")
            ),
            context,
        )
        retry = verify_install(
            InstallRequest(
                Ecosystem.PYPI, "csv-parser", "1.2.0", quarantine_id=first.quarantine_id
            ),
            context,
        )
    assert first.outcome is Outcome.QUARANTINE
    assert retry.outcome is Outcome.BLOCK
    assert retry.violation is not None
    assert retry.violation.check == "rate_limit"
