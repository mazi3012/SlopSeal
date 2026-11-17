"""Request binding and replay (D2 section 8.4): AC-26 to AC-29.

The clock is injected, so every freshness case is exact. Nothing here calls the verdict path: the
test counts quota itself, the same way the caller would.

Requirements: R-RB-1 (identical replay is cached, altered replay is refused), R-RB-2 (stale requests
are refused). Covers AC-26 to AC-29.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from slopseal.core.types import Ecosystem
from slopseal.requests.replay import CanonicalRequest, Decision, ReplayStore

T0 = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _request(
    timestamp: datetime = T0, holder: str = "tok-a", version: str = "1.2.0"
) -> CanonicalRequest:
    return CanonicalRequest(
        ecosystem=Ecosystem.PYPI,
        name="csv-parser",
        version=version,
        timestamp=timestamp.isoformat(),
        token_id=holder,
    )


@pytest.fixture
def clock() -> Clock:
    return Clock(T0)


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> ReplayStore:
    return ReplayStore(tmp_path / "state", clock=clock)


def _evaluate_and_count(
    store: ReplayStore, request_id: str, request: CanonicalRequest, counter: list[str]
) -> str:
    """What a caller does: admit, then evaluate and count only for a new request."""
    admission = store.admit(request_id, request)
    if admission.decision is Decision.EVALUATE:
        counter.append(request_id)  # the quota count
        verdict_id = "vd-" + request_id
        store.record(request_id, request, verdict_id)
        return verdict_id
    if admission.decision is Decision.REPLAY_CACHED:
        assert admission.verdict_id is not None
        return admission.verdict_id
    raise AssertionError("refused: " + admission.decision.value)


# AC-26 -------------------------------------------------------------------------------------


def test_ac26_identical_replay_returns_the_cached_verdict_and_counts_once(
    store: ReplayStore,
) -> None:
    counted: list[str] = []
    request = _request()
    first = _evaluate_and_count(store, "req-1", request, counted)
    again = _evaluate_and_count(store, "req-1", request, counted)
    assert again == first  # the same verdict id
    assert counted == ["req-1"]  # quota counted once


# AC-27 -------------------------------------------------------------------------------------


def test_ac27_altered_replay_under_the_same_id_and_token_is_refused(store: ReplayStore) -> None:
    counted: list[str] = []
    _evaluate_and_count(store, "req-1", _request(version="1.2.0"), counted)
    altered = store.admit("req-1", _request(version="9.9.9"))
    assert altered.decision is Decision.REPLAY_CONFLICT
    assert altered.verdict_id is None
    assert counted == ["req-1"]


@pytest.mark.parametrize(
    "field_change",
    [
        {"purpose": "a different reason"},
        {"expected_api": "other_symbol"},
        {"quarantine_id": "qs_other"},
        {"name": "csv-parser-extra"},
        {"ecosystem": Ecosystem.NPM},
    ],
)
def test_ac27_every_security_relevant_field_is_bound(
    store: ReplayStore, field_change: dict[str, object]
) -> None:
    base = replace(_request(), purpose="reason", expected_api="symbol", quarantine_id=None)
    store.record("req-1", base, "vd-1")
    altered = replace(base, **field_change)  # type: ignore[arg-type]
    assert store.admit("req-1", altered).decision is Decision.REPLAY_CONFLICT


def test_name_normalisation_does_not_create_a_false_conflict(store: ReplayStore) -> None:
    """Two spellings of one PyPI name are the same request, so the hash must match."""
    store.record("req-1", _request(), "vd-1")
    spelled = replace(_request(), name="CSV_Parser")
    assert store.admit("req-1", spelled).decision is Decision.REPLAY_CACHED


# AC-28 -------------------------------------------------------------------------------------


def test_ac28_same_id_under_a_different_token_is_denied(store: ReplayStore) -> None:
    counted: list[str] = []
    _evaluate_and_count(store, "req-1", _request(holder="tok-a"), counted)
    other = store.admit("req-1", _request(holder="tok-b"))
    assert other.decision is Decision.REPLAY_DENIED
    assert other.verdict_id is None
    assert counted == ["req-1"]


# AC-29 -------------------------------------------------------------------------------------


def test_ac29_a_request_older_than_the_window_is_stale(store: ReplayStore) -> None:
    old = T0 - timedelta(minutes=10, seconds=1)
    assert store.admit("req-old", _request(timestamp=old)).decision is Decision.REQUEST_STALE


def test_ac29_a_request_more_than_two_minutes_in_the_future_is_stale(store: ReplayStore) -> None:
    ahead = T0 + timedelta(minutes=2, seconds=1)
    assert store.admit("req-ahead", _request(timestamp=ahead)).decision is Decision.REQUEST_STALE


def test_ac29_a_request_at_the_window_edge_is_fresh(store: ReplayStore) -> None:
    edge = T0 - timedelta(minutes=10)
    assert store.admit("req-edge", _request(timestamp=edge)).decision is Decision.EVALUATE


def test_ac29_timestamp_without_offset_is_stale(store: ReplayStore) -> None:
    bad = replace(_request(), timestamp="2026-11-17T12:00:00")
    assert store.admit("req-naive", bad).decision is Decision.REQUEST_STALE


def test_ac29_stale_requests_are_not_recorded_or_counted(
    store: ReplayStore, tmp_path: Path
) -> None:
    store.admit("req-old", _request(timestamp=T0 - timedelta(hours=1)))
    assert not (tmp_path / "state" / "replay.json").exists()


# Restart and record integrity -------------------------------------------------------------


def test_the_replay_record_survives_a_restart(tmp_path: Path, clock: Clock) -> None:
    first = ReplayStore(tmp_path / "state", clock=clock)
    counted: list[str] = []
    _evaluate_and_count(first, "req-1", _request(), counted)
    restarted = ReplayStore(tmp_path / "state", clock=clock)
    assert restarted.admit("req-1", _request()).decision is Decision.REPLAY_CACHED
    assert counted == ["req-1"]


def test_an_id_cannot_be_recorded_twice(store: ReplayStore) -> None:
    store.record("req-1", _request(), "vd-1")
    with pytest.raises(ValueError, match="already recorded"):
        store.record("req-1", _request(), "vd-2")


def test_the_record_is_pruned_after_the_window(store: ReplayStore, clock: Clock) -> None:
    store.record("req-1", _request(), "vd-1")
    clock.now = T0 + timedelta(minutes=13)
    fresh = _request(timestamp=clock.now)
    assert store.admit("req-1", fresh).decision is Decision.EVALUATE
