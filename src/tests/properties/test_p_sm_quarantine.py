"""Property tests for the quarantine state machine and exit-75 payload.

Requirements: R-Q-1..R-Q-7. Properties: P-SM-1..P-SM-5, P-FC-4.
Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import itertools
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.policy.loader import load_policy
from slopseal.quarantine.state_machine import QState, QuarantineStore, new_quarantine_id
from slopseal.registry.source import OfflineSource
from slopseal.verdict import Context, InstallRequest, Intent, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
AS_OF = datetime(2026, 11, 18, tzinfo=UTC)

# csv-parser exports parse and parse_file in 1.2.0. csv.reader and the rest are absent.
EXPORTED = ("parse", "parse_file")
ABSENT = ("csv.reader", "read", "DictReader", "foo")
apis = st.sampled_from([*EXPORTED, *ABSENT])


def make_context(state: Path, *, now: datetime = AS_OF, id_start: int = 1) -> Context:
    counter = itertools.count(id_start)
    return Context(
        policy=load_policy(str(POLICY)),
        source=OfflineSource(load_snapshot(FIXTURES)),
        store=QuarantineStore(state),
        log=AuditLog(state / "audit.jsonl", load_or_create_key(state)),
        now=now,
        new_id=lambda: new_quarantine_id(next(counter).to_bytes(13, "big")),
    )


def csv_request(api: str, quarantine_id: str | None = None) -> InstallRequest:
    return InstallRequest(
        ecosystem=Ecosystem.PYPI,
        package="csv-parser",
        version="1.2.0",
        intent=Intent(purpose="parse CSV", expected_api=api),
        quarantine_id=quarantine_id,
    )


def open_quarantine(context: Context) -> str:
    decision = verify_install(csv_request("csv.reader"), context)
    assert decision.outcome is Outcome.QUARANTINE
    assert decision.quarantine_id is not None
    return decision.quarantine_id


def _walk(node: Any):  # yields every dict in a nested structure
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


# ---- P-SM-1 bounded termination, P-SM-2 budget -------------------------------------------


@given(attempts=st.lists(apis, min_size=1, max_size=3))
def test_p_sm_1_every_sequence_terminates_in_a_defined_exit_code(attempts: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        context = make_context(Path(tmp))
        qid = open_quarantine(context)
        codes = []
        for api in attempts:
            decision = verify_install(csv_request(api, qid), context)
            codes.append(decision.exit_code)
        assert set(codes) <= {0, 1, 75}


@given(attempts=st.lists(apis, min_size=1, max_size=3))
def test_p_sm_2_after_one_retry_the_budget_is_spent(attempts: list[str]) -> None:
    """Once the single retry is used, the quarantine never offers another automated check."""
    with tempfile.TemporaryDirectory() as tmp:
        context = make_context(Path(tmp))
        qid = open_quarantine(context)
        seen_budget_one = 0
        for api in attempts:
            decision = verify_install(csv_request(api, qid), context)
            payload = decision.quarantine_payload
            if decision.outcome is Outcome.QUARANTINE and payload is not None:
                seen_budget_one += payload["retry_budget_remaining"] == 1
        assert seen_budget_one <= 1


@given(attempts=st.lists(apis, min_size=2, max_size=4))
def test_p_sm_2_escalated_quarantine_never_allows_and_stays_at_75(attempts: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        context = make_context(Path(tmp))
        qid = open_quarantine(context)
        # First retry with an absent API escalates the quarantine.
        verify_install(csv_request("csv.reader", qid), context)
        for api in attempts:
            decision = verify_install(csv_request(api, qid), context)
            assert decision.outcome is Outcome.QUARANTINE
            assert decision.exit_code == 75
            assert decision.quarantine_payload is not None
            assert decision.quarantine_payload["retry_budget_remaining"] == 0


# ---- P-SM-3 retry re-checks ---------------------------------------------------------------


@given(api=apis)
def test_p_sm_3_retry_result_follows_the_exports_not_the_first_attempt(api: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        context = make_context(Path(tmp))
        qid = open_quarantine(context)
        decision = verify_install(csv_request(api, qid), context)
        if api in EXPORTED:
            assert decision.outcome is Outcome.ALLOW
        else:
            assert decision.outcome is Outcome.QUARANTINE
            assert decision.quarantine_payload is not None
            assert decision.quarantine_payload["retry_budget_remaining"] == 0


# ---- P-SM-4 payload shape, P-SM-5 no confidence --------------------------------------------


PAYLOAD_FIELDS = {
    "verdict",
    "quarantine_id",
    "package",
    "declared_intent",
    "declared_api",
    "found_apis",
    "mismatch_type",
    "missing_evidence",
    "suggested_alternatives",
    "retry_budget_remaining",
    "escalation_command",
}


def test_p_sm_4_payload_has_exactly_the_documented_fields() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(csv_request("csv.reader"), make_context(Path(tmp)))
    assert decision.quarantine_payload is not None
    assert set(decision.quarantine_payload) == PAYLOAD_FIELDS


def test_p_sm_5_payload_never_carries_a_confidence_value() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(csv_request("csv.reader"), make_context(Path(tmp)))
    payload = json.loads(json.dumps(decision.quarantine_payload))
    assert all("confidence" not in node for node in _walk(payload))


# ---- Expiry, corruption, mismatch, abandon, approve ----------------------------------------


def test_expired_window_escalates_and_writes_the_artifact() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        qid = open_quarantine(make_context(state))
        late = make_context(state, now=AS_OF + timedelta(seconds=10_000))
        decision = verify_install(csv_request("parse", qid), late)
        assert decision.outcome is Outcome.QUARANTINE
        assert decision.exit_code == 75
        assert (state / "pending_approval" / f"{qid}.json").exists()


def test_corrupt_state_file_is_never_allowed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        qid = open_quarantine(make_context(state))
        (state / "quarantine" / f"{qid}.json").write_text("{not json", encoding="utf-8")
        decision = verify_install(csv_request("csv.reader", qid), make_context(state, id_start=500))
        assert decision.outcome is Outcome.QUARANTINE
        assert decision.quarantine_id != qid


def test_retry_for_a_different_package_starts_a_fresh_check() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = make_context(state)
        qid = open_quarantine(context)
        before = (state / "quarantine" / f"{qid}.json").read_text(encoding="utf-8")
        other = InstallRequest(
            ecosystem=Ecosystem.PYPI,
            package="urlnorm-py",
            version="0.9.0",
            intent=Intent(purpose="normalize", expected_api="normalize"),
            quarantine_id=qid,
        )
        decision = verify_install(other, context)
        assert decision.outcome is Outcome.ALLOW
        assert (state / "quarantine" / f"{qid}.json").read_text(encoding="utf-8") == before


def test_abandoned_quarantine_blocks_a_later_retry() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = make_context(state)
        qid = open_quarantine(context)
        stored = context.store.load(qid)
        assert stored is not None
        context.store.save(
            type(stored)(**{**stored.__dict__, "state": QState.ABANDONED, "reason": "abandoned"})
        )
        decision = verify_install(csv_request("parse", qid), context)
        assert decision.outcome is Outcome.BLOCK


def test_approved_quarantine_allows_with_the_recorded_reason() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = make_context(state)
        qid = open_quarantine(context)
        verify_install(csv_request("csv.reader", qid), context)  # escalates
        stored = context.store.load(qid)
        assert stored is not None
        assert stored.state == QState.ESCALATED
        context.store.save(
            type(stored)(
                **{**stored.__dict__, "state": QState.APPROVED, "reason": "approved: reviewed"}
            )
        )
        decision = verify_install(csv_request("csv.reader", qid), context)
        assert decision.outcome is Outcome.ALLOW
        assert decision.bypassed is True
        assert "reviewed" in decision.reason
