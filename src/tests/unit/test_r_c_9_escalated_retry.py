"""R-C-9: a retry against an escalated quarantine with an unknown contract blocks.

It never returns exit 75 with mismatch_type api_absent. Requirements: R-C-9, R-Q-6, R-Q-2.
Property: P-SM-2 still holds when exports are known.
"""

from __future__ import annotations

import itertools
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.policy.loader import load_policy
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id
from slopseal.registry.source import OfflineSource
from slopseal.verdict import Context, InstallRequest, Intent, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
AS_OF = datetime(2026, 11, 18, tzinfo=UTC)


class SwitchableSource(OfflineSource):
    """Offline source whose exports can be made unknown for the escalated retry only."""

    def __init__(self, snapshot) -> None:  # type: ignore[no-untyped-def]
        super().__init__(snapshot)
        self.unknown = False

    def exports(self, eco: Ecosystem, name: str, version: str) -> tuple[str, ...] | None:
        if self.unknown:
            return None
        return super().exports(eco, name, version)


def _context(state: Path, source: SwitchableSource) -> Context:
    counter = itertools.count(1)
    return Context(
        policy=load_policy(str(POLICY)),
        source=source,
        store=QuarantineStore(state),
        log=AuditLog(state / "audit.jsonl", load_or_create_key(state)),
        now=AS_OF,
        new_id=lambda: new_quarantine_id(next(counter).to_bytes(13, "big")),
    )


def _request(api: str, quarantine_id: str | None = None) -> InstallRequest:
    return InstallRequest(
        ecosystem=Ecosystem.PYPI,
        package="csv-parser",
        version="1.2.0",
        intent=Intent(purpose="parse CSV", expected_api=api),
        quarantine_id=quarantine_id,
    )


def _escalate(state: Path, source: SwitchableSource) -> str:
    """Open and escalate a quarantine: first call quarantines, the retry escalates."""
    context = _context(state, source)
    first = verify_install(_request("csv.reader"), context)
    assert first.outcome is Outcome.QUARANTINE
    qid = first.quarantine_id
    assert qid is not None
    second = verify_install(_request("csv.reader", qid), context)
    assert second.outcome is Outcome.QUARANTINE
    assert second.exit_code == 75
    return qid


def test_r_c_9_unknown_contract_on_escalated_retry_blocks_with_exit_1() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        source = SwitchableSource(load_snapshot(FIXTURES))
        qid = _escalate(state, source)
        source.unknown = True
        decision = verify_install(_request("csv.reader", qid), _context(state, source))
        assert decision.outcome is Outcome.BLOCK
        assert decision.exit_code == 1
        assert decision.violation is not None
        assert decision.violation.check == "api_surface"
        assert decision.quarantine_payload is None  # no api_absent payload for an unknown contract


def test_r_c_9_known_exports_on_escalated_retry_is_unchanged() -> None:
    """Control: with exports known, the escalated retry still returns exit 75 (P-SM-2)."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        source = SwitchableSource(load_snapshot(FIXTURES))
        qid = _escalate(state, source)
        decision = verify_install(_request("csv.reader", qid), _context(state, source))
        assert decision.outcome is Outcome.QUARANTINE
        assert decision.exit_code == 75
        assert decision.quarantine_payload is not None
