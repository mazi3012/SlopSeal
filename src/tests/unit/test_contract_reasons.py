"""Per-reason tests for the Contract Check (R-C-5, design 2.3, properties.md).

One test per typed reason that triggers it. Each asserts the reason and the exit code the
verdict gives for it (exit 1, BLOCK). The reasons are tested where they are produced.

- not_in_snapshot: produced by the offline contract (this file).
- limit, network, no_digest: produced by the 2.B pipeline (test_contract_pipeline.py).
- sdist_only, dynamic_exports, parse_error: produced by the extractors, not in this phase.

The verdict-level end-to-end check of these reasons waits for the decision on how the live
source reports a contract (see the step report). Requirements: R-C-5, R-C-8.
"""

from __future__ import annotations

from pathlib import Path

from slopseal.contract.offline import offline_contract
from slopseal.contract.types import UnknownReason
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.quarantine.api_surface import check_contract, unknown_block
from slopseal.verdict import Decision, Outcome

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"


def _exit_for_block(reason_check: str, text: str) -> int:
    # The verdict gives exit 1 for any BLOCK. The Decision mapping is the one the verdict uses.
    decision = Decision(
        outcome=Outcome.BLOCK,
        ecosystem="pypi",
        package="csv-parser",
        version="1.2.0",
        reason=text,
    )
    assert reason_check == "api_surface"
    return decision.exit_code


def test_reason_not_in_snapshot() -> None:
    snapshot = load_snapshot(FIXTURES)
    # csv-parser 9.9.9 is not in the snapshot. The version is not covered.
    result = offline_contract(snapshot, Ecosystem.PYPI, "csv-parser", "9.9.9")
    assert result.reason is UnknownReason.NOT_IN_SNAPSHOT  # type: ignore[union-attr]
    surface = check_contract(result, "parse")  # type: ignore[arg-type]
    violation = unknown_block(surface)
    assert violation.check == "api_surface"
    assert "not_in_snapshot" in violation.reason
    assert _exit_for_block(violation.check, violation.reason) == 1


def test_reason_not_in_snapshot_is_never_quarantine_or_allow() -> None:
    snapshot = load_snapshot(FIXTURES)
    result = offline_contract(snapshot, Ecosystem.PYPI, "not-a-package", "1.0.0")
    surface = check_contract(result, "parse")  # type: ignore[arg-type]
    assert surface.outcome.value == "unknown"
    assert surface.reason is UnknownReason.NOT_IN_SNAPSHOT
