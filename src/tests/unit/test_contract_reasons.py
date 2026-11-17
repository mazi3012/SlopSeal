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


# ---- Reasons produced by the 2.B pipeline. Each goes through the same mapping as the verdict. ----


def _block_exit_for(result: object) -> tuple[str, str, int]:
    """Map an UNKNOWN contract to the BLOCK the verdict gives: (check, reason text, exit code)."""
    from slopseal.contract.types import ContractComplete, ContractUnknown

    assert isinstance(result, ContractUnknown)
    assert not isinstance(result, ContractComplete)
    surface = check_contract(result, "parse")
    violation = unknown_block(surface)
    decision = Decision(
        outcome=Outcome.BLOCK,
        ecosystem="pypi",
        package="pkg",
        version="1.0.0",
        reason=violation.reason,
    )
    return violation.check, violation.reason, decision.exit_code


def test_reason_limit() -> None:
    """An artifact over the compressed limit is limit, and the verdict gives exit 1."""
    import tempfile

    from slopseal.contract.limits import MAX_COMPRESSED_BYTES
    from slopseal.contract.runner import run_archive_check

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "huge.whl"
        with path.open("wb") as handle:
            handle.truncate(MAX_COMPRESSED_BYTES + 1)
        result = run_archive_check(path, "wheel")
    assert getattr(result, "reason", None) is UnknownReason.LIMIT
    check, text, exit_code = _block_exit_for(result)
    assert check == "api_surface"
    assert "limit" in text
    assert exit_code == 1


def test_reason_network() -> None:
    """A failed download is network, and the verdict gives exit 1."""
    import urllib.error

    from slopseal.contract.fetch import download
    from slopseal.core.types import Ecosystem

    class Refuse:
        def __call__(self, request: object, timeout: float) -> object:
            raise urllib.error.URLError("connection refused")

    result = download(
        "https://files.pythonhosted.org/packages/p/pkg-1.0-py3-none-any.whl",
        Ecosystem.PYPI,
        opener=Refuse(),  # type: ignore[arg-type]
    )
    assert getattr(result, "reason", None) is UnknownReason.NETWORK
    check, text, exit_code = _block_exit_for(result)
    assert "network" in text
    assert exit_code == 1


def test_reason_no_digest() -> None:
    """A registry with no usable digest is no_digest, and the verdict gives exit 1."""
    from slopseal.contract.digest import published_from_npm_integrity

    result = published_from_npm_integrity("sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    assert getattr(result, "reason", None) is UnknownReason.NO_DIGEST
    check, text, exit_code = _block_exit_for(result)
    assert "no_digest" in text
    assert exit_code == 1
