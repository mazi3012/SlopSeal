"""Property tests for verify_install: the fail-closed invariant and verdict order.

Requirements: R-V-1..R-V-4, R-1.5, R-P-1, R-Q-2. Properties: P-FC-1..P-FC-6, P-SN-2, P-AU-1.
Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import itertools
import tempfile
from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.policy.loader import load_policy
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id
from slopseal.registry.live import LiveSource
from slopseal.registry.source import OfflineSource
from slopseal.verdict import Context, InstallRequest, Intent, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
from datetime import UTC, datetime  # noqa: E402

AS_OF = datetime(2026, 11, 18, tzinfo=UTC)
KNOWN_PYPI_CLEAN = {"tinyfmt-kit": "0.4.0", "csv-parser": "1.2.0", "colorkit": "2.0.1"}
BLOCKED_PYPI = {"reqeusts": "1.0.0", "nunpy": "1.0.0", "flsk": "1.0.0", "pandsa": "1.0.0"}
letters = st.characters(whitelist_categories=("Ll",), min_codepoint=97, max_codepoint=122)


def context_for(state: Path, *, source=None, log_path: Path | None = None) -> Context:
    counter = itertools.count(1)
    key = load_or_create_key(state)
    return Context(
        policy=load_policy(str(POLICY)),
        source=source or OfflineSource(load_snapshot(FIXTURES)),
        store=QuarantineStore(state),
        log=AuditLog(log_path or state / "audit.jsonl", key),
        now=AS_OF,
        new_id=lambda: new_quarantine_id(next(counter).to_bytes(13, "big")),
    )


# ---- P-FC-2: unknown registry state never allows ------------------------------------------


@given(name=st.text(alphabet=letters, min_size=3, max_size=20))
def test_p_fc_2_unknown_registry_state_never_allows(name: str) -> None:
    snapshot = load_snapshot(FIXTURES)
    known = {*snapshot.known_names(Ecosystem.PYPI), *snapshot.absent_names(Ecosystem.PYPI)}
    assume(name not in known)
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, name, "1.0.0"), context_for(Path(tmp))
        )
    assert decision.outcome is Outcome.BLOCK
    assert decision.exit_code == 1


# ---- P-FC-3: unknown exports block, never quarantine ----------------------------------------


@given(version=st.text(alphabet=letters, min_size=1, max_size=8))
def test_p_fc_3_unknown_version_blocks_not_quarantines(version: str) -> None:
    assume(version not in {"1.2.0"})
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(
                Ecosystem.PYPI,
                "csv-parser",
                version,
                intent=Intent("parse CSV", expected_api="csv.reader"),
            ),
            context_for(Path(tmp)),
        )
    assert decision.outcome is Outcome.BLOCK


# ---- P-FC-4 and P-FC-6: quarantine only from intent, blocks dominate -------------------------


@given(
    package=st.sampled_from(sorted(BLOCKED_PYPI)), api=st.sampled_from(["parse", "csv.reader", "x"])
)
def test_p_fc_6_hard_block_dominates_any_intent(package: str, api: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(
                Ecosystem.PYPI,
                package,
                BLOCKED_PYPI[package],
                intent=Intent("anything", expected_api=api),
            ),
            context_for(Path(tmp)),
        )
    assert decision.outcome is Outcome.BLOCK


@given(package=st.sampled_from(sorted(BLOCKED_PYPI)))
def test_p_fc_4_blocked_package_is_never_quarantined(package: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, package, BLOCKED_PYPI[package]),
            context_for(Path(tmp)),
        )
    assert decision.outcome is not Outcome.QUARANTINE


@given(api=st.sampled_from(["parse", "parse_file", "csv.reader", "missing.thing"]))
def test_p_fc_4_quarantine_only_when_declared_api_is_absent(api: str) -> None:
    """For a clean package, the verdict is QUARANTINE exactly when the declared API is absent."""
    exports = {"parse", "parse_file"}
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(
                Ecosystem.PYPI,
                "csv-parser",
                "1.2.0",
                intent=Intent("parse CSV", expected_api=api),
            ),
            context_for(Path(tmp)),
        )
    expected = Outcome.ALLOW if api in exports else Outcome.QUARANTINE
    assert decision.outcome is expected


# ---- P-FC-1 and internal errors -----------------------------------------------------------


def _no_network(url: str, body: bytes | None) -> bytes | None:
    raise OSError("network is disabled in tests")


def test_p_fc_1_live_source_blocks_every_package() -> None:
    # Every registry call fails, so every answer is unknown. The test never reaches the network.
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, "csv-parser", "1.2.0"),
            context_for(Path(tmp), source=LiveSource(fetch=_no_network)),
        )
    assert decision.outcome is Outcome.BLOCK


def test_internal_error_becomes_block_and_does_not_raise() -> None:
    class Broken(OfflineSource):
        def registry_result(self, eco, name):  # type: ignore[override]
            raise RuntimeError("simulated defect")

    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, "csv-parser", "1.2.0"),
            context_for(Path(tmp), source=Broken(load_snapshot(FIXTURES))),
        )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "internal_error"


def test_allow_is_refused_when_the_audit_line_cannot_be_written() -> None:
    """An ALLOW that cannot be logged is not returned (fail closed)."""
    with tempfile.TemporaryDirectory() as tmp:
        blocked_path = Path(tmp) / "audit-is-a-directory"
        blocked_path.mkdir()
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0"),
            context_for(Path(tmp), log_path=blocked_path),
        )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "internal_error"


def test_allow_unsafe_without_a_reason_is_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, "reqeusts", "1.0.0", bypass_reason="   "),
            context_for(Path(tmp)),
        )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "bypass"


def test_allow_unsafe_with_a_reason_is_allowed_and_recorded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        decision = verify_install(
            InstallRequest(Ecosystem.PYPI, "reqeusts", "1.0.0", bypass_reason="reviewed"),
            context_for(state),
        )
        line = (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1]
    assert decision.outcome is Outcome.ALLOW
    assert decision.bypassed is True
    assert '"bypass"' in line
    assert "reviewed" in line


# ---- P-SN-2 determinism and P-AU-1 one line per verdict -----------------------------------


@given(package=st.sampled_from(sorted(KNOWN_PYPI_CLEAN) + sorted(BLOCKED_PYPI)))
def test_p_sn_2_same_inputs_give_the_same_decision(package: str) -> None:
    version = {**KNOWN_PYPI_CLEAN, **BLOCKED_PYPI}[package]
    request = InstallRequest(Ecosystem.PYPI, package, version)
    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        one = verify_install(request, context_for(Path(first)))
        two = verify_install(request, context_for(Path(second)))
    assert (one.outcome, one.reason, one.checks_run) == (two.outcome, two.reason, two.checks_run)


@given(count=st.integers(min_value=1, max_value=4))
def test_p_au_1_one_audit_line_per_verdict(count: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = context_for(state)
        for _ in range(count):
            verify_install(InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0"), context)
        report = context.log.verify()
    assert report.ok
    assert report.lines == count + 1  # plus the genesis line


@pytest.mark.parametrize("name", ["tinyfmt-kit", "colorkit"])
def test_clean_packages_are_allowed_without_intent(name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        decision = verify_install(
            InstallRequest(
                Ecosystem.PYPI if name == "tinyfmt-kit" else Ecosystem.NPM,
                name,
                KNOWN_PYPI_CLEAN.get(name, "2.0.1"),
            ),
            context_for(Path(tmp)),
        )
    assert decision.outcome is Outcome.ALLOW
