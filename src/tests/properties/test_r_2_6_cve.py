"""Property tests for check 2.6 (CVE lookup for the exact version).

Requirements: R-2.6, R-P-1. Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.advisory import Advisories, Advisory, AdvisoryUnknown, Severity
from slopseal.core.cve import DEFAULT_BLOCK_SEVERITIES, check_cve
from slopseal.core.types import Level

ids = st.sampled_from(["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1", "CVE-2026-0001", "MAL-2026-9"])
severities = st.sampled_from(list(Severity))
advisory = st.builds(Advisory, advisory_id=ids, severity=severities, summary=st.text(max_size=40))
advisory_lists = st.lists(advisory, max_size=6).map(tuple)


def oracle(items: tuple[Advisory, ...]) -> Level:
    non_malware = [a for a in items if not a.advisory_id.startswith("MAL-")]
    if any(a.severity is Severity.UNKNOWN for a in non_malware):
        return Level.BLOCK
    if any(a.severity in DEFAULT_BLOCK_SEVERITIES for a in non_malware):
        return Level.BLOCK
    return Level.PASS


@given(items=advisory_lists)
def test_r_2_6_blocks_iff_critical_or_high_or_unknown(items: tuple[Advisory, ...]) -> None:
    result = check_cve(Advisories(items))
    assert result.level is oracle(items)


@given(items=advisory_lists)
def test_r_2_6_result_is_pass_or_block_only(items: tuple[Advisory, ...]) -> None:
    assert check_cve(Advisories(items)).level in {Level.PASS, Level.BLOCK}


@given(items=advisory_lists, extra=advisory)
def test_r_2_6_adding_an_advisory_never_lowers_severity(
    items: tuple[Advisory, ...], extra: Advisory
) -> None:
    before = check_cve(Advisories(items)).level
    after = check_cve(Advisories((*items, extra))).level
    assert after >= before


@given(items=advisory_lists)
def test_r_2_6_result_does_not_depend_on_order(items: tuple[Advisory, ...]) -> None:
    forward = check_cve(Advisories(items))
    backward = check_cve(Advisories(tuple(reversed(items))))
    assert forward == backward


@given(severity=st.sampled_from([Severity.MEDIUM, Severity.LOW]))
def test_r_2_6_medium_and_low_do_not_block(severity: Severity) -> None:
    result = check_cve(Advisories((Advisory("GHSA-x", severity, "s"),)))
    assert result.level is Level.PASS


@given(reason=st.text(min_size=1, max_size=40))
def test_p_fc_2_unknown_advisory_source_blocks(reason: str) -> None:
    result = check_cve(AdvisoryUnknown(reason))
    assert result.level is Level.BLOCK


def test_no_advisories_passes() -> None:
    assert check_cve(Advisories(())).level is Level.PASS


def test_unknown_severity_blocks_even_when_others_are_low() -> None:
    items = (
        Advisory("GHSA-low", Severity.LOW, "s"),
        Advisory("GHSA-odd", Severity.UNKNOWN, "s"),
    )
    assert check_cve(Advisories(items)).level is Level.BLOCK


def test_malware_records_are_not_double_reported_here() -> None:
    items = (Advisory("MAL-2026-9", Severity.CRITICAL, "malicious"),)
    assert check_cve(Advisories(items)).level is Level.PASS
