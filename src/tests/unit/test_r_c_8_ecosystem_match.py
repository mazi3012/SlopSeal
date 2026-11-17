"""R-C-8: LiveSource.contract() matches every Ecosystem value exhaustively, one test per value.

PyPI and npm are extracted. Their metadata request fails here, so the answer is network and no
artifact is requested. CARGO, RUBYGEMS, and GO give parse_error with no request at all. No
failure reason is added (the seven-reason rule).

Requirements: R-C-8. Layer 1 (adapter).
"""

from __future__ import annotations

from slopseal.contract.types import ContractUnknown, UnknownReason
from slopseal.core.types import Ecosystem
from slopseal.registry.live import LiveSource


def _recording_source() -> tuple[LiveSource, list[str], list[str]]:
    requests: list[str] = []
    artifacts: list[str] = []

    def fetch(url: str, body: bytes | None) -> bytes | None:
        requests.append(url)
        raise OSError("no network in this test")

    def artifact_fetch(url: str, eco: Ecosystem) -> ContractUnknown:
        artifacts.append(url)
        return ContractUnknown(UnknownReason.NETWORK, "not reached")

    return LiveSource(fetch=fetch, artifact_fetch=artifact_fetch), requests, artifacts


def test_r_c_8_pypi_is_extracted_and_a_failed_metadata_request_is_network() -> None:
    live, requests, artifacts = _recording_source()
    result = live.contract(Ecosystem.PYPI, "csv-parser", "1.2.0")
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.NETWORK
    assert requests, "PyPI reads the registry metadata"
    assert artifacts == []


def test_r_c_8_npm_is_extracted_and_a_failed_metadata_request_is_network() -> None:
    live, requests, artifacts = _recording_source()
    result = live.contract(Ecosystem.NPM, "semver", "7.6.3")
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.NETWORK
    assert requests, "npm reads the packument"
    assert artifacts == []


def test_r_c_8_cargo_is_parse_error_with_no_request() -> None:
    eco = Ecosystem.CARGO
    live, requests, artifacts = _recording_source()
    result = live.contract(eco, "serde", "1.0.0")
    assert result == ContractUnknown(
        UnknownReason.PARSE_ERROR, "no contract source for this ecosystem"
    )
    assert requests == []
    assert artifacts == []


def test_r_c_8_rubygems_is_parse_error_with_no_request() -> None:
    eco = Ecosystem.RUBYGEMS
    live, requests, artifacts = _recording_source()
    result = live.contract(eco, "rails", "7.1.0")
    assert result == ContractUnknown(
        UnknownReason.PARSE_ERROR, "no contract source for this ecosystem"
    )
    assert requests == []
    assert artifacts == []


def test_r_c_8_go_is_parse_error_with_no_request() -> None:
    eco = Ecosystem.GO
    live, requests, artifacts = _recording_source()
    result = live.contract(eco, "golang.org/x/net", "v0.1.0")
    assert result == ContractUnknown(
        UnknownReason.PARSE_ERROR, "no contract source for this ecosystem"
    )
    assert requests == []
    assert artifacts == []


def test_r_c_8_every_ecosystem_value_has_a_test() -> None:
    """Guards the list above: a new Ecosystem value must get its own test."""
    covered = {Ecosystem.PYPI, Ecosystem.NPM, Ecosystem.CARGO, Ecosystem.RUBYGEMS, Ecosystem.GO}
    assert covered == set(Ecosystem)
