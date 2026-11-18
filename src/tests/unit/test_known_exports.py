"""Reviewed known exports for an allowlisted compiled wheel (R-CW-2, ADR 0005).

The positive case uses the real reviewed policy file. The negative cases change a copy of it.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.contract.types import (
    ContractComplete,
    ContractResult,
    ContractUnknown,
    UnknownReason,
)
from slopseal.core.types import Ecosystem, Level
from slopseal.fixtures.loader import load_snapshot
from slopseal.policy.invariants import enforce_floors
from slopseal.policy.known_exports import reviewed_symbols
from slopseal.policy.loader import KnownExport, Policy, PolicyError, load_policy, parse_policy
from slopseal.quarantine.api_surface import (
    ApiSurface,
    ApiSurfaceResult,
    apply_reviewed_exports,
    unknown_block,
)
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id
from slopseal.registry import live
from slopseal.registry.live import OSV_URL, PYPI_BASE, LiveSource
from slopseal.verdict import Context, InstallRequest, Intent, Outcome, verify_install

REPO_ROOT = Path(__file__).resolve().parents[3]
REPO_POLICY = REPO_ROOT / ".kiro" / "steering" / "dependency-trust.md"
ED25519 = "ed25519.Ed25519PublicKey"
AS_OF = datetime(2026, 11, 18, tzinfo=UTC)
CRYPTOGRAPHY_LINUX_WHEEL = "cryptography-50.0.2-cp39-abi3-manylinux_2_28_x86_64.whl"
CRYPTOGRAPHY_LINUX_SHA = "f21e8a22c8605750c7af886bab299a363721264061b4ac0a30efb73cfd58efc5"
CRYPTOGRAPHY_MAC_WHEEL = "cryptography-50.0.2-cp39-abi3-macosx_11_0_arm64.whl"
CRYPTOGRAPHY_MAC_SHA = "0ec5f09541743261e66e291b4a0cbf0fb2997aeaab6d9e9c740b9dba1b58d1c2"
REVIEWED_POLICY: Policy = parse_policy(REPO_POLICY.read_text(encoding="utf-8"))


def _dynamic(api: str) -> ApiSurfaceResult:
    return ApiSurfaceResult(ApiSurface.UNKNOWN, api, (), UnknownReason.DYNAMIC_EXPORTS)


def test_r_cw_2_allowlisted_package_with_recorded_symbol_passes() -> None:
    reviewed = reviewed_symbols(REVIEWED_POLICY, "cryptography", "50.0.2")
    assert ED25519 in reviewed

    surface = apply_reviewed_exports(_dynamic(ED25519), reviewed)

    assert surface.outcome is ApiSurface.PRESENT


def test_r_cw_2_allowlisted_package_with_unrecorded_symbol_fails_closed() -> None:
    reviewed = reviewed_symbols(REVIEWED_POLICY, "cryptography", "50.0.2")

    surface = apply_reviewed_exports(_dynamic("x25519.X25519PublicKey"), reviewed)

    assert surface.outcome is ApiSurface.UNKNOWN
    assert unknown_block(surface).reason == (
        "exported symbols for this version are unknown (reason: dynamic_exports)"
    )


def test_r_cw_2_non_allowlisted_package_fails_closed() -> None:
    # A record for a package that is not on the allowlist in code must have no effect.
    rogue = dataclasses.replace(
        REVIEWED_POLICY.compiled_wheels[0],
        name="requests",
        known_exports=(
            KnownExport(
                package="requests",
                version="2.32.0",
                symbol="get",
                reviewer="owner",
                date="2026-11-17",
            ),
        ),
    )
    policy = dataclasses.replace(REVIEWED_POLICY, compiled_wheels=(rogue,))

    reviewed = reviewed_symbols(policy, "requests", "2.32.0")

    assert reviewed == frozenset()
    assert apply_reviewed_exports(_dynamic("get"), reviewed).outcome is ApiSurface.UNKNOWN
    assert enforce_floors(policy)  # the floors also refuse the policy itself


def test_r_cw_2_other_version_of_allowlisted_package_fails_closed() -> None:
    assert reviewed_symbols(REVIEWED_POLICY, "cryptography", "50.0.3") == frozenset()


def test_r_cw_2_other_unknown_reason_keeps_block_even_for_recorded_symbol() -> None:
    surface = ApiSurfaceResult(ApiSurface.UNKNOWN, ED25519, (), UnknownReason.PARSE_ERROR)

    result = apply_reviewed_exports(surface, frozenset({ED25519}))

    assert result.outcome is ApiSurface.UNKNOWN


def test_r_cw_2_loader_rejects_a_record_for_another_package() -> None:
    text = REPO_POLICY.read_text(encoding="utf-8")
    assert text.count('package = "cryptography"') == 1
    broken = text.replace('package = "cryptography"', 'package = "requests"')

    with pytest.raises(PolicyError, match="package must be cryptography"):
        parse_policy(broken)


# ---- end to end through verify_install (verdict.py wiring) ---------------------------------


class _ContractStubLiveSource(LiveSource):
    """A LiveSource whose contract is a fixed `dynamic_exports` UNKNOWN.

    The real artifact bytes cannot be served here, because the pinned digest belongs to the
    real wheel. Every other answer comes from LiveSource: the registry metadata, the compiled
    wheel pin and its digests, install scripts, and OSV. The verdict code under test is not
    stubbed.
    """

    def contract(self, eco: Ecosystem, name: str, version: str) -> ContractResult:
        return ContractUnknown(UnknownReason.DYNAMIC_EXPORTS, "stubbed compiled export set")


def _fake_registry() -> dict[str, bytes]:
    """Registry documents for cryptography 50.0.2 and requests 2.32.0, plus an empty OSV answer."""

    def document(value: dict[str, Any]) -> bytes:
        return json.dumps(value).encode("utf-8")

    crypto_source = {"source": "https://github.com/pyca/cryptography/"}
    return {
        f"{PYPI_BASE}/cryptography/json": document(
            {
                "info": {
                    "version": "50.0.2",
                    "license": None,
                    "classifiers": [],
                    "project_urls": crypto_source,
                },
                "releases": {"50.0.2": [{"upload_time_iso_8601": "2025-06-01T00:00:00Z"}]},
            }
        ),
        f"{PYPI_BASE}/cryptography/50.0.2/json": document(
            {
                "info": {"project_urls": crypto_source},
                "urls": [
                    {
                        "filename": CRYPTOGRAPHY_LINUX_WHEEL,
                        "packagetype": "bdist_wheel",
                        "digests": {"sha256": CRYPTOGRAPHY_LINUX_SHA},
                    },
                    {
                        "filename": CRYPTOGRAPHY_MAC_WHEEL,
                        "packagetype": "bdist_wheel",
                        "digests": {"sha256": CRYPTOGRAPHY_MAC_SHA},
                    },
                    {
                        "filename": "cryptography-50.0.2.tar.gz",
                        "packagetype": "sdist",
                        "digests": {"sha256": "0" * 64},
                    },
                ],
            }
        ),
        f"{PYPI_BASE}/requests/json": document(
            {
                "info": {
                    "version": "2.32.0",
                    "license": "Apache-2.0",
                    "classifiers": [],
                    "project_urls": {"source": "https://github.com/psf/requests"},
                },
                "releases": {"2.32.0": [{"upload_time_iso_8601": "2024-05-01T00:00:00Z"}]},
            }
        ),
        f"{PYPI_BASE}/requests/2.32.0/json": document(
            {
                "info": {"project_urls": {"source": "https://github.com/psf/requests"}},
                "urls": [
                    {
                        "filename": "requests-2.32.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "digests": {"sha256": "1" * 64},
                    }
                ],
            }
        ),
        OSV_URL: document({"vulns": []}),
    }


def _fetch_from(routes: dict[str, bytes]) -> Any:
    def fetch(url: str, body: bytes | None) -> bytes | None:
        if url in routes:
            return routes[url]
        raise OSError(f"no fake route for {url}")

    return fetch


def _verdict_context(state: Path, source: LiveSource) -> Context:
    counter = itertools.count(1)
    return Context(
        policy=load_policy(str(REPO_POLICY)),
        source=source,
        store=QuarantineStore(state),
        log=AuditLog(state / "audit.jsonl", load_or_create_key(state)),
        now=AS_OF,
        new_id=lambda: new_quarantine_id(next(counter).to_bytes(13, "big")),
    )


def test_r_cw_2_verify_install_allows_recorded_export_and_blocks_other_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Full verify_install path with the real policy file (R-CW-2).

    cryptography 50.0.2 with the recorded symbol is ALLOW. requests 2.32.0 with a symbol it has
    no record for is BLOCK, and the api_surface block carries dynamic_exports.
    """
    monkeypatch.setattr(live, "host_platform", lambda: "linux-x86_64")
    # The near-name check fails closed on an empty top-N list. The gate reads that list from the
    # checksummed snapshot, so the test does the same.
    top_n = {
        Ecosystem.PYPI: load_snapshot(REPO_ROOT / "src" / "slopseal" / "fixtures").top_n(
            Ecosystem.PYPI
        )
    }
    source = _ContractStubLiveSource(
        fetch=_fetch_from(_fake_registry()),
        artifact_fetch=lambda url, eco: ContractUnknown(UnknownReason.NETWORK, "not used"),
        top_n=top_n,
        compiled_wheels=REVIEWED_POLICY.compiled_wheels,
    )

    allowed = verify_install(
        InstallRequest(
            ecosystem=Ecosystem.PYPI,
            package="cryptography",
            version="50.0.2",
            intent=Intent(purpose="receipt signing", expected_api=ED25519),
        ),
        _verdict_context(tmp_path, source),
    )
    assert allowed.outcome is Outcome.ALLOW
    assert allowed.exit_code == 0
    assert allowed.violation is None

    blocked = verify_install(
        InstallRequest(
            ecosystem=Ecosystem.PYPI,
            package="requests",
            version="2.32.0",
            intent=Intent(purpose="http client", expected_api="get"),
        ),
        _verdict_context(tmp_path, source),
    )
    assert blocked.outcome is Outcome.BLOCK
    assert blocked.exit_code == 1
    assert blocked.violation is not None
    assert blocked.violation.check == "api_surface"
    assert "(reason: dynamic_exports)" in blocked.violation.reason


# ---- R-CW-3 (#53): an override ALLOW leaves a trace, a normal ALLOW does not -----------------

OVERRIDE_TEXT = (
    "reviewed export override applied (ed25519.Ed25519PublicKey, reviewer owner, date 2026-11-17)"
)


class _FixedContractSource(LiveSource):
    """A LiveSource whose contract answer is set per test (R-CW-3)."""

    result: ContractResult

    def contract(self, eco: Ecosystem, name: str, version: str) -> ContractResult:
        return self.result


def _cryptography_allow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, contract: ContractResult
) -> tuple[Any, str]:
    monkeypatch.setattr(live, "host_platform", lambda: "linux-x86_64")
    top_n = {
        Ecosystem.PYPI: load_snapshot(REPO_ROOT / "src" / "slopseal" / "fixtures").top_n(
            Ecosystem.PYPI
        )
    }
    source = _FixedContractSource(
        fetch=_fetch_from(_fake_registry()),
        artifact_fetch=lambda url, eco: ContractUnknown(UnknownReason.NETWORK, "not used"),
        top_n=top_n,
        compiled_wheels=REVIEWED_POLICY.compiled_wheels,
    )
    source.result = contract
    decision = verify_install(
        InstallRequest(
            ecosystem=Ecosystem.PYPI,
            package="cryptography",
            version="50.0.2",
            intent=Intent(purpose="receipt signing", expected_api=ED25519),
        ),
        _verdict_context(tmp_path, source),
    )
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    return decision, audit_text


def test_r_cw_3_override_allow_carries_api_surface_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    decision, audit_text = _cryptography_allow(
        monkeypatch, tmp_path, ContractUnknown(UnknownReason.DYNAMIC_EXPORTS, "stubbed")
    )

    assert decision.outcome is Outcome.ALLOW
    traces = [
        w for w in decision.warnings if w.check == "api_surface" and w.reason == OVERRIDE_TEXT
    ]
    assert len(traces) == 1
    assert traces[0].level is Level.WARN
    assert OVERRIDE_TEXT in audit_text


def test_r_cw_3_normal_allow_has_no_override_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    decision, audit_text = _cryptography_allow(
        monkeypatch, tmp_path, ContractComplete(exports=(ED25519,))
    )

    assert decision.outcome is Outcome.ALLOW
    assert not [w for w in decision.warnings if "reviewed export override" in w.reason]
    assert "reviewed export override" not in audit_text
