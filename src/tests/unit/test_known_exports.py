"""Reviewed known exports for an allowlisted compiled wheel (R-CW-2, ADR 0005).

The positive case uses the real reviewed policy file. The negative cases change a copy of it.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from slopseal.contract.types import UnknownReason
from slopseal.policy.invariants import enforce_floors
from slopseal.policy.known_exports import reviewed_symbols
from slopseal.policy.loader import KnownExport, Policy, PolicyError, parse_policy
from slopseal.quarantine.api_surface import (
    ApiSurface,
    ApiSurfaceResult,
    apply_reviewed_exports,
    unknown_block,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
REPO_POLICY = REPO_ROOT / ".kiro" / "steering" / "dependency-trust.md"
ED25519 = "ed25519.Ed25519PublicKey"
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
