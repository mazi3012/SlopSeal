"""Reviewed compiled-wheel exception for cryptography 50.0.2 (R-CW-1, ADR 0005).

The tests use the real reviewed policy file, so they check the entries as committed. Each
refusal case must give a refusal reason, never None.
"""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from typing import Any

import pytest

from slopseal.core.install_scripts import ScriptsUnknown
from slopseal.core.types import Ecosystem
from slopseal.policy import compiled_wheels as cw
from slopseal.policy import invariants
from slopseal.policy.loader import PolicyError, parse_policy
from slopseal.registry import live
from slopseal.registry.live import LiveSource

REPO_ROOT = Path(__file__).resolve().parents[3]
REPO_POLICY = REPO_ROOT / ".kiro" / "steering" / "dependency-trust.md"
LOCK = REPO_ROOT / "requirements" / "sign.lock"

REVIEWED = parse_policy(REPO_POLICY.read_text(encoding="utf-8")).compiled_wheels
PUBLISHER_URL = "https://github.com/pyca/cryptography/"
LINUX = "cryptography-50.0.2-cp39-abi3-manylinux_2_28_x86_64.whl"
LINUX_SHA = "f21e8a22c8605750c7af886bab299a363721264061b4ac0a30efb73cfd58efc5"
MAC = "cryptography-50.0.2-cp39-abi3-macosx_11_0_arm64.whl"
MAC_SHA = "0ec5f09541743261e66e291b4a0cbf0fb2997aeaab6d9e9c740b9dba1b58d1c2"
SDIST = "cryptography-50.0.2.tar.gz"


def _release(
    *, source: str = PUBLISHER_URL, files: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    if files is None:
        files = [
            {"filename": LINUX, "packagetype": "bdist_wheel", "digests": {"sha256": LINUX_SHA}},
            {"filename": MAC, "packagetype": "bdist_wheel", "digests": {"sha256": MAC_SHA}},
            {"filename": SDIST, "packagetype": "sdist", "digests": {"sha256": "0" * 64}},
        ]
    return {"info": {"project_urls": {"source": source}}, "urls": files}


def _refuse(release: dict[str, Any], version: str = "50.0.2") -> str | None:
    return cw.compiled_wheel_refusal("cryptography", version, release, REVIEWED, "linux-x86_64")


# ---- the four required cases ------------------------------------------------------------


def test_r_cw_1_allowlisted_pinned_wheel_passes() -> None:
    assert _refuse(_release()) is None


def test_r_cw_1_unpinned_version_fails() -> None:
    reason = _refuse(_release(), version="50.0.1")
    assert reason is not None
    assert "not the reviewed version" in reason


def test_r_cw_1_non_allowlisted_publisher_fails() -> None:
    release = _release(source="https://github.com/attacker/cryptography")
    assert _refuse(release) == "publisher does not match the reviewed publisher"


def test_r_cw_1_sdist_fallback_fails() -> None:
    sdist_only = [{"filename": SDIST, "packagetype": "sdist", "digests": {"sha256": "0" * 64}}]
    reason = _refuse(_release(files=sdist_only))
    assert reason is not None
    assert "sdist fallback refused" in reason


# ---- further refusals -------------------------------------------------------------------


def test_r_cw_1_digest_mismatch_fails() -> None:
    files = [
        {"filename": LINUX, "packagetype": "bdist_wheel", "digests": {"sha256": "1" * 64}},
    ]
    reason = _refuse(_release(files=files))
    assert reason == "reviewed wheel digest does not match the pinned digest"


def test_r_cw_1_unreviewed_host_platform_fails() -> None:
    reason = cw.compiled_wheel_refusal(
        "cryptography", "50.0.2", _release(), REVIEWED, platform_key=None
    )
    assert reason == "this host platform has no reviewed wheel"


def test_r_cw_1_other_package_has_no_exception() -> None:
    reason = cw.compiled_wheel_refusal("pynacl", "1.6.2", _release(), REVIEWED, "linux-x86_64")
    assert reason == "no reviewed exception for this package"


def test_r_cw_1_adapter_applies_the_exception_only_when_it_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live, "host_platform", lambda: "linux-x86_64")
    body = json.dumps(_release()).encode("utf-8")

    def fetch(url: str, _body: bytes | None) -> bytes | None:
        if url.endswith("/pypi/cryptography/50.0.2/json"):
            return body
        raise OSError("no network in this test")

    source = LiveSource(fetch=fetch, compiled_wheels=REVIEWED)
    assert source.install_scripts(Ecosystem.PYPI, "cryptography", "50.0.2") == ()

    bad = json.dumps(_release(source="https://github.com/attacker/cryptography")).encode()

    def attacker_fetch(url: str, _body: bytes | None) -> bytes | None:
        if url.endswith("/pypi/cryptography/50.0.2/json"):
            return bad
        raise OSError("no network in this test")

    refused = LiveSource(fetch=attacker_fetch, compiled_wheels=REVIEWED)
    scripts = refused.install_scripts(Ecosystem.PYPI, "cryptography", "50.0.2")
    assert isinstance(scripts, ScriptsUnknown)
    assert "publisher does not match" in scripts.reason


def test_r_cw_1_adapter_without_policy_entries_still_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live, "host_platform", lambda: "linux-x86_64")
    body = json.dumps(_release()).encode("utf-8")

    def fetch(url: str, _body: bytes | None) -> bytes | None:
        if url.endswith("/pypi/cryptography/50.0.2/json"):
            return body
        raise OSError("no network in this test")

    scripts = LiveSource(fetch=fetch).install_scripts(Ecosystem.PYPI, "cryptography", "50.0.2")
    assert isinstance(scripts, ScriptsUnknown)


# ---- policy file, floors, and the lock file ---------------------------------------------


def test_r_cw_1_allowlist_is_exactly_cryptography_50_0_2() -> None:
    assert frozenset({("cryptography", "50.0.2")}) == invariants.ALLOWED_COMPILED_WHEELS
    assert invariants.enforce_floors(parse_policy(REPO_POLICY.read_text("utf-8"))) == ()


def test_r_cw_1_floor_rejects_a_second_library() -> None:
    policy = parse_policy(REPO_POLICY.read_text(encoding="utf-8"))
    extra = dataclasses.replace(REVIEWED[0], name="pynacl", version="1.6.2")
    widened = dataclasses.replace(policy, compiled_wheels=(*REVIEWED, extra))
    violations = invariants.enforce_floors(widened)
    assert any("pynacl 1.6.2 is not allowlisted" in v for v in violations)


def test_r_cw_1_lock_file_carries_the_policy_digests() -> None:
    lock = LOCK.read_text(encoding="utf-8")
    pinned = set(re.findall(r"sha256:([0-9a-f]{64})", lock))
    policy_digests = {pin.sha256 for entry in REVIEWED for pin in entry.pins}
    assert pinned == policy_digests
    assert "cryptography==50.0.2" in lock


def _with_entry(text: str, old: str, new: str) -> str:
    assert old in text, old
    return text.replace(old, new, 1)


def test_r_cw_1_loader_rejects_a_range_instead_of_a_pin() -> None:
    text = REPO_POLICY.read_text(encoding="utf-8")
    bad = _with_entry(text, 'version = "50.0.2"', 'version = ">=50.0"')
    with pytest.raises(PolicyError, match="exact version"):
        parse_policy(bad)


def test_r_cw_1_loader_rejects_a_malformed_digest() -> None:
    text = REPO_POLICY.read_text(encoding="utf-8")
    bad = _with_entry(text, LINUX_SHA, "not-a-digest")
    with pytest.raises(PolicyError, match="64 lowercase hex"):
        parse_policy(bad)


def test_r_cw_1_loader_rejects_a_publisher_that_is_not_a_repo_url() -> None:
    text = REPO_POLICY.read_text(encoding="utf-8")
    bad = _with_entry(text, 'publisher = "github.com/pyca/cryptography"', 'publisher = "pyca"')
    with pytest.raises(PolicyError, match="github.com/owner/repo"):
        parse_policy(bad)


def test_r_cw_1_missing_table_means_no_exceptions() -> None:
    text = REPO_POLICY.read_text(encoding="utf-8")
    start = text.index("[compiled_wheels.cryptography]")
    end = text.index("```", start)
    stripped = text[:start] + text[end:]
    assert parse_policy(stripped).compiled_wheels == ()
