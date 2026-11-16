"""Tests for `slopseal policy diff` (R-5.7.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from slopseal.cli import main
from slopseal.policy.diff import diff_policies
from slopseal.policy.loader import load_policy

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
RATE_LINE = "max_installs_per_minute = 10"


@pytest.fixture
def policy_text() -> str:
    text = POLICY.read_text(encoding="utf-8")
    assert RATE_LINE in text, "the rate limit line moved; update this test"
    return text


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_identical_policies_have_no_changes(tmp_path: Path, policy_text: str) -> None:
    old = load_policy(str(_write(tmp_path, "a.md", policy_text)))
    new = load_policy(str(_write(tmp_path, "b.md", policy_text)))
    assert diff_policies(old, new) == []
    assert old.policy_hash == new.policy_hash


def test_one_changed_value_is_the_only_change(tmp_path: Path, policy_text: str) -> None:
    edited = policy_text.replace(RATE_LINE, "max_installs_per_minute = 5")
    old = load_policy(str(_write(tmp_path, "a.md", policy_text)))
    new = load_policy(str(_write(tmp_path, "b.md", edited)))
    changes = diff_policies(old, new)
    assert [(c.field, c.old, c.new) for c in changes] == [("max_installs_per_minute", 10, 5)]
    assert old.policy_hash != new.policy_hash


def test_cli_prints_the_changed_field_and_both_hashes(
    tmp_path: Path, policy_text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    edited = policy_text.replace(RATE_LINE, "max_installs_per_minute = 5")
    a = _write(tmp_path, "a.md", policy_text)
    b = _write(tmp_path, "b.md", edited)
    assert main(["policy", "diff", str(a), str(b)]) == 0
    out = capsys.readouterr().out.splitlines()
    old_hash = load_policy(str(a)).policy_hash
    new_hash = load_policy(str(b)).policy_hash
    assert out[0] == f"policy_hash: {old_hash} -> {new_hash}"
    assert out[1] == "changed max_installs_per_minute: 10 -> 5"
    assert len(out) == 2


def test_cli_reports_no_change_for_identical_files(
    tmp_path: Path, policy_text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    a = _write(tmp_path, "a.md", policy_text)
    b = _write(tmp_path, "b.md", policy_text)
    assert main(["policy", "diff", str(a), str(b)]) == 0
    assert "no policy field changed" in capsys.readouterr().out


def test_cli_fails_closed_when_a_file_is_not_a_valid_policy(
    tmp_path: Path, policy_text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    good = _write(tmp_path, "a.md", policy_text)
    bad = _write(tmp_path, "bad.md", "no policy block here\n")
    assert main(["policy", "diff", str(good), str(bad)]) == 78
    assert "policy error" in capsys.readouterr().err


def test_bundled_default_policy_loads_without_workspace_file(tmp_path: Path) -> None:
    """When no workspace policy exists, load_policy_or_bundled_default uses the bundled default."""
    import os

    from slopseal.policy.loader import load_policy_or_bundled_default

    # Temporarily change to a temp directory with no .kiro folder
    original_cwd = os.getcwd()
    original_env = os.environ.get("SLOPSEAL_POLICY_PATH")
    try:
        os.chdir(tmp_path)
        # Ensure SLOPSEAL_POLICY_PATH is not set
        if "SLOPSEAL_POLICY_PATH" in os.environ:
            del os.environ["SLOPSEAL_POLICY_PATH"]
        # Load should succeed using the bundled default
        policy = load_policy_or_bundled_default()
        assert policy.schema_version == 1
        assert policy.max_installs_per_minute == 10
    finally:
        os.chdir(original_cwd)
        if original_env is not None:
            os.environ["SLOPSEAL_POLICY_PATH"] = original_env

