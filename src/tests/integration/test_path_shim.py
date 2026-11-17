"""Integration tests for the PATH shim (R-1.1, R-1.3, R-1.4).

The shim execs the real tool, so each test runs it as a subprocess. The real pip and npm are
stub scripts that record their arguments and exit with a chosen code. No test installs
anything.
"""

# ruff: noqa: S603 - every argv here is built by the test, not from untrusted input.
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from slopseal.intercept.shims import write_shims

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
STUB = '#!/bin/sh\necho "$@" > "$STUB_MARK"\nexit "${STUB_EXIT:-0}"\n'


@pytest.fixture
def stubs(tmp_path: Path) -> dict[str, Path]:
    real = tmp_path / "real"
    real.mkdir()
    marks: dict[str, Path] = {}
    for tool in ("pip", "npm", "npx"):
        script = real / tool
        script.write_text(STUB, encoding="utf-8")
        script.chmod(0o755)
        marks[tool] = tmp_path / f"{tool}.mark"
    return marks | {"dir": real}


@pytest.fixture
def base_env(tmp_path: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "SLOPSEAL_OFFLINE_SNAPSHOT": "1",
        "SLOPSEAL_STATE_DIR": str(tmp_path / "state"),
        "SLOPSEAL_POLICY_PATH": str(POLICY),
        "PYTHONPATH": str(REPO / "src"),
    }


def _run_shim(
    tool: str, args: list[str], env: dict[str, str], stubs: dict[str, Path]
) -> subprocess.CompletedProcess[str]:
    env = dict(env)
    env["SLOPSEAL_REAL_" + tool.upper()] = str(stubs["dir"] / tool)
    env["STUB_MARK"] = str(stubs[tool])
    return subprocess.run(
        [sys.executable, "-m", "slopseal.intercept.path_shim", tool, *args],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )


def _last_json(text: str) -> dict[str, object]:
    return json.loads(text.strip().splitlines()[-1])


def test_slopsquat_pip_install_is_blocked_before_the_real_tool_runs(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("pip", ["install", "csv-parser-pro==0.1.0"], base_env, stubs)
    assert result.returncode == 1
    violation = _last_json(result.stderr)
    assert violation["check"] == "existence"
    assert violation["remedy"] == "Did you mean csv-parser?"
    assert not stubs["pip"].exists(), "the real pip must not run after a BLOCK"


def test_allowed_pinned_pip_install_runs_the_real_tool_with_its_args(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("pip", ["install", "tinyfmt-kit==0.4.0"], base_env, stubs)
    assert result.returncode == 0, result.stderr
    assert "SlopSeal: Package verified. Installation is permitted." in result.stderr
    assert '"package": "tinyfmt-kit"' in result.stderr
    assert stubs["pip"].read_text().strip() == "install tinyfmt-kit==0.4.0"


def test_real_tool_exit_code_reaches_the_caller(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    env = dict(base_env, STUB_EXIT="3")
    result = _run_shim("pip", ["install", "tinyfmt-kit==0.4.0"], env, stubs)
    assert result.returncode == 3


def test_npm_install_of_a_known_malicious_version_is_blocked(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("npm", ["install", "react-codeshift@1.0.0"], base_env, stubs)
    assert result.returncode == 1
    assert not stubs["npm"].exists()


def test_unpinned_install_is_blocked_and_nothing_runs(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("pip", ["install", "tinyfmt-kit"], base_env, stubs)
    assert result.returncode == 1
    assert _last_json(result.stderr)["check"] == "shim"
    assert not stubs["pip"].exists()


def test_non_install_command_passes_through_unverified(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("pip", ["list"], base_env, stubs)
    assert result.returncode == 0
    assert stubs["pip"].read_text().strip() == "list"


def test_missing_real_tool_is_a_setup_failure_and_nothing_is_installed(
    base_env: dict[str, str], stubs: dict[str, Path], tmp_path: Path
) -> None:
    env = dict(base_env, SLOPSEAL_REAL_PIP=str(tmp_path / "does-not-exist"))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "slopseal.intercept.path_shim",
            "pip",
            "install",
            "tinyfmt-kit==0.4.0",
        ],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    assert result.returncode == 78
    assert "cannot find the real pip" in result.stderr


def test_written_wrappers_find_the_real_tool_past_the_shim_directory(
    tmp_path: Path, base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    shim_dir = tmp_path / "shims"
    write_shims(shim_dir)
    env = dict(base_env)
    env["PATH"] = f"{shim_dir}{os.pathsep}{stubs['dir']}{os.pathsep}{base_env['PATH']}"
    env["STUB_MARK"] = str(stubs["pip"])
    result = subprocess.run(
        [str(shim_dir / "pip"), "install", "tinyfmt-kit==0.4.0"],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert stubs["pip"].read_text().strip() == "install tinyfmt-kit==0.4.0"


def test_wrapper_for_a_blocked_package_stops_the_install(
    tmp_path: Path, base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    shim_dir = tmp_path / "shims"
    write_shims(shim_dir)
    env = dict(base_env)
    env["PATH"] = f"{shim_dir}{os.pathsep}{stubs['dir']}{os.pathsep}{base_env['PATH']}"
    env["STUB_MARK"] = str(stubs["pip"])
    result = subprocess.run(
        [str(shim_dir / "pip"), "install", "csv-parser-pro==0.1.0"],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    assert result.returncode == 1
    assert not stubs["pip"].exists()


# R-1.6: npx and npm exec download and run packages, so they go through the same verification.


def test_npx_unpinned_package_is_refused_and_runs_nothing(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("npx", ["evil"], base_env, stubs)
    assert result.returncode == 1
    assert _last_json(result.stderr)["check"] == "shim"
    assert not stubs["npx"].exists(), "the real npx must not run an unpinned package"


def test_npx_known_malicious_version_is_blocked(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("npx", ["react-codeshift@1.0.0"], base_env, stubs)
    assert result.returncode == 1
    assert _last_json(result.stderr)["package"] == "react-codeshift"
    assert not stubs["npx"].exists()


def test_npx_pinned_allowed_package_runs_the_real_tool(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("npx", ["uuidkit@1.4.0", "--help"], base_env, stubs)
    assert result.returncode == 0, result.stderr
    assert "SlopSeal: Package verified. Installation is permitted." in result.stderr
    assert '"package": "uuidkit"' in result.stderr
    assert stubs["npx"].read_text().strip() == "uuidkit@1.4.0 --help"


def test_npm_exec_unpinned_package_is_refused(
    base_env: dict[str, str], stubs: dict[str, Path]
) -> None:
    result = _run_shim("npm", ["exec", "evil"], base_env, stubs)
    assert result.returncode == 1
    assert not stubs["npm"].exists()


def test_written_wrappers_include_npx(tmp_path: Path) -> None:
    names = sorted(path.name for path in write_shims(tmp_path / "shims"))
    assert names == ["npm", "npx", "pip"]
