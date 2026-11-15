"""Property tests for check 2.5 (install-script detection).

Requirements: R-2.5, R-P-1. Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.install_scripts import (
    ALWAYS_RUN_HOOKS,
    EXECUTION_PRIMITIVES,
    InstallScript,
    ScriptsUnknown,
    check_install_scripts,
)
from slopseal.core.types import Level

FILLER = ["print('hi')", "x = 1", "\n", "setup()", " ", "version = '1.0'"]
PRIMITIVE_TOKENS = sorted({p for group in EXECUTION_PRIMITIVES.values() for p in group})
bodies = st.lists(st.sampled_from([*FILLER, *PRIMITIVE_TOKENS]), max_size=8).map("".join)
hook_kinds = st.sampled_from(sorted(ALWAYS_RUN_HOOKS))
levels = st.sampled_from([Level.WARN, Level.BLOCK])


@given(hook=hook_kinds, body=bodies, level=levels)
def test_r_2_5_npm_lifecycle_hook_is_always_a_finding(hook: str, body: str, level: Level) -> None:
    result = check_install_scripts((InstallScript(hook, body),), level=level)
    assert result.level is level


@given(body=bodies, level=levels)
def test_r_2_5_setup_py_finding_iff_execution_primitive(body: str, level: Level) -> None:
    result = check_install_scripts((InstallScript("setup.py", body),), level=level)
    expected = any(token in body.lower() for token in EXECUTION_PRIMITIVES["setup.py"])
    assert (result.level is level) == expected
    assert result.level in {Level.PASS, level}


@given(
    hook=st.text(min_size=1, max_size=20).filter(
        lambda h: h not in ALWAYS_RUN_HOOKS and h not in EXECUTION_PRIMITIVES
    ),
    body=bodies,
)
def test_r_2_5_unrecognized_hook_is_a_finding(hook: str, body: str) -> None:
    result = check_install_scripts((InstallScript(hook, body),), level=Level.BLOCK)
    assert result.level is Level.BLOCK


@given(level=levels)
def test_r_2_5_unknown_inventory_blocks(level: Level) -> None:
    result = check_install_scripts(ScriptsUnknown("download failed"), level=level)
    assert result.level is Level.BLOCK


def test_r_2_5_no_scripts_passes() -> None:
    assert check_install_scripts((), level=Level.BLOCK).level is Level.PASS


@given(
    scripts=st.lists(
        st.builds(
            InstallScript,
            hook=st.sampled_from(["postinstall", "setup.py", "build.rs"]),
            body=bodies,
        ),
        min_size=1,
        max_size=4,
    ),
    extra=st.builds(InstallScript, hook=st.sampled_from(["postinstall", "setup.py"]), body=bodies),
)
def test_r_2_5_adding_a_script_never_reduces_severity(
    scripts: list[InstallScript], extra: InstallScript
) -> None:
    before = check_install_scripts(tuple(scripts), level=Level.WARN).level
    after = check_install_scripts((*scripts, extra), level=Level.WARN).level
    assert after >= before


@given(
    scripts=st.lists(
        st.builds(InstallScript, hook=st.sampled_from(["postinstall", "setup.py"]), body=bodies),
        min_size=1,
        max_size=4,
    )
)
def test_r_2_5_result_does_not_depend_on_script_order(scripts: list[InstallScript]) -> None:
    forward = check_install_scripts(tuple(scripts), level=Level.BLOCK)
    backward = check_install_scripts(tuple(reversed(scripts)), level=Level.BLOCK)
    assert forward == backward


def test_r_2_5_configured_level_is_reported() -> None:
    script = (InstallScript("postinstall", ""),)
    assert check_install_scripts(script, level=Level.WARN).level is Level.WARN
    assert check_install_scripts(script, level=Level.BLOCK).level is Level.BLOCK


def test_r_2_5_hard_block_is_not_a_configurable_level() -> None:
    with pytest.raises(ValueError, match="WARN or BLOCK"):
        check_install_scripts((InstallScript("postinstall", ""),), level=Level.HARD_BLOCK)
