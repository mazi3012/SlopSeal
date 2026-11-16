"""Property test: a broken pipeline never allows an install (P-G-3).

Requirements: R-G-6, R-G-7. Property: P-G-3 (`.kiro/specs/seal-v2/properties.md`).
Hypothesis runs 500 examples per property (conftest.py profile).

Every command here contains an install. A broken pipeline must exit 2 with no ALLOW line. A
command with no install is outside this property (R-G-7). It never loads the pipeline, so it
keeps exit 0, which the last test checks.

The hook runs end to end (`on_install.main()`). Only the failure point is replaced, as in
P-G-1: the gate import, the context build, the decision, and the verdict call.
"""

from __future__ import annotations

import contextlib
import io
import json
import shlex
import sys
import types
from collections.abc import Iterator
from unittest import mock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.audit.seal import SealKeyError
from slopseal.fixtures.loader import SnapshotIntegrityError
from slopseal.hooks import gate, on_install
from slopseal.policy.loader import PolicyError
from slopseal.verdict import Decision, InstallRequest, Outcome

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")

GATE_MODULE = "slopseal.hooks.gate"
BUILD_ERRORS: dict[str, BaseException] = {
    "build_policy": PolicyError("policy is broken"),
    "build_seal_key": SealKeyError("key is missing"),
    "build_snapshot": SnapshotIntegrityError("checksum mismatch"),
    "build_os": OSError(13, "permission denied"),
}
FAILURES = (*BUILD_ERRORS, "import_missing", "decision_error", "verify_error")

names = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=8)
versions = st.builds(lambda a, b: f"{a}.{b}.1", st.integers(0, 20), st.integers(0, 20))


@st.composite
def install_piece(draw: st.DrawFn) -> str:
    """One install: pinned or unpinned, pip or npm, optionally behind a wrapper."""
    name = draw(names)
    version = draw(versions)
    text = draw(
        st.sampled_from(
            [
                f"pip install {name}=={version}",
                f"pip install {name}",
                f"npm install {name}@{version}",
                f"npm install {name}",
                f"npx {name}@{version}",
                f"uv add {name}",
            ]
        )
    )
    wrapper = draw(st.sampled_from(["", "sudo ", "nohup "]))
    text = wrapper + text
    if draw(st.booleans()):
        text = f"bash -c {shlex.quote(text)}"
    return text


@st.composite
def install_commands(draw: st.DrawFn) -> str:
    pieces = draw(st.lists(install_piece(), min_size=1, max_size=4))
    joiners = draw(st.lists(st.sampled_from([" && ", " ; ", " | "]), min_size=3, max_size=3))
    text = pieces[0]
    for joiner, piece in zip(joiners, pieces[1:], strict=False):
        text += joiner + piece
    return text


def kiro_payload(command: str) -> bytes:
    return json.dumps(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": command}}
    ).encode()


@contextlib.contextmanager
def _pipeline_broken(failure: str) -> Iterator[None]:
    if failure == "import_missing":
        saved = sys.modules.get(GATE_MODULE)
        sys.modules[GATE_MODULE] = None  # None in sys.modules makes an import fail
        try:
            yield
        finally:
            if saved is None:
                sys.modules.pop(GATE_MODULE, None)
            else:
                sys.modules[GATE_MODULE] = saved  # type: ignore[assignment]
    else:
        yield


def run_hook(command: str, failure: str) -> tuple[int, str, str, list[str]]:
    """Run the hook with one pipeline failure. Returns (exit, stdout, stderr, verified names)."""
    verified: list[str] = []
    real_decide = gate.decide

    def build() -> object:
        if failure in BUILD_ERRORS:
            raise BUILD_ERRORS[failure]
        return object()

    def verify(request: InstallRequest, context: object) -> Decision:
        if failure == "verify_error":
            raise RuntimeError("verdict call failed")
        verified.append(request.package)
        return Decision(
            outcome=Outcome.ALLOW,
            ecosystem=request.ecosystem.value,
            package=request.package,
            version=request.version or "",
            reason="stub allow",
        )

    def stub_decide(found: object) -> on_install.Evaluation:
        if failure == "decision_error":
            raise RuntimeError("decision failed")
        return real_decide(found, build=build, verify=verify)  # type: ignore[arg-type]

    stdout, stderr = io.StringIO(), io.StringIO()
    stdin = types.SimpleNamespace(buffer=io.BytesIO(kiro_payload(command)))
    with (
        _pipeline_broken(failure),
        mock.patch.object(sys, "stdin", stdin),
        mock.patch.object(gate, "decide", stub_decide),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        code = on_install.main()
    return code, stdout.getvalue(), stderr.getvalue(), verified


@given(command=install_commands(), failure=st.sampled_from(FAILURES))
def test_p_g_3_a_broken_pipeline_never_allows_an_install(command: str, failure: str) -> None:
    """P-G-3: exit 2, empty stdout, and no ALLOW line for any install under any failure."""
    code, stdout, stderr, _verified = run_hook(command, failure)
    assert code == 2
    assert stdout == ""
    assert "slopseal: ALLOW" not in stderr


@pytest.mark.parametrize("failure", FAILURES)
def test_p_g_3_pinned_install_is_blocked_under_each_failure(failure: str) -> None:
    code, _stdout, stderr, _verified = run_hook("pip install tinyfmt-kit==0.4.0", failure)
    assert code == 2
    assert "slopseal: ALLOW" not in stderr


@pytest.mark.parametrize("failure", FAILURES)
def test_p_g_3_non_install_keeps_exit_0_under_each_failure(failure: str) -> None:
    """R-G-7: a broken pipeline does not block a command that has no install."""
    code, stdout, stderr, verified = run_hook("ls -la", failure)
    assert code == 0
    assert stdout == ""
    assert stderr == ""
    assert verified == []
