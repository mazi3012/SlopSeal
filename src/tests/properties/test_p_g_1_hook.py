"""Property test for the verdict-aware install hook (P-G-1).

Requirements: R-G-1..R-G-8. Property: P-G-1 (`.kiro/specs/seal-v2/properties.md`).
Hypothesis runs 500 examples per property (conftest.py profile).

The tests run `on_install.main()` end to end: payload on stdin, exit code returned, stdout and
stderr captured. The collaborators are replaced only where a failure is injected: the context
build, the gate import, the gate call, stdin, the stdin stall timer, and the deadline. The
generator knows what each piece of a command is by construction, so the expected exit code
comes from the spec rules, not from the code under test.
"""

from __future__ import annotations

import contextlib
import io
import json
import shlex
import sys
import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any
from unittest import mock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.audit.seal import SealKeyError
from slopseal.core.types import CheckResult, Level
from slopseal.fixtures.loader import SnapshotIntegrityError
from slopseal.hooks import gate, on_install
from slopseal.policy.loader import PolicyError
from slopseal.verdict import Decision, InstallRequest, Outcome

# The decision and import failures are injected on purpose. The hook's worker thread prints
# their tracebacks, and pytest reports each as a warning. The assertions are unaffected.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")

GATE_MODULE = "slopseal.hooks.gate"
OUTCOMES = [Outcome.ALLOW, Outcome.BLOCK, Outcome.QUARANTINE]

# Setup failures from `.kiro/specs/seal-v2/properties.md`, P-G-1.
BUILD_ERRORS: dict[str, BaseException] = {
    "build_policy": PolicyError("policy is broken"),
    "build_seal_key": SealKeyError("key is missing"),
    "build_snapshot": SnapshotIntegrityError("checksum mismatch"),
    "build_os": OSError(13, "permission denied"),
}
# The hook cannot know the command, or the decision did not finish, so these block whatever
# the command is (R-G-6).
ALWAYS_BLOCKED = frozenset({"stdin_unreadable", "stdin_stalled", "deadline"})
# These only matter when the command has an install. A command with no install never builds
# the context or loads the gate (R-G-7).
INSTALL_BLOCKED = frozenset({*BUILD_ERRORS, "import_missing", "decision_error"})
FAILURES = ("none", *sorted(ALWAYS_BLOCKED), *sorted(INSTALL_BLOCKED))

NO_INSTALL = [
    "ls",
    "ls -la",
    "git status",
    "echo hello",
    "pytest -q",
    "npm run build",
    "npm test",
    "cat file.txt",
    "echo pip install x",
    "grep -r 'pip install' docs",
    "python3 -m pytest",
    "pip --version",
    "git commit -m 'use npm install'",
]
# Installs the hook cannot verify, whatever the verdict would be.
UNVERIFIABLE = [
    "pip install somepackage",
    "pip install -r requirements.txt",
    "pip install ./local-package",
    "npm install",
    "npm install left-pad",
    "uv add requests",
    "cargo install ripgrep",
    "pnpm add left-pad",
    "yarn add left-pad",
    "go get example.invalid/x",
    "pipx install black",
    "pip download somepackage==1.0.0",
]
# Wrappers that keep an install verifiable, and wrappers that make it unverifiable (R-G-5).
NEUTRAL_WRAPPERS = ["", "sudo ", "nohup ", "command "]
TAINTING_WRAPPERS = ["env FOO=1 ", "FOO=1 ", "env -i BAR=2 "]
JOINERS = [" && ", " ; ", " || ", " | ", "\n"]

names = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=8)
versions = st.builds(
    lambda a, b, c: f"{a}.{b}.{c}",
    st.integers(0, 20),
    st.integers(0, 20),
    st.integers(0, 20),
)


@dataclass(frozen=True)
class Piece:
    text: str
    kind: str  # "none", "verifiable", or "unverifiable"
    taints: bool = False  # True when the piece sets a sticky taint for the rest of the command
    package: tuple[str, str] | None = None


@st.composite
def pieces(draw: st.DrawFn) -> Piece:
    kind = draw(st.sampled_from(["none", "verifiable", "unverifiable"]))
    if kind == "none":
        return Piece(draw(st.sampled_from(NO_INSTALL)), "none")
    if kind == "unverifiable":
        return Piece(draw(st.sampled_from(UNVERIFIABLE)), "unverifiable")
    name, version = draw(names), draw(versions)
    form = draw(st.sampled_from(["pip", "pip3", "python", "npm", "npx", "exec"]))
    text = {
        "pip": f"pip install {name}=={version}",
        "pip3": f"pip3 install --quiet {name}=={version}",
        "python": f"python3 -m pip install {name}=={version}",
        "npm": f"npm install {name}@{version}",
        "npx": f"npx {name}@{version}",
        "exec": f"npm exec {name}@{version}",
    }[form]
    taints = draw(st.booleans())
    wrapper = draw(st.sampled_from(TAINTING_WRAPPERS if taints else NEUTRAL_WRAPPERS))
    text = wrapper + text
    if draw(st.booleans()):
        text = f"bash -c {shlex.quote(text)}"
    return Piece(text, "verifiable", taints, (name, version))


@dataclass(frozen=True)
class Command:
    text: str
    pieces: tuple[Piece, ...]

    @property
    def has_install(self) -> bool:
        return any(piece.kind != "none" for piece in self.pieces)

    @property
    def unverifiable(self) -> bool:
        """True when any install cannot be verified. A taint applies to every later install."""
        tainted = False
        for piece in self.pieces:
            if piece.kind == "none":
                continue
            tainted = tainted or piece.taints
            if piece.kind == "unverifiable" or tainted:
                return True
        return False

    @property
    def packages(self) -> set[tuple[str, str]]:
        """The packages the gate sends to verify_install: the untainted verifiable ones."""
        found: set[tuple[str, str]] = set()
        tainted = False
        for piece in self.pieces:
            if piece.kind == "none":
                continue
            tainted = tainted or piece.taints
            if piece.kind == "verifiable" and not tainted and piece.package is not None:
                found.add(piece.package)
        return found


@st.composite
def commands(draw: st.DrawFn) -> Command:
    parts = tuple(draw(st.lists(pieces(), min_size=1, max_size=5)))
    text = parts[0].text
    for piece in parts[1:]:
        text += draw(st.sampled_from(JOINERS)) + piece.text
    return Command(text, parts)


def kiro_payload(command: str) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_input": {"command": command}})


def decision(request: InstallRequest, outcome: Outcome) -> Decision:
    violation = CheckResult("existence", Level.HARD_BLOCK, "stub reason", "stub remedy")
    return Decision(
        outcome=outcome,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=request.version or "",
        reason="stub",
        violation=violation if outcome is Outcome.BLOCK else None,
        quarantine_id="q-1" if outcome is Outcome.QUARANTINE else None,
        quarantine_payload=(
            {"quarantine_id": "q-1", "mismatch_type": "api_absent"}
            if outcome is Outcome.QUARANTINE
            else None
        ),
    )


@dataclass
class HookRun:
    exit_code: int
    stdout: str
    stderr: str
    calls: list[InstallRequest]
    outcomes: list[Outcome]


class _BrokenStdin:
    """A stdin buffer whose read fails, as when the pipe is closed by the OS."""

    def read(self) -> bytes:
        raise OSError(5, "input/output error")


@contextlib.contextmanager
def _failure_injected(failure: str) -> Iterator[None]:
    """Patch the one point where `failure` occurs. Everything else runs for real."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(on_install, "_exit_now", _recording_exit_now)
        )  # the real one calls os._exit, which would end the test run
        if failure == "stdin_stalled":
            stack.enter_context(
                mock.patch.object(on_install, "_read_stdin", return_value=(None, True))
            )
        elif failure == "deadline":

            def timed_out(raw: str | None) -> on_install.Evaluation | None:
                raise TimeoutError

            stack.enter_context(mock.patch.object(on_install, "_evaluate_in_worker", timed_out))
        elif failure == "import_missing":
            saved = sys.modules.get(GATE_MODULE)
            sys.modules[GATE_MODULE] = None  # None in sys.modules makes an import fail
            stack.callback(_restore_module, saved)
        yield


def _restore_module(saved: object) -> None:
    if saved is None:
        sys.modules.pop(GATE_MODULE, None)
    else:
        sys.modules[GATE_MODULE] = saved  # type: ignore[assignment]


def _recording_exit_now() -> int:
    sys.stderr.write(on_install.BLOCK_MESSAGE + "\n")
    return on_install.BLOCK_EXIT


def run_hook(
    raw: bytes,
    *,
    outcome_for: Callable[[InstallRequest], Outcome],
    failure: str = "none",
) -> HookRun:
    """Run on_install.main() with `raw` on stdin, with the failure `failure` injected."""
    calls: list[InstallRequest] = []
    outcomes: list[Outcome] = []
    real_decide = gate.decide

    def build() -> object:
        if failure in BUILD_ERRORS:
            raise BUILD_ERRORS[failure]
        return object()

    def verify(request: InstallRequest, context: object) -> Decision:
        outcome = outcome_for(request)
        calls.append(request)
        outcomes.append(outcome)
        return decision(request, outcome)

    def stub_decide(found: Any) -> on_install.Evaluation:
        if failure == "decision_error":
            raise RuntimeError("decision failed")
        return real_decide(found, build=build, verify=verify)  # type: ignore[arg-type]

    stdin_buffer: Any = _BrokenStdin() if failure == "stdin_unreadable" else io.BytesIO(raw)
    stdin = types.SimpleNamespace(buffer=stdin_buffer)
    stdout, stderr = io.StringIO(), io.StringIO()
    with (
        _failure_injected(failure),
        mock.patch.object(sys, "stdin", stdin),
        mock.patch.object(gate, "decide", stub_decide),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        code = on_install.main()
    return HookRun(code, stdout.getvalue(), stderr.getvalue(), calls, outcomes)


def must_block(has_install: bool, failure: str) -> bool:
    """P-G-1 (6, 7): the exit code is 2 for these failures, by the rules in the spec."""
    if failure in ALWAYS_BLOCKED:
        return True
    return failure in INSTALL_BLOCKED and has_install


@given(
    command=commands(),
    outcome_by_name=st.dictionaries(names, st.sampled_from(OUTCOMES), max_size=8),
    default=st.sampled_from(OUTCOMES),
    failure=st.sampled_from(FAILURES),
)
def test_p_g_1_only_allow_reaches_exit_0(
    command: Command,
    outcome_by_name: dict[str, Outcome],
    default: Outcome,
    failure: str,
) -> None:
    """P-G-1 (1 to 7): exit 0 or 2, empty stdout, and 0 only if every verdict is ALLOW."""
    run = run_hook(
        kiro_payload(command.text).encode(),
        outcome_for=lambda request: outcome_by_name.get(request.package, default),
        failure=failure,
    )

    assert run.exit_code in (0, 2)  # (1)
    assert run.stdout == ""  # (2)

    if must_block(command.has_install, failure):
        assert run.exit_code == 2  # (6, 7)
    if failure != "none":
        assert run.calls == []  # (3) a setup failure verifies nothing
    if not command.has_install and failure not in ALWAYS_BLOCKED:
        assert run.exit_code == 0  # (7) R-G-7: not on the path of a non-install command
        assert run.calls == []
        assert run.stderr == ""
        return

    if failure == "none":
        assert {(call.package, call.version) for call in run.calls} == command.packages  # (3)

    if run.exit_code == 0:
        # (4) Exit 0 must be earned.
        assert failure == "none"
        assert not command.unverifiable
        assert run.calls
        assert all(outcome is Outcome.ALLOW for outcome in run.outcomes)

    if any(outcome is not Outcome.ALLOW for outcome in run.outcomes):
        assert run.exit_code == 2  # (5)

    # The gate is not stricter than it must be: every earned ALLOW exits 0.
    earned = (
        failure == "none"
        and not command.unverifiable
        and bool(run.calls)
        and all(outcome is Outcome.ALLOW for outcome in run.outcomes)
    )
    assert (run.exit_code == 0) == earned


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=12,
)


@given(
    raw=st.one_of(
        st.binary(max_size=200),
        st.text(max_size=200).map(str.encode),
        json_values.map(lambda value: json.dumps(value).encode()),
        st.text(max_size=200).map(lambda command: kiro_payload(command).encode()),
        st.fixed_dictionaries({"tool_input": st.fixed_dictionaries({"command": json_values})}).map(
            lambda value: json.dumps(value).encode()
        ),
    ),
    outcome=st.sampled_from(OUTCOMES),
    failure=st.sampled_from(FAILURES),
)
def test_p_g_1_any_payload_exits_0_or_2(raw: bytes, outcome: Outcome, failure: str) -> None:
    """P-G-1 (1, 2, 5, 6) for arbitrary bytes, text, and JSON, under every setup failure."""
    run = run_hook(raw, outcome_for=lambda request: outcome, failure=failure)
    assert run.exit_code in (0, 2)
    assert run.stdout == ""
    if failure in ALWAYS_BLOCKED:
        assert run.exit_code == 2
    if run.exit_code == 0:
        assert failure not in ALWAYS_BLOCKED
        assert all(item is Outcome.ALLOW for item in run.outcomes)
    if outcome is not Outcome.ALLOW and run.calls:
        assert run.exit_code == 2


@pytest.mark.parametrize("failure", FAILURES)
@pytest.mark.parametrize(
    ("command", "has_install"),
    [("ls -la", False), ("pip install tinyfmt-kit==0.4.0", True)],
)
def test_p_g_1_every_setup_failure_on_one_command(
    failure: str, command: str, has_install: bool
) -> None:
    """A readable table of the P-G-1 rules: each failure on a non-install and an install."""
    run = run_hook(
        kiro_payload(command).encode(), outcome_for=lambda request: Outcome.ALLOW, failure=failure
    )
    expected = 2 if must_block(has_install, failure) else 0
    assert run.exit_code == expected
    assert run.stdout == ""
    if failure != "none":
        assert run.calls == []


@pytest.mark.parametrize("outcome", [Outcome.BLOCK, Outcome.QUARANTINE])
def test_p_g_1_a_single_non_allow_verdict_cannot_reach_exit_0(outcome: Outcome) -> None:
    """The smallest case of P-G-1 (5), kept as a readable example next to the property."""
    run = run_hook(
        kiro_payload("pip install tinyfmt-kit==0.4.0").encode(), outcome_for=lambda r: outcome
    )
    assert run.exit_code == 2
    assert len(run.calls) == 1
