"""Property test for the verdict-aware install hook (P-G-1).

Requirements: R-G-1..R-G-8. Property: P-G-1 (`.kiro/specs/seal-v2/properties.md`).
Hypothesis runs 500 examples per property (conftest.py profile).

The tests run `on_install.main()` end to end: payload on stdin, exit code returned, stdout and
stderr captured. Only the gate's collaborators are replaced: building the context and
`verify_install`. The generator knows what each piece of a command is by construction, so the
expected exit code does not come from the code under test.
"""

from __future__ import annotations

import contextlib
import io
import json
import shlex
import sys
import types
from collections.abc import Callable
from dataclasses import dataclass
from unittest import mock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.audit.seal import SealKeyError
from slopseal.core.types import CheckResult, Ecosystem, Level
from slopseal.fixtures.loader import SnapshotIntegrityError
from slopseal.hooks import gate, on_install
from slopseal.policy.loader import PolicyError
from slopseal.verdict import Decision, InstallRequest, Outcome

OUTCOMES = [Outcome.ALLOW, Outcome.BLOCK, Outcome.QUARANTINE]
SETUP_ERRORS = [
    None,
    PolicyError("policy is broken"),
    SealKeyError("key is missing"),
    SnapshotIntegrityError("checksum mismatch"),
    OSError(13, "permission denied"),
]

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


def run_hook(
    raw: bytes,
    *,
    outcome_for: Callable[[InstallRequest], Outcome],
    setup_error: BaseException | None = None,
) -> HookRun:
    """Run on_install.main() with `raw` on stdin. verify_install and the context are stubs."""
    calls: list[InstallRequest] = []
    outcomes: list[Outcome] = []
    real_decide = gate.decide

    def build() -> object:
        if setup_error is not None:
            raise setup_error
        return object()

    def verify(request: InstallRequest, context: object) -> Decision:
        outcome = outcome_for(request)
        calls.append(request)
        outcomes.append(outcome)
        return decision(request, outcome)

    def stub_decide(found: object) -> on_install.Evaluation:
        return real_decide(found, build=build, verify=verify)  # type: ignore[arg-type]

    stdout, stderr = io.StringIO(), io.StringIO()
    stdin = types.SimpleNamespace(buffer=io.BytesIO(raw))
    with (
        mock.patch.object(sys, "stdin", stdin),
        mock.patch.object(gate, "decide", stub_decide),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        code = on_install.main()
    return HookRun(code, stdout.getvalue(), stderr.getvalue(), calls, outcomes)


@given(
    command=commands(),
    outcome_by_name=st.dictionaries(names, st.sampled_from(OUTCOMES), max_size=8),
    default=st.sampled_from(OUTCOMES),
    setup_error=st.sampled_from(SETUP_ERRORS),
)
def test_p_g_1_only_allow_reaches_exit_0(
    command: Command,
    outcome_by_name: dict[str, Outcome],
    default: Outcome,
    setup_error: BaseException | None,
) -> None:
    """P-G-1 (1 to 6): exit 0 or 2, empty stdout, and 0 only if every verdict is ALLOW."""
    run = run_hook(
        kiro_payload(command.text).encode(),
        outcome_for=lambda request: outcome_by_name.get(request.package, default),
        setup_error=setup_error,
    )

    assert run.exit_code in (0, 2)  # (1)
    assert run.stdout == ""  # (2)

    if not command.has_install:
        assert run.exit_code == 0  # (3)
        assert run.calls == []
        assert run.stderr == ""
        return

    # An install is present. Exit 0 must be earned (4).
    expected = command.packages
    if setup_error is None:
        assert {(call.package, call.version) for call in run.calls} == expected
        assert all(call.ecosystem in (Ecosystem.PYPI, Ecosystem.NPM) for call in run.calls)
    else:
        assert run.calls == []  # (6) nothing is verified when the context cannot be built

    if run.exit_code == 0:
        assert not command.unverifiable
        assert setup_error is None
        assert run.calls
        assert all(outcome is Outcome.ALLOW for outcome in run.outcomes)

    if any(outcome is not Outcome.ALLOW for outcome in run.outcomes):
        assert run.exit_code == 2  # (5)
    if command.unverifiable or (expected and setup_error is not None):
        assert run.exit_code == 2

    # The gate is not stricter than it must be: every earned ALLOW exits 0.
    earned = (
        not command.unverifiable
        and setup_error is None
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
)
def test_p_g_1_any_payload_exits_0_or_2(raw: bytes, outcome: Outcome) -> None:
    """P-G-1 (1, 2) for arbitrary bytes, text, and JSON. Exit 0 needs ALLOW or no install."""
    run = run_hook(raw, outcome_for=lambda request: outcome)
    assert run.exit_code in (0, 2)
    assert run.stdout == ""
    if run.exit_code == 0:
        assert all(item is Outcome.ALLOW for item in run.outcomes)
    if outcome is not Outcome.ALLOW and run.calls:
        assert run.exit_code == 2


@pytest.mark.parametrize("outcome", [Outcome.BLOCK, Outcome.QUARANTINE])
def test_p_g_1_a_single_non_allow_verdict_cannot_reach_exit_0(outcome: Outcome) -> None:
    """The smallest case of P-G-1 (5), kept as a readable example next to the property."""
    run = run_hook(
        kiro_payload("pip install tinyfmt-kit==0.4.0").encode(), outcome_for=lambda r: outcome
    )
    assert run.exit_code == 2
    assert len(run.calls) == 1
