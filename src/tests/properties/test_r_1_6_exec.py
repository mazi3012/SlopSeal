"""Property tests for exec-style installs (R-1.6).

Oracle: an exec-style command may run code only when every package it names is pinned exactly
in its own arguments and was verified ALLOW. The verifier and os.execv are replaced, so no
package is downloaded and no real tool runs.

Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import string
from unittest import mock

from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.types import Ecosystem
from slopseal.intercept import path_shim
from slopseal.intercept.parse import Install, Passthrough, parse
from slopseal.verdict import Decision, InstallRequest, Outcome

PREFIXES = st.sampled_from([("npx", []), ("npm", ["exec"]), ("npm", ["x"])])
FIXED_TOKENS = st.sampled_from(
    [
        "-p",
        "--package",
        "--package=a@1.0.0",
        "-c",
        "--call",
        "-y",
        "--yes",
        "--",
        "--registry",
        "--no-install",
        "evil",
        "evil@1.0.0",
        "react-codeshift@1.0.0",
        "tinyfmt-kit@0.4.0",
        "a@1.0.0",
        "a",
        "@s/p@2.0.1",
        "./x",
        "file:x",
        "https://example.com/x.tgz",
        "git+https://github.com/x/y.git",
        "^1.0.0",
        "a@latest",
    ]
)
RANDOM_TOKENS = st.text(alphabet=string.ascii_letters + string.digits + "@-./:=^~", max_size=14)
TOKENS = st.one_of(FIXED_TOKENS, RANDOM_TOKENS)


@st.composite
def exec_argv(draw: st.DrawFn) -> tuple[str, list[str]]:
    tool, lead = draw(PREFIXES)
    body = draw(st.lists(TOKENS, max_size=6))
    return tool, [*lead, *body]


def _allow_all(request: InstallRequest, ctx: object) -> Decision:
    return Decision(
        outcome=Outcome.ALLOW,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=request.version or "",
        reason="test allow",
    )


def _block_all(request: InstallRequest, ctx: object) -> Decision:
    return Decision(
        outcome=Outcome.BLOCK,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=request.version or "",
        reason="test block",
    )


def _run_with(tool: str, argv: list[str], verifier: object) -> list[tuple[str, ...]]:
    """Run the shim with a fake verifier and record every os.execv call."""
    execs: list[tuple[str, ...]] = []

    def fake_execv(path: str, args: list[str]) -> None:
        execs.append((path, *args))

    with (
        mock.patch.object(path_shim, "build_context", return_value=object()),
        mock.patch.object(path_shim, "verify_install", side_effect=verifier),
        mock.patch.object(path_shim, "find_real_tool", return_value="/bin/true"),
        mock.patch.object(path_shim.os, "execv", side_effect=fake_execv),
    ):
        path_shim.run([tool, *argv], {"PATH": ""})
    return execs


@given(exec_argv())
def test_exec_style_result_is_never_passthrough_and_only_names_pinned_packages(
    case: tuple[str, list[str]],
) -> None:
    """P-EXEC-1: an exec-style command is never passed through, and an Install result pins every
    package to an exact `name@x.y.z` token that appears in the command itself."""
    tool, argv = case
    result = parse(tool, argv)
    assert not isinstance(result, Passthrough)
    if isinstance(result, Install):
        for name, version in result.specs:
            assert any(f"{name}@{version}" in token for token in argv), (name, version, argv)


@given(exec_argv())
def test_exec_style_command_never_reaches_real_tool_unless_verified(
    case: tuple[str, list[str]],
) -> None:
    """P-EXEC-2: with every package refused, the real tool never runs. With every package allowed,
    the real tool runs only when the command parsed to an Install of pinned packages."""
    tool, argv = case

    blocked_run = _run_with(tool, argv, _block_all)
    assert blocked_run == [], "a refused package reached the real tool"

    allowed_run = _run_with(tool, argv, _allow_all)
    if allowed_run:
        assert isinstance(parse(tool, argv), Install), argv


def test_exec_request_carries_the_pinned_version_to_the_verifier() -> None:
    """The verifier receives the exact version the parser read, never None."""
    seen: list[InstallRequest] = []

    def record(request: InstallRequest, ctx: object) -> Decision:
        seen.append(request)
        return _allow_all(request, ctx)

    _run_with("npx", ["tinyfmt-kit@0.4.0", "--help"], record)
    assert seen == [InstallRequest(ecosystem=Ecosystem.NPM, package="tinyfmt-kit", version="0.4.0")]
