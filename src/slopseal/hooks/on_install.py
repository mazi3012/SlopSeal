"""PreToolUse hook: verdict-aware gate for agent shell commands that install packages.

Kiro writes the hook payload as JSON on stdin. The install check reads only
tool_input.command, the text the shell will run. It does not scan description or cwd.
If that key is missing or not a string, every string in the payload is scanned instead, and any
install found there is refused, because the hook cannot know what will run.

Detection looks at command positions, not at raw text. It splits the command into simple
commands at &&, ||, ;, |, &, parentheses, backticks, and newlines. It strips wrappers such as
sudo, env, VAR=val, nohup, and xargs, and it recurses into shell strings such as
`bash -c "..."`. A package manager named in an argument, such as `echo "pip install x"`,
is not an install. Each install found becomes a `Detected` record.

A command with no install exits 0 and writes nothing (R-G-7). A command with installs goes to
slopseal.hooks.gate.decide, which calls verify_install for every pinned pip or npm package and
exits 0 only if all are ALLOW. Everything else exits 2 (R-G-2..R-G-5). The gate module is
imported only when an install is found, so ordinary commands do not load the pipeline.

Exit 2 blocks. The hook also blocks when the payload cannot be read, when stdin does not
close within 3 seconds, when the command cannot be parsed, when shell nesting is too deep, when
the decision does not finish within the deadline, and when the decision code raises (R-G-6).
The decision runs in a worker thread. A worker that dies without a result is a block, so no
exception can reach exit 0 or the interpreter's exit 1.

Known limit: a script file, or `python -c`, that runs an install is not inspected. Neither is
a package index set outside the command (a config file such as .npmrc or pip.conf).

Requirements: R-1.1, R-G-1..R-G-8. Property: P-G-1. Layer 5.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

BLOCK_EXIT = 2
ALLOW_EXIT = 0
STDIN_TIMEOUT_SECONDS = 3.0
# The hook config sets a 30 second timeout. The deadline leaves time to write the block message.
DEADLINE_SECONDS = 25.0
MAX_DEPTH = 8

# Written when the hook cannot reach a decision (unreadable payload, timeout, crash). That is an
# error, not a finding about a package, so the wording says verification could not run (R-U-1).
BLOCK_MESSAGE = (
    "SlopSeal: Unable to verify package. Installation is not permitted. "
    "Verify the package with the slopseal MCP tool, then run the install again."
)

UNREADABLE_REASON = "the command text cannot be read or is nested too deeply"
NO_COMMAND_REASON = "the payload has no command text, so the hook cannot know what will run"
ASSIGNMENT_REASON = (
    "an environment assignment, export, or env wrapper comes before the install and can "
    "redirect the package index"
)
XARGS_REASON = "xargs supplies the package names from stdin, so they cannot be verified"

_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_PIP = re.compile(r"pip[0-9.]*")
_PYTHON = re.compile(r"python[0-9.]*")
_EASY_INSTALL = re.compile(r"easy_install(-[0-9.]+)?")

SEPARATOR_CHARS = frozenset("();&|")
REDIRECT_CHARS = frozenset("<>")
KEYWORDS = frozenset({"!", "{", "}", "if", "then", "else", "elif", "do", "while", "until"})
WRAPPERS = frozenset(
    {"sudo", "doas", "env", "command", "exec", "builtin", "nohup", "nice", "time", "xargs"}
)
WRAPPER_ARG_OPTIONS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C"}),
    "exec": frozenset({"-a"}),
    "nice": frozenset({"-n"}),
    "time": frozenset({"-f", "-o"}),
    "xargs": frozenset({"-I", "-n", "-P", "-L", "-d", "-s", "-a", "-E"}),
}
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash"})
# Builtins that set shell variables for the rest of the command line.
ENV_BUILTINS = frozenset({"export", "declare", "typeset", "readonly", "local"})

PIP_VERBS = frozenset({"install", "download", "wheel"})
PIPX_VERBS = frozenset({"install", "run", "inject", "upgrade"})
UV_VERBS = frozenset({"add", "sync", "lock"})
POETRY_VERBS = frozenset({"add", "install"})
PDM_VERBS = frozenset({"add", "install", "sync"})
PIPENV_VERBS = frozenset({"install"})
NODE_INSTALL_VERBS = frozenset({"install", "i", "add", "ci"})
NODE_EXEC_VERBS = frozenset({"exec", "x", "dlx"})
CONDA_VERBS = frozenset({"install", "create", "update"})
CARGO_VERBS = frozenset({"install", "add"})
GEM_VERBS = frozenset({"install"})
GO_VERBS = frozenset({"get", "install"})
RUN_WORD = "run"


@dataclass(frozen=True)
class Detected:
    """One install found in the command text.

    tool is the base name of the installing command (pip, npm, npx, uv, ...). It is empty when
    the text could not be read. args are its arguments after wrappers were removed.
    unverifiable is a reason when the hook must refuse the install whatever the verdict says.
    """

    tool: str
    args: tuple[str, ...] = ()
    unverifiable: str | None = None


@dataclass(frozen=True)
class Evaluation:
    """What the hook does: the exit code and the text for stderr. Stdout is never written."""

    exit_code: int
    stderr: str = ""


class _Scan:
    """Collects the installs found while the command text is walked left to right.

    taint is sticky. Once an environment assignment, an export, or xargs has been seen, every
    later install is unverifiable, because the command that runs may differ from the one the
    verdict covers (R-G-5).
    """

    def __init__(self) -> None:
        self.found: list[Detected] = []
        self.taint: str | None = None

    def hit(self, tool: str, args: Sequence[str], reason: str | None = None) -> bool:
        item = Detected(tool, tuple(args), reason or self.taint)
        if item not in self.found:
            self.found.append(item)
        return True


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _payload_commands(payload: Any) -> tuple[list[str], bool]:
    """Return the shell text to check, and whether it is the command Kiro will run.

    The text is tool_input.command when it is a string. Otherwise it is every string in the
    payload, and the flag is False: an install found there cannot be tied to a command.
    """
    if isinstance(payload, dict):
        tool_input = payload.get("tool_input")
        if isinstance(tool_input, dict):
            command = tool_input.get("command")
            if isinstance(command, str):
                return [command], True
    return list(_strings(payload)), False


def _base(token: str) -> str:
    name = token.rsplit("/", 1)[-1].lower()
    return name[: -len(".exe")] if name.endswith(".exe") else name


def _is_assignment(token: str) -> bool:
    return _ASSIGNMENT.match(token) is not None


def _positionals(args: list[str]) -> list[str]:
    return [arg for arg in args if not arg.startswith("-")]


def _leading(args: list[str], count: int) -> list[str]:
    return _positionals(args)[:count]


def _is_separator(token: str) -> bool:
    # "<(" and ">(" start a process substitution, so they separate commands too.
    return token.endswith("(") or (bool(token) and set(token) <= SEPARATOR_CHARS)


def scan_command(text: str) -> list[Detected]:
    """Return every install in shell text. An empty list means the text has no install."""
    scan = _Scan()
    _blocked_text(text, 0, scan)
    return scan.found


def _blocked_text(text: str, depth: int, scan: _Scan) -> bool:
    """True when any simple command in shell text installs a package, or the text is unparseable.

    Every True comes with at least one Detected record in the scan.
    """
    if depth > MAX_DEPTH:
        return _unreadable(scan)
    # Backticks and newlines separate commands in the shell, so treat them as ";".
    normalized = text.replace("`", " ; ").replace("\r", " ; ").replace("\n", " ; ")
    lexer = shlex.shlex(normalized, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""  # A "#" inside a word is not a comment for the shell.
    try:
        tokens = list(lexer)
    except ValueError:
        return _unreadable(scan)  # Unclosed quote: the command cannot be read, so it is blocked.

    segments: list[list[str]] = [[]]
    skip_redirect_target = False
    for token in tokens:
        if skip_redirect_target and not _is_separator(token):
            skip_redirect_target = False
            continue
        skip_redirect_target = False
        if _is_separator(token):
            segments.append([])
        elif REDIRECT_CHARS & set(token):
            skip_redirect_target = True
        elif token:
            segments[-1].append(token)
    # Walk every segment, in order: a later segment may be tainted by an earlier one.
    results = [_blocked_argv(segment, depth, scan) for segment in segments if segment]
    return any(results)


def _unreadable(scan: _Scan) -> bool:
    return scan.hit("", (), UNREADABLE_REASON)


def _blocked_argv(tokens: list[str], depth: int, scan: _Scan, expand_run: bool = True) -> bool:
    """Check one simple command, after stripping wrappers, VAR=val, and shell keywords."""
    if depth > MAX_DEPTH:
        return _unreadable(scan)
    index = 0
    count = len(tokens)
    while index < count:
        token = tokens[index]
        base = _base(token)
        if _is_assignment(token) or base in KEYWORDS:
            if _is_assignment(token):
                scan.taint = ASSIGNMENT_REASON
            index += 1
            continue
        if base in WRAPPERS:
            index += 1
            if base == "xargs":
                scan.taint = XARGS_REASON
            arg_options = WRAPPER_ARG_OPTIONS.get(base, frozenset())
            while index < count and (
                tokens[index].startswith("-") or _is_assignment(tokens[index])
            ):
                option = tokens[index]
                index += 1
                if _is_assignment(option):
                    scan.taint = ASSIGNMENT_REASON
                if option == "--":
                    break
                if base == "env" and option.startswith("-S") and len(option) > 2:
                    # `env -S "pip install x"` splits its own string, so check that string.
                    return _blocked_text(option[2:], depth + 1, scan)
                if base == "env" and option in {"-S", "--split-string"} and index < count:
                    return _blocked_text(tokens[index], depth + 1, scan)
                if option in arg_options:
                    index += 1
            continue
        break
    if index >= count:
        return False
    return _blocked_command(tokens[index:], depth, expand_run, scan)


def _blocked_command(argv: list[str], depth: int, expand_run: bool, scan: _Scan) -> bool:
    name = _base(argv[0])
    args = argv[1:]

    if name in ENV_BUILTINS:
        scan.taint = ASSIGNMENT_REASON
        return False

    if name in SHELLS:
        blocked = False
        for position, arg in enumerate(args):
            is_c_flag = arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]
            if is_c_flag and position + 1 < len(args):
                blocked = _blocked_text(args[position + 1], depth + 1, scan) or blocked
        return blocked

    if _PYTHON.fullmatch(name):
        for position, arg in enumerate(args):
            if arg == "-m" and position + 1 < len(args) and args[position + 1] == "pip":
                return _blocked_command(["pip", *args[position + 2 :]], depth + 1, expand_run, scan)
            if arg == "-mpip":
                return _blocked_command(["pip", *args[position + 1 :]], depth + 1, expand_run, scan)
        return False

    if _PIP.fullmatch(name):
        return _hit_if(any(word in PIP_VERBS for word in _positionals(args)), scan, "pip", args)
    if _EASY_INSTALL.fullmatch(name):
        return scan.hit("easy_install", args)
    if name in {"npx", "uvx"}:
        return scan.hit(name, args)
    if name == "pipx":
        lead = _leading(args, 1)
        return _hit_if(bool(lead) and lead[0] in PIPX_VERBS, scan, name, args)
    if name == "uv":
        return _uv_blocked(args, depth, expand_run, scan)
    if name == "poetry":
        return _wrapper_blocked(name, args, POETRY_VERBS, depth, expand_run, scan)
    if name == "pdm":
        return _wrapper_blocked(name, args, PDM_VERBS, depth, expand_run, scan)
    if name == "pipenv":
        return _wrapper_blocked(name, args, PIPENV_VERBS, depth, expand_run, scan)
    if name in {"conda", "mamba", "micromamba"}:
        return _hit_if(any(word in CONDA_VERBS for word in _positionals(args)), scan, name, args)
    if name in {"npm", "pnpm", "yarn"}:
        return _hit_if(_node_blocked(args), scan, name, args)
    if name == "cargo":
        return _hit_if(any(word in CARGO_VERBS for word in _positionals(args)), scan, name, args)
    if name == "gem":
        return _hit_if(any(word in GEM_VERBS for word in _positionals(args)), scan, name, args)
    if name == "go":
        lead = _leading(args, 1)
        return _hit_if(bool(lead) and lead[0] in GO_VERBS, scan, name, args)
    return False


def _hit_if(is_install: bool, scan: _Scan, tool: str, args: list[str]) -> bool:
    return scan.hit(tool, args) if is_install else False


def _node_blocked(args: list[str]) -> bool:
    positionals = _positionals(args)
    if positionals[:1] in (["run"], ["run-script"]):
        # `npm run build` is a script, not an install. Only a script named as an installer counts.
        return len(positionals) > 1 and positionals[1] in NODE_INSTALL_VERBS
    return any(word in NODE_INSTALL_VERBS | NODE_EXEC_VERBS for word in positionals)


def _wrapper_blocked(
    name: str,
    args: list[str],
    verbs: frozenset[str],
    depth: int,
    expand_run: bool,
    scan: _Scan,
) -> bool:
    """Tools with install verbs and a `run` form that executes another command."""
    lead = _leading(args, 2)
    if any(word in verbs for word in lead):
        return scan.hit(name, args)
    if expand_run and RUN_WORD in lead:
        return _run_suffix_blocked(args[args.index(RUN_WORD) + 1 :], depth, scan)
    return False


def _uv_blocked(args: list[str], depth: int, expand_run: bool, scan: _Scan) -> bool:
    if any(arg.startswith("--with") for arg in args):
        return scan.hit("uv", args)
    positionals = _positionals(args)
    lead = positionals[:2]
    if any(word in UV_VERBS for word in lead):
        return scan.hit("uv", args)
    for position, word in enumerate(lead):
        follow = positionals[position + 1] if position + 1 < len(positionals) else ""
        if word == "pip" and follow in {"install", "sync"}:
            return scan.hit("uv", args)
        if word == "tool" and follow in {"install", "run"}:
            return scan.hit("uv", args)
    if expand_run and RUN_WORD in lead:
        return _run_suffix_blocked(args[args.index(RUN_WORD) + 1 :], depth, scan)
    return False


def _run_suffix_blocked(tokens: list[str], depth: int, scan: _Scan) -> bool:
    """Check every start: options can come before the command in `uv run --python 3.12 pip`."""
    results = [
        _blocked_argv(tokens[start:], depth + 1, scan, expand_run=False)
        for start in range(len(tokens))
    ]
    return any(results)


def _read_stdin(timeout: float) -> tuple[str | None, bool]:
    """Read stdin in a thread so a stalled writer cannot hang the hook.

    Returns (text, stalled). text is None when stdin is unreadable. stalled is True when the
    read did not finish within the timeout.
    """
    received: list[bytes] = []

    def reader() -> None:
        received.append(sys.stdin.buffer.read())

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return None, True
    if not received:
        return None, False
    try:
        return received[0].decode("utf-8"), False
    except UnicodeDecodeError:
        return None, False


def _blocked() -> Evaluation:
    return Evaluation(BLOCK_EXIT, BLOCK_MESSAGE + "\n")


Decide = Callable[[Sequence[Detected]], Evaluation]


def evaluate(raw: str | None, decide: Decide | None = None) -> Evaluation:
    """Decide what the hook does for one payload. `decide` is the gate, replaceable in tests."""
    if raw is None:
        return _blocked()
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        return _blocked()
    texts, is_command = _payload_commands(payload)
    if not texts:
        # No command text at all means the hook cannot tell what the tool will run.
        return _blocked()
    found: list[Detected] = []
    for text in texts:
        found.extend(scan_command(text))
    if not found:
        return Evaluation(ALLOW_EXIT)
    if not is_command:
        found = [Detected(item.tool, item.args, NO_COMMAND_REASON) for item in found]
    if decide is None:
        from slopseal.hooks.gate import decide as gate_decide

        decide = gate_decide
    return decide(found)


def _evaluate_in_worker(raw: str | None) -> Evaluation | None:
    """Run evaluate in a thread with a deadline. None means no result: block.

    A worker that raises ends without a result, so any error becomes a block (R-G-6) without
    a bare `except Exception` here (tech.md).
    """
    result: list[Evaluation] = []

    def worker() -> None:
        result.append(evaluate(raw))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(DEADLINE_SECONDS)
    if thread.is_alive():
        # Still running. A normal exit would wait on the thread, so the caller exits at once.
        raise TimeoutError
    return result[0] if result else None


def main() -> int:
    raw, stalled = _read_stdin(STDIN_TIMEOUT_SECONDS)
    if stalled:
        # The reader thread still holds stdin. A normal exit would abort in interpreter shutdown,
        # so flush the message and exit at once with the block code.
        return _exit_now()
    try:
        evaluation = _evaluate_in_worker(raw)
    except TimeoutError:
        return _exit_now()
    if evaluation is None:
        evaluation = _blocked()
    sys.stderr.write(evaluation.stderr)
    return evaluation.exit_code


def _exit_now() -> NoReturn:
    sys.stderr.write(BLOCK_MESSAGE + "\n")
    sys.stderr.flush()
    os._exit(BLOCK_EXIT)


if __name__ == "__main__":
    sys.exit(main())
