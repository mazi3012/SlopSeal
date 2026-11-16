"""PreToolUse hook: block agent shell commands that install packages (T11, R-1.1).

Kiro writes the hook payload as JSON on stdin. The install check reads only
tool_input.command, the text the shell will run. It does not scan description or cwd.
If that key is missing or not a string, every string in the payload is scanned instead.

The check looks at command positions, not at raw text. It splits the command into simple
commands at &&, ||, ;, |, &, parentheses, backticks, and newlines. It strips wrappers such as
sudo, env, VAR=val, nohup, and xargs, and it recurses into shell strings such as
`bash -c "..."`. A package manager named in an argument, such as `echo "pip install x"`,
does not block.

Exit 2 blocks. The hook also blocks when the payload cannot be read, when stdin does not
close within 3 seconds, when the command cannot be parsed, or when shell nesting is too deep.
The hook does not verify packages. Verification runs in the PATH shim
(src/slopseal/intercept/path_shim.py) or in the slopseal MCP tool, which the block message
names. Known limit: a script file, or `python -c`, that runs
an install is not inspected.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import threading
from collections.abc import Iterator
from typing import Any

BLOCK_EXIT = 2
STDIN_TIMEOUT_SECONDS = 3.0
MAX_DEPTH = 8

BLOCK_MESSAGE = (
    "BLOCKED by SlopSeal: Direct installs are disabled. You must use the slopseal MCP tool "
    "to verify the package first."
)

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


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _payload_commands(payload: Any) -> list[str]:
    """Return the shell text to check: tool_input.command, or every string if it is missing."""
    if isinstance(payload, dict):
        tool_input = payload.get("tool_input")
        if isinstance(tool_input, dict):
            command = tool_input.get("command")
            if isinstance(command, str):
                return [command]
    return list(_strings(payload))


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


def _blocked_text(text: str, depth: int) -> bool:
    """True when any simple command in shell text installs a package, or the text is unparseable."""
    if depth > MAX_DEPTH:
        return True
    # Backticks and newlines separate commands in the shell, so treat them as ";".
    normalized = text.replace("`", " ; ").replace("\r", " ; ").replace("\n", " ; ")
    lexer = shlex.shlex(normalized, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""  # A "#" inside a word is not a comment for the shell.
    try:
        tokens = list(lexer)
    except ValueError:
        return True  # Unclosed quote: the command cannot be read, so it is blocked.

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
    return any(_blocked_argv(segment, depth) for segment in segments if segment)


def _blocked_argv(tokens: list[str], depth: int, expand_run: bool = True) -> bool:
    """Check one simple command, after stripping wrappers, VAR=val, and shell keywords."""
    if depth > MAX_DEPTH:
        return True
    index = 0
    count = len(tokens)
    while index < count:
        token = tokens[index]
        base = _base(token)
        if _is_assignment(token) or base in KEYWORDS:
            index += 1
            continue
        if base in WRAPPERS:
            index += 1
            arg_options = WRAPPER_ARG_OPTIONS.get(base, frozenset())
            while index < count and (
                tokens[index].startswith("-") or _is_assignment(tokens[index])
            ):
                option = tokens[index]
                index += 1
                if option == "--":
                    break
                if base == "env" and option.startswith("-S") and len(option) > 2:
                    # `env -S "pip install x"` splits its own string, so check that string.
                    return _blocked_text(option[2:], depth + 1)
                if base == "env" and option in {"-S", "--split-string"} and index < count:
                    return _blocked_text(tokens[index], depth + 1)
                if option in arg_options:
                    index += 1
            continue
        break
    if index >= count:
        return False
    return _blocked_command(tokens[index:], depth, expand_run)


def _blocked_command(argv: list[str], depth: int, expand_run: bool) -> bool:
    name = _base(argv[0])
    args = argv[1:]

    if name in SHELLS:
        blocked = False
        for position, arg in enumerate(args):
            is_c_flag = arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]
            if is_c_flag and position + 1 < len(args):
                blocked = _blocked_text(args[position + 1], depth + 1) or blocked
        return blocked

    if _PYTHON.fullmatch(name):
        for position, arg in enumerate(args):
            if arg == "-m" and position + 1 < len(args) and args[position + 1] == "pip":
                return _blocked_command(["pip", *args[position + 2 :]], depth + 1, expand_run)
            if arg == "-mpip":
                return _blocked_command(["pip", *args[position + 1 :]], depth + 1, expand_run)
        return False

    if _PIP.fullmatch(name):
        return any(word in PIP_VERBS for word in _positionals(args))
    if _EASY_INSTALL.fullmatch(name) or name in {"npx", "uvx"}:
        return True
    if name == "pipx":
        lead = _leading(args, 1)
        return bool(lead) and lead[0] in PIPX_VERBS
    if name == "uv":
        return _uv_blocked(args, depth, expand_run)
    if name == "poetry":
        return _wrapper_blocked(args, POETRY_VERBS, depth, expand_run)
    if name == "pdm":
        return _wrapper_blocked(args, PDM_VERBS, depth, expand_run)
    if name == "pipenv":
        return _wrapper_blocked(args, PIPENV_VERBS, depth, expand_run)
    if name in {"conda", "mamba", "micromamba"}:
        return any(word in CONDA_VERBS for word in _positionals(args))
    if name in {"npm", "pnpm", "yarn"}:
        return _node_blocked(args)
    if name == "cargo":
        return any(word in CARGO_VERBS for word in _positionals(args))
    if name == "gem":
        return any(word in GEM_VERBS for word in _positionals(args))
    if name == "go":
        lead = _leading(args, 1)
        return bool(lead) and lead[0] in GO_VERBS
    return False


def _node_blocked(args: list[str]) -> bool:
    positionals = _positionals(args)
    if positionals[:1] in (["run"], ["run-script"]):
        # `npm run build` is a script, not an install. Only a script named as an installer counts.
        return len(positionals) > 1 and positionals[1] in NODE_INSTALL_VERBS
    return any(word in NODE_INSTALL_VERBS | NODE_EXEC_VERBS for word in positionals)


def _wrapper_blocked(args: list[str], verbs: frozenset[str], depth: int, expand_run: bool) -> bool:
    """Tools with install verbs and a `run` form that executes another command."""
    lead = _leading(args, 2)
    if any(word in verbs for word in lead):
        return True
    if expand_run and RUN_WORD in lead:
        return _run_suffix_blocked(args[args.index(RUN_WORD) + 1 :], depth)
    return False


def _uv_blocked(args: list[str], depth: int, expand_run: bool) -> bool:
    if any(arg.startswith("--with") for arg in args):
        return True
    positionals = _positionals(args)
    lead = positionals[:2]
    if any(word in UV_VERBS for word in lead):
        return True
    for position, word in enumerate(lead):
        follow = positionals[position + 1] if position + 1 < len(positionals) else ""
        if word == "pip" and follow in {"install", "sync"}:
            return True
        if word == "tool" and follow in {"install", "run"}:
            return True
    if expand_run and RUN_WORD in lead:
        return _run_suffix_blocked(args[args.index(RUN_WORD) + 1 :], depth)
    return False


def _run_suffix_blocked(tokens: list[str], depth: int) -> bool:
    """Check every start: options can come before the command in `uv run --python 3.12 pip`."""
    return any(
        _blocked_argv(tokens[start:], depth + 1, expand_run=False) for start in range(len(tokens))
    )


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


def _block() -> int:
    print(BLOCK_MESSAGE, file=sys.stderr)
    return BLOCK_EXIT


def main() -> int:
    raw, stalled = _read_stdin(STDIN_TIMEOUT_SECONDS)
    if stalled:
        # The reader thread still holds stdin. A normal exit would abort in interpreter shutdown,
        # so flush the message and exit at once with the block code.
        _block()
        sys.stderr.flush()
        os._exit(BLOCK_EXIT)
    if raw is None:
        return _block()
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        return _block()
    texts = _payload_commands(payload)
    if not texts:
        # No command text at all means the hook cannot tell what the tool will run.
        return _block()
    if any(_blocked_text(text, 0) for text in texts):
        return _block()
    return 0


if __name__ == "__main__":
    sys.exit(main())
