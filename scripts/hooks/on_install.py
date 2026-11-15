"""PreToolUse hook: stop a shell command that installs packages until the user confirms it.

Reads the hook payload (JSON) from stdin and searches every string in it for an install
command. When one is found, the hook returns `permissionDecision: ask`, so the user decides.

Verification is not wired yet. The `verify_install` entry point arrives in Phase 4, so the
hook cannot yet give a verdict. Asking is the fail-closed stand-in. An unreadable payload
also asks, because the hook cannot prove the command is safe.

Exit code is always 0. The decision is in the JSON on stdout.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from typing import Any

INSTALL_COMMAND = re.compile(
    r"\b(pip3?|npm|pnpm|yarn|cargo|gem)\s+(install|i|add)\b"
    r"|\bgo\s+get\b"
    r"|\bpython3?\s+-m\s+pip\s+install\b"
)


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _ask(reason: str) -> None:
    decision = {
        "hookSpecificOutput": {
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(decision))


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        _ask("SlopSeal could not read the hook payload, so this command needs confirmation.")
        return 0

    matches = [text for text in _strings(payload) if INSTALL_COMMAND.search(text)]
    if matches:
        _ask(
            "This command installs packages. SlopSeal verification is not wired yet "
            "(Phase 4), so confirm the install is intended before it runs."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
