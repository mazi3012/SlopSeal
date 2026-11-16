"""PreToolUse hook: block agent shell commands that install packages.

Kiro writes the hook payload as JSON on stdin. If any string in the payload contains a pip,
npm, npx, or python -m pip install command, the hook exits 2. Kiro documents exit 2 as the
block for PreToolUse, and it returns stderr to the agent, so the agent sees the reason.

This hook does not verify packages. Verification runs in the PATH shim
(src/slopseal/intercept/path_shim.py). The hook stops agent-issued installs, which would
otherwise bypass the shim. See docs/THREAT_MODEL.md, T11.

Fail closed: a payload that is not JSON also blocks, because the hook cannot prove the command
is safe. Exit 0 means no install command was found.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from typing import Any

INSTALL_COMMAND = re.compile(
    r"\b(pip3?|npm|npx|pnpm|yarn|cargo|gem)\s+(install|i|add|exec|x)\b"
    r"|\bnpx\s"
    r"|\bgo\s+get\b"
    r"|\bpython3?\s+-m\s+pip\s+install\b"
)
BLOCK_EXIT = 2


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _block(reason: str) -> None:
    print(f"slopseal: {reason}", file=sys.stderr)


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        _block("the hook payload could not be read, so the command is blocked.")
        return BLOCK_EXIT

    if any(INSTALL_COMMAND.search(text) for text in _strings(payload)):
        _block(
            "this command installs packages, and agents may not install directly. "
            "Ask the user to run the install in a shell where the SlopSeal shim is on PATH, "
            "so every package is verified first."
        )
        return BLOCK_EXIT
    return 0


if __name__ == "__main__":
    sys.exit(main())
