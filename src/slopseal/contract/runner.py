"""Run the worker in a subprocess with resource limits (R-C-2, R-C-4). POSIX only.

The worker gets an empty environment, no stdin, the artifact's private directory as its working
directory, and its own process group. It is killed after the wall-time limit. A worker killed by a
signal (wall time, CPU, memory, or file size) gives ContractUnknown with reason limit. A non-zero
exit without a limit kill, or output that is not the expected JSON, gives parse_error. The parent
re-validates the worker's root before it trusts it (R-C-4).

Windows is out of scope for this phase (design 2.5).

Requirements: R-C-2, R-C-4. Layer 1 (adapter). Standard library only.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from slopseal.contract.limits import (
    DETAIL_MAX_CHARS,
    MAX_COMPRESSED_BYTES,
    MAX_CONTRACT_NAMES,
    MAX_EXPANDED_BYTES,
    MAX_MEMBERS,
    SOURCE_FILE_MAX_BYTES,
    WORKER_ADDRESS_SPACE_BYTES,
    WORKER_OPEN_FILES,
    WORKER_OUTPUT_MAX_BYTES,
    WORKER_WALL_SECONDS,
)
from slopseal.contract.types import ContractComplete, ContractUnknown, UnknownReason

WORKER = Path(__file__).with_name("worker.py")
# The deadline of the artifact being checked. Unset outside wall_budget (R-C-4).
_DEADLINE: ContextVar[float | None] = ContextVar("slopseal_worker_deadline", default=None)
KINDS = frozenset({"wheel", "npm"})


@dataclass(frozen=True)
class ArchiveOk:
    """The archive passed the safety check. `root` is the npm package root, or "" for a wheel."""

    root: str


@contextmanager
def wall_budget(seconds: float = WORKER_WALL_SECONDS) -> Iterator[None]:
    """One wall-time budget for the worker runs of one artifact (R-C-4).

    The archive check and the extraction both run inside it, so together they get `seconds`.
    """
    token = _DEADLINE.set(time.monotonic() + seconds)
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def _time_left(timeout: float) -> float | None:
    """The timeout for one run: the smaller of `timeout` and the time left, or None."""
    deadline = _DEADLINE.get()
    if deadline is None:
        return timeout
    left = deadline - time.monotonic()
    return min(timeout, left) if left > 0 else None


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _short(text: str) -> str:
    return text[:DETAIL_MAX_CHARS]


def _root_inside(root: str, private_dir: Path) -> bool:
    """The worker's root must be relative and must resolve inside the private directory (R-C-4)."""
    if not root:
        return True
    if root.startswith("/") or "\\" in root or "\x00" in root:
        return False
    if any(part == ".." for part in root.split("/")):
        return False
    base = private_dir.resolve()
    target = (private_dir / root).resolve()
    return target == base or base in target.parents


def _invoke(tail: list[str], artifact: Path, timeout: float, what: str) -> bytes | ContractUnknown:
    """Run the worker with `tail` as its arguments. Returns its stdout, or the typed unknown."""
    argv = [sys.executable, "-I", str(WORKER), *tail]
    limit = _time_left(timeout)
    if limit is None:
        return ContractUnknown(UnknownReason.LIMIT, f"{what} had no wall time left")
    process = subprocess.Popen(  # noqa: S603 - argv is built here from constants and our path; no shell
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
        cwd=str(artifact.parent),
        close_fds=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        _kill_group(process)
        process.communicate()
        return ContractUnknown(UnknownReason.LIMIT, f"{what} exceeded its wall time")
    if len(output) > WORKER_OUTPUT_MAX_BYTES:
        return ContractUnknown(UnknownReason.LIMIT, f"{what} output is larger than the limit")
    if process.returncode < 0:
        return ContractUnknown(UnknownReason.LIMIT, f"{what} was stopped by a limit")
    if process.returncode != 0:
        return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} failed")
    return output


def _message(output: bytes, what: str) -> dict[str, Any] | ContractUnknown:
    """The worker's JSON object, or a parse_error. An unknown status is returned as its reason."""
    try:
        message = json.loads(output)
    except ValueError:
        return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} output is malformed")
    if not isinstance(message, dict):
        return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} output is malformed")
    if message.get("status") == "unknown":
        try:
            reason = UnknownReason(message.get("reason"))
        except ValueError:
            return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} gave an unknown reason")
        detail = message.get("detail")
        partial = message.get("partial", [])
        if not isinstance(partial, list) or not all(isinstance(name, str) for name in partial):
            return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} gave invalid partial names")
        try:
            return ContractUnknown(
                reason, _short(detail if isinstance(detail, str) else ""), tuple(partial)
            )
        except ValueError:
            return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} gave invalid partial names")
    return message


def run_archive_check(
    artifact: Path, kind: str, *, timeout: float = WORKER_WALL_SECONDS
) -> ArchiveOk | ContractUnknown:
    if os.name != "posix":
        return ContractUnknown(UnknownReason.LIMIT, "archive checks need POSIX resource limits")
    if kind not in KINDS:
        raise ValueError("unknown artifact kind")
    if artifact.stat().st_size > MAX_COMPRESSED_BYTES:
        return ContractUnknown(UnknownReason.LIMIT, "artifact is larger than the compressed limit")
    tail = [
        kind,
        str(artifact),
        str(MAX_EXPANDED_BYTES),
        str(MAX_MEMBERS),
        str(SOURCE_FILE_MAX_BYTES),
        str(int(WORKER_WALL_SECONDS)),
        str(WORKER_ADDRESS_SPACE_BYTES),
        str(WORKER_OPEN_FILES),
    ]
    what = "archive check"
    output = _invoke(tail, artifact, timeout, what)
    if isinstance(output, ContractUnknown):
        return output
    message = _message(output, what)
    if isinstance(message, ContractUnknown):
        return message
    if message.get("status") == "ok" and isinstance(message.get("root"), str):
        root = message["root"]
        if not _root_inside(root, artifact.parent):
            return ContractUnknown(
                UnknownReason.PARSE_ERROR, "archive root is outside the artifact directory"
            )
        return ArchiveOk(root)
    return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} output is malformed")


def run_extract(
    artifact: Path, kind: str, root: str = "", *, timeout: float = WORKER_WALL_SECONDS
) -> ContractComplete | ContractUnknown:
    """The export names of an artifact, from the worker's extract mode (R-C-2, R-C-3).

    `root` is the package root that the archive check selected (npm), or "" for a wheel.
    """
    if os.name != "posix":
        return ContractUnknown(UnknownReason.LIMIT, "extraction needs POSIX resource limits")
    if kind not in KINDS:
        raise ValueError("unknown artifact kind")
    tail = [
        "extract",
        kind,
        str(artifact),
        root,
        str(SOURCE_FILE_MAX_BYTES),
        str(MAX_CONTRACT_NAMES),
        str(int(WORKER_WALL_SECONDS)),
        str(WORKER_ADDRESS_SPACE_BYTES),
        str(WORKER_OPEN_FILES),
    ]
    what = "extraction"
    output = _invoke(tail, artifact, timeout, what)
    if isinstance(output, ContractUnknown):
        return output
    message = _message(output, what)
    if isinstance(message, ContractUnknown):
        return message
    exports = message.get("exports")
    if message.get("status") == "complete" and isinstance(exports, list):
        try:
            return ContractComplete(tuple(exports))
        except (TypeError, ValueError):
            return ContractUnknown(UnknownReason.PARSE_ERROR, "extraction gave invalid names")
    return ContractUnknown(UnknownReason.PARSE_ERROR, f"{what} output is malformed")
