"""Run the archive worker in a subprocess with resource limits (R-C-4). POSIX only.

The worker gets an empty environment, no stdin, the artifact's private directory as its working
directory, and its own process group. It is killed after the wall-time limit. Any limit gives
ContractUnknown with reason limit. Malformed output or a non-zero exit gives parse_error.

Windows is out of scope for this phase (design 2.5).

Requirements: R-C-4. Layer 1 (adapter). Standard library only.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from slopseal.contract.limits import (
    DETAIL_MAX_CHARS,
    MAX_COMPRESSED_BYTES,
    MAX_EXPANDED_BYTES,
    MAX_MEMBERS,
    SOURCE_FILE_MAX_BYTES,
    WORKER_ADDRESS_SPACE_BYTES,
    WORKER_OPEN_FILES,
    WORKER_OUTPUT_MAX_BYTES,
    WORKER_WALL_SECONDS,
)
from slopseal.contract.types import ContractUnknown, UnknownReason

WORKER = Path(__file__).with_name("worker.py")
KINDS = frozenset({"wheel", "npm"})


@dataclass(frozen=True)
class ArchiveOk:
    """The archive passed the safety check. `root` is the npm package root, or "" for a wheel."""

    root: str


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _short(text: str) -> str:
    return text[:DETAIL_MAX_CHARS]


def run_archive_check(
    artifact: Path, kind: str, *, timeout: float = WORKER_WALL_SECONDS
) -> ArchiveOk | ContractUnknown:
    if os.name != "posix":
        return ContractUnknown(UnknownReason.LIMIT, "archive checks need POSIX resource limits")
    if kind not in KINDS:
        raise ValueError("unknown artifact kind")
    if artifact.stat().st_size > MAX_COMPRESSED_BYTES:
        return ContractUnknown(UnknownReason.LIMIT, "artifact is larger than the compressed limit")
    argv = [
        sys.executable,
        "-I",
        str(WORKER),
        kind,
        str(artifact),
        str(MAX_EXPANDED_BYTES),
        str(MAX_MEMBERS),
        str(SOURCE_FILE_MAX_BYTES),
        str(int(WORKER_WALL_SECONDS)),
        str(WORKER_ADDRESS_SPACE_BYTES),
        str(WORKER_OPEN_FILES),
    ]
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
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(process)
        process.communicate()
        return ContractUnknown(UnknownReason.LIMIT, "archive check exceeded its wall time")
    if len(output) > WORKER_OUTPUT_MAX_BYTES:
        return ContractUnknown(UnknownReason.LIMIT, "archive check output is larger than the limit")
    if process.returncode < 0:
        return ContractUnknown(UnknownReason.LIMIT, "archive check was stopped by a limit")
    if process.returncode != 0:
        return ContractUnknown(UnknownReason.PARSE_ERROR, "archive check failed")
    try:
        message = json.loads(output)
    except ValueError:
        return ContractUnknown(UnknownReason.PARSE_ERROR, "archive check output is malformed")
    if not isinstance(message, dict):
        return ContractUnknown(UnknownReason.PARSE_ERROR, "archive check output is malformed")
    if message.get("status") == "ok" and isinstance(message.get("root"), str):
        return ArchiveOk(message["root"])
    if message.get("status") == "unknown":
        try:
            reason = UnknownReason(message.get("reason"))
        except ValueError:
            return ContractUnknown(
                UnknownReason.PARSE_ERROR, "archive check gave an unknown reason"
            )
        detail = message.get("detail")
        return ContractUnknown(reason, _short(detail if isinstance(detail, str) else ""))
    return ContractUnknown(UnknownReason.PARSE_ERROR, "archive check output is malformed")
