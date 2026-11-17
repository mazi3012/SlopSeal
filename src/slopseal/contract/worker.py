"""Archive safety check, run as a subprocess with resource limits (R-C-4). Standard library only.

Invoked as:
    python -I worker.py <kind> <path> <max_expanded> <max_members> <max_package_json>
                        <cpu_seconds> <address_bytes> <open_files>

`kind` is `wheel` (a zip) or `npm` (a gzip tarball). This module imports nothing from slopseal.
It reads archive members into memory, one at a time, and never writes them to disk. It never
imports, executes, or compiles anything from the artifact, and it never runs an install script
(R-C-1, P-C-1). Its output is one JSON object on stdout:

    {"status": "ok", "root": "<dir>"}
    {"status": "unknown", "reason": "<typed reason>", "detail": "<short text>"}

Checks: member names (absolute, `..`, NUL, backslash, duplicate), links, devices, and fifos
rejected before any member is read; member count; expanded bytes counted after decompression.
For npm, the root is the directory of the shallowest package.json. A tie or a missing file is an
error.

Requirements: R-C-4, R-C-3 (root selection). Property: P-C-5.
"""

from __future__ import annotations

import json
import stat
import sys
import tarfile
import zipfile
from typing import IO

CHUNK = 1 << 16


class Unsafe(Exception):
    """An unsafe or malformed archive. Reason parse_error."""


class Limit(Exception):
    """A limit was reached. Reason limit."""


def _emit(obj: dict[str, str]) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")


def _check_name(name: str) -> None:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or any(part == ".." for part in name.split("/"))
    ):
        raise Unsafe("unsafe member name")


def _consume(stream: IO[bytes], budget: list[int], max_package_json: int, keep: bool) -> bytes:
    """Read a member to the end, counting bytes against the expanded budget."""
    kept = bytearray()
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            break
        budget[0] -= len(chunk)
        if budget[0] < 0:
            raise Limit("expanded size is larger than the limit")
        if keep:
            kept.extend(chunk)
            if len(kept) > max_package_json:
                raise Limit("package.json is larger than the limit")
    return bytes(kept)


def check_zip(
    path: str, max_expanded: int, max_members: int, max_package_json: int
) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > max_members:
            raise Limit("member count is larger than the limit")
        seen: set[str] = set()
        budget = [max_expanded]
        for info in infos:
            _check_name(info.filename)
            if info.filename in seen:
                raise Unsafe("duplicate member name")
            seen.add(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and (
                stat.S_ISLNK(mode)
                or stat.S_ISCHR(mode)
                or stat.S_ISBLK(mode)
                or stat.S_ISFIFO(mode)
                or stat.S_ISSOCK(mode)
            ):
                raise Unsafe("link or special file member")
            if info.is_dir():
                continue
            with archive.open(info) as stream:
                _consume(stream, budget, max_package_json, keep=False)
    return {"status": "ok", "root": ""}


def check_npm(
    path: str, max_expanded: int, max_members: int, max_package_json: int
) -> dict[str, str]:
    manifests: list[tuple[str, bytes]] = []
    with tarfile.open(path, "r:*") as archive:
        seen: set[str] = set()
        budget = [max_expanded]
        count = 0
        for member in archive:
            count += 1
            if count > max_members:
                raise Limit("member count is larger than the limit")
            _check_name(member.name)
            if member.name in seen:
                raise Unsafe("duplicate member name")
            seen.add(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise Unsafe("link or special file member")
            if member.isdir():
                continue
            if not member.isreg():
                raise Unsafe("unsupported member type")
            stream = archive.extractfile(member)
            if stream is None:
                raise Unsafe("member has no data")
            with stream:
                is_manifest = member.name.rsplit("/", 1)[-1] == "package.json"
                data = _consume(stream, budget, max_package_json, keep=is_manifest)
            if is_manifest:
                manifests.append((member.name, data))
    if not manifests:
        raise Unsafe("no package.json in the archive")
    shallowest = min(name.count("/") for name, _ in manifests)
    at_depth = [(name, data) for name, data in manifests if name.count("/") == shallowest]
    if len(at_depth) != 1:
        raise Unsafe("ambiguous package.json root")
    name, data = at_depth[0]
    json.loads(data.decode("utf-8"))  # must parse; a bad manifest is malformed
    root = name.rsplit("/", 1)[0] if "/" in name else ""
    return {"status": "ok", "root": root}


def _apply_limits(cpu: int, address: int, open_files: int) -> str | None:
    """Set resource limits before any archive is opened. Returns a detail if they cannot be set."""
    try:
        import resource
    except ImportError:
        return "resource limits are not available on this platform"
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (address, address))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (open_files, open_files))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        return "resource limits could not be set"
    return None


def main(argv: list[str]) -> int:
    kind, path = argv[0], argv[1]
    max_expanded, max_members, max_package_json = int(argv[2]), int(argv[3]), int(argv[4])
    cpu, address, open_files = int(argv[5]), int(argv[6]), int(argv[7])
    limit_detail = _apply_limits(cpu, address, open_files)
    if limit_detail is not None:
        _emit({"status": "unknown", "reason": "limit", "detail": limit_detail})
        return 0
    try:
        if kind == "wheel":
            result = check_zip(path, max_expanded, max_members, max_package_json)
        elif kind == "npm":
            result = check_npm(path, max_expanded, max_members, max_package_json)
        else:
            raise Unsafe("unknown artifact kind")
    except Limit as exc:
        _emit({"status": "unknown", "reason": "limit", "detail": str(exc)})
        return 0
    except Unsafe as exc:
        _emit({"status": "unknown", "reason": "parse_error", "detail": str(exc)})
        return 0
    except (
        OSError,
        zipfile.BadZipFile,
        tarfile.TarError,
        RuntimeError,
        NotImplementedError,
        ValueError,
        UnicodeDecodeError,
    ):
        _emit({"status": "unknown", "reason": "parse_error", "detail": "archive could not be read"})
        return 0
    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
