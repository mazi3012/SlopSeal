"""Archive checks and Python export extraction, run as a subprocess with resource limits.

Standard library only. This module imports nothing from slopseal: it runs as a separate program
with `python -I`, which drops the script directory from sys.path, so it cannot import a sibling.

Invoked as one of:
    python -I worker.py <kind> <path> <max_expanded> <max_members> <max_package_json>
                        <cpu_seconds> <address_bytes> <open_files>
    python -I worker.py extract <kind> <path> <max_file_bytes> <max_names>
                        <cpu_seconds> <address_bytes> <open_files>

`kind` is `wheel` (a zip) or `npm` (a gzip tarball). The check mode reads archive members into
memory, one at a time, and never writes them to disk. The extract mode (R-C-2) reads the wheel's
module files and parses them with `ast`. Neither mode imports, executes, or compiles anything from
the artifact, and neither runs an install script (R-C-1, P-C-1). Output is one JSON object on
stdout:

    {"status": "ok", "root": "<dir>"}
    {"status": "complete", "exports": ["<name>", ...]}
    {"status": "unknown", "reason": "<typed reason>", "detail": "<short text>"}

Checks: member names (absolute, `..`, NUL, backslash, duplicate), links, devices, and fifos
rejected before any member is read; member count; expanded bytes counted after decompression.
For npm, the root is the directory of the shallowest package.json. A tie or a missing file is an
error.

Requirements: R-C-2, R-C-4, R-C-3 (root selection). Property: P-C-4, P-C-5, P-C-8.
"""

from __future__ import annotations

import ast
import csv
import io
import json
import re
import stat
import sys
import tarfile
import zipfile
from collections.abc import Iterator, Mapping
from typing import IO

CHUNK = 1 << 16
MAX_NAME_LENGTH = 256
_NAME_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f]")
# Builtins whose use can change a module's names at run time (R-C-2, Q1).
_DYNAMIC_CALLS = frozenset({"exec", "eval", "setattr", "globals", "vars"})
_DYNAMIC_ATTRS = frozenset({"__dict__", "modules"})
_TRY_TYPES: tuple[type, ...] = (ast.Try, ast.TryStar)
_MODULE_STATEMENTS: tuple[type, ...] = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Import,
    ast.ImportFrom,
    ast.Expr,
    ast.Pass,
    ast.Assert,
    ast.Raise,
    ast.Assign,
    ast.AnnAssign,
    ast.AugAssign,
    ast.If,
) + _TRY_TYPES


class Unsafe(Exception):
    """An unsafe or malformed archive. Reason parse_error."""


class Limit(Exception):
    """A limit was reached. Reason limit."""


class Dynamic(Exception):
    """A form that can change the export set at run time, or an unmodelled form. dynamic_exports."""


def _emit(obj: Mapping[str, object]) -> None:
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


# ---- Python export extraction (R-C-2) -------------------------------------------------------


def _valid_name(name: str) -> bool:
    return 0 < len(name) <= MAX_NAME_LENGTH and _NAME_FORBIDDEN.search(name) is None


def _public(name: str) -> bool:
    return not name.startswith("_")


def _installed_path(member: str) -> str | None:
    """Where a wheel member is installed, or None when it is not importable Python (R-C-2).

    `*.dist-info/` is metadata. `*.data/` is installed only from its purelib and platlib parts.
    Everything else is installed at its own path.
    """
    parts = member.split("/")
    if parts[0].endswith(".dist-info"):
        return None
    if parts[0].endswith(".data"):
        if len(parts) > 2 and parts[1] in ("purelib", "platlib"):
            return "/".join(parts[2:])
        return None
    return member


def _module_name(installed: str) -> tuple[str, bool]:
    """The dotted module name of an installed .py or .pyi path, and whether it is a package."""
    stem = installed.rsplit(".", 1)[0]
    package = stem == "__init__" or stem.endswith("/__init__")
    if package:
        stem = stem[: -len("__init__")].rstrip("/")
    parts = stem.split("/") if stem else []
    if not parts or not all(part.isidentifier() for part in parts):
        raise Unsafe("module layout is not handled")
    return ".".join(parts), package


def _record_paths(
    archive: zipfile.ZipFile, infos: dict[str, zipfile.ZipInfo], limit: int
) -> set[str]:
    """The paths listed in the single `*.dist-info/RECORD` of the wheel (R-C-2)."""
    records = [
        name
        for name in infos
        if name.count("/") == 1
        and name.split("/")[0].endswith(".dist-info")
        and name.split("/")[1] == "RECORD"
    ]
    if len(records) != 1:
        raise Unsafe("a wheel needs exactly one RECORD file")
    with archive.open(infos[records[0]]) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise Limit("RECORD is larger than the limit")
    try:
        text = raw.decode("utf-8")
        return {row[0] for row in csv.reader(io.StringIO(text)) if row}
    except (UnicodeDecodeError, csv.Error) as exc:
        raise Unsafe("RECORD cannot be read") from exc


def _literal_strings(node: ast.expr) -> list[str] | None:
    """The strings of a literal list or tuple of string constants, or None for anything else."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    values: list[str] = []
    for element in node.elts:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            return None
        values.append(element.value)
    return values


def _module_level(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Statements that run at import time: the module body and every branch of if and try."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, ast.If):
            yield from _module_level(stmt.body)
            yield from _module_level(stmt.orelse)
        elif isinstance(stmt, (ast.Try, ast.TryStar)):
            yield from _module_level(stmt.body)
            for handler in stmt.handlers:
                yield from _module_level(handler.body)
            yield from _module_level(stmt.orelse)
            yield from _module_level(stmt.finalbody)


def _check_forms(tree: ast.Module) -> None:
    """Raise Dynamic for every form that R-C-2 lists as dynamic, anywhere in the file.

    `__all__` is read only as the target of a plain or annotated literal assignment (ruled at 2.6).
    Every other use of the name gives Dynamic: an alias, `+=`, `.extend`, `.append`, a call
    argument, a computed value. A module-level Name write at run time (Q1), a module-level loop or
    tuple target, and a `__getattr__` or `__dir__` also give Dynamic.
    """
    literal_targets: set[int] = set()
    for stmt in _module_level(tree.body):
        if not isinstance(stmt, _MODULE_STATEMENTS):
            raise Dynamic("module-level statement is not modelled")
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name in ("__getattr__", "__dir__"):
                raise Dynamic("module-level __getattr__ or __dir__")
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, (ast.Tuple, ast.List, ast.Starred)):
                    raise Dynamic("tuple target at module level")
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if _literal_strings(stmt.value) is None:
                        raise Dynamic("__all__ is computed")
                    literal_targets.add(id(target))
        elif isinstance(stmt, ast.AnnAssign):
            target = stmt.target
            if isinstance(target, ast.Name) and target.id == "__all__":
                if stmt.value is None or _literal_strings(stmt.value) is None:
                    raise Dynamic("__all__ is annotated without a literal value")
                literal_targets.add(id(target))
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            raise Dynamic("augmented assignment to a module name")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id in _DYNAMIC_CALLS:
                raise Dynamic("reference to a builtin that changes names at run time")
            if node.id == "__all__" and id(node) not in literal_targets:
                raise Dynamic("__all__ is read or changed outside a literal assignment")
        elif isinstance(node, ast.Attribute):
            if node.attr in _DYNAMIC_ATTRS:
                raise Dynamic("reference to a module namespace")
            value_name = node.value.id if isinstance(node.value, ast.Name) else ""
            if value_name == "builtins" and node.attr in _DYNAMIC_CALLS:
                raise Dynamic("reference to a builtin that changes names at run time")
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name in _DYNAMIC_CALLS | _DYNAMIC_ATTRS for alias in node.names):
                raise Dynamic("import of a builtin that changes names at run time")
        elif isinstance(node, ast.Global):
            raise Dynamic("global statement in a module file")
        elif isinstance(node, ast.Delete):
            if any(isinstance(target, ast.Name) for target in node.targets):
                raise Dynamic("del of a module name")
        elif isinstance(node, ast.NamedExpr):
            raise Dynamic("assignment expression binds a name the model does not follow")


class _Module:
    """The names one module file can bind, and its star imports."""

    def __init__(self, package: bool) -> None:
        self.package = package
        self.names: set[str] = set()
        self.stars: list[tuple[int, str]] = []


def _collect(tree: ast.Module, module: _Module) -> None:
    """Set A (a literal `__all__` assignment, underscores kept) and set B (public bindings).

    Only a literal assignment of `__all__` reaches here: _check_forms has already refused every
    other use of the name.
    """
    for stmt in _module_level(tree.body):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if _public(stmt.name):
                module.names.add(stmt.name)
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound = alias.asname or alias.name.split(".")[0]
                if _public(bound):
                    module.names.add(bound)
        elif isinstance(stmt, ast.ImportFrom):
            if stmt.module == "__future__":
                continue
            for alias in stmt.names:
                if alias.name == "*":
                    module.stars.append((stmt.level, stmt.module or ""))
                    continue
                bound = alias.asname or alias.name
                if _public(bound):
                    module.names.add(bound)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    if target.id == "__all__":
                        module.names.update(_literal_strings(stmt.value) or [])
                    elif _public(target.id):
                        module.names.add(target.id)
        elif isinstance(stmt, ast.AnnAssign):
            target = stmt.target
            if isinstance(target, ast.Name):
                if target.id == "__all__" and stmt.value is not None:
                    module.names.update(_literal_strings(stmt.value) or [])
                elif target.id != "__all__" and _public(target.id):
                    module.names.add(target.id)


def _star_target(module: str, package: bool, level: int, target: str, known: set[str]) -> str:
    """The module a star import reads. It must be inside the artifact (R-C-2)."""
    if level == 0:
        resolved = target
    else:
        parts = module.split(".") if module else []
        base = parts if package else parts[:-1]
        up = level - 1
        if up > len(base):
            raise Dynamic("relative star import goes above the package")
        base = base[: len(base) - up]
        resolved = ".".join(base + ([target] if target else []))
    if not resolved or resolved not in known:
        raise Dynamic("star import target is outside the artifact")
    return resolved


def _export_names(modules: dict[str, _Module]) -> set[str]:
    """Qualified names for every module, bare names for top-level modules, and module paths."""
    known = set(modules)
    names: set[str] = set()
    for name, module in modules.items():
        exported = set(module.names)
        for level, target in module.stars:
            source = modules[_star_target(name, module.package, level, target, known)]
            if source.stars:
                raise Dynamic("star import of a module that itself has a star import")
            exported |= source.names
        names.add(name)
        for symbol in exported:
            names.add(f"{name}.{symbol}")
            if "." not in name:
                names.add(symbol)
    return names


def extract_wheel(path: str, max_file_bytes: int, max_names: int) -> list[str]:
    """The export names of a wheel. Parses with ast only. Raises Dynamic, Limit, or Unsafe."""
    with zipfile.ZipFile(path) as archive:
        infos = {info.filename: info for info in archive.infolist()}
        listed = _record_paths(archive, infos, max_file_bytes)
        modules: dict[str, _Module] = {}
        for member in infos:
            installed = _installed_path(member)
            if installed is None:
                continue
            if installed.endswith((".so", ".pyd")):
                raise Dynamic("compiled extension module: its names are not read")
            if not installed.endswith((".py", ".pyi")):
                continue
            if member not in listed:
                raise Unsafe("importable file is not listed in RECORD")
            module_name, package = _module_name(installed)
            with archive.open(infos[member]) as stream:
                data = stream.read(max_file_bytes + 1)
            if len(data) > max_file_bytes:
                raise Limit("source file is larger than the limit")
            tree = ast.parse(data, filename=member)
            _check_forms(tree)
            module = modules.setdefault(module_name, _Module(package))
            if module.package != package:
                raise Unsafe("a module is both a package and a plain module")
            _collect(tree, module)
        for member in listed:
            if member.endswith((".py", ".pyi")) and member not in infos:
                raise Unsafe("RECORD lists a module that is not in the wheel")
    if not modules:
        raise Unsafe("wheel has no importable module")
    names = _export_names(modules)
    if len(names) > max_names:
        raise Limit("export count is larger than the limit")
    for name in names:
        if not _valid_name(name):
            raise Unsafe("export name fails the name check")
    return sorted(names)


# ---- entry point ----------------------------------------------------------------------------


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


def _main_extract(argv: list[str]) -> int:
    kind, path = argv[0], argv[1]
    max_file_bytes, max_names = int(argv[2]), int(argv[3])
    cpu, address, open_files = int(argv[4]), int(argv[5]), int(argv[6])
    limit_detail = _apply_limits(cpu, address, open_files)
    if limit_detail is not None:
        _emit({"status": "unknown", "reason": "limit", "detail": limit_detail})
        return 0
    try:
        if kind != "wheel":
            raise Unsafe("extraction is implemented for wheels only")
        names = extract_wheel(path, max_file_bytes, max_names)
    except Dynamic as exc:
        _emit({"status": "unknown", "reason": "dynamic_exports", "detail": str(exc)})
        return 0
    except Limit as exc:
        _emit({"status": "unknown", "reason": "limit", "detail": str(exc)})
        return 0
    except MemoryError:
        _emit({"status": "unknown", "reason": "limit", "detail": "memory limit reached"})
        return 0
    except Unsafe as exc:
        _emit({"status": "unknown", "reason": "parse_error", "detail": str(exc)})
        return 0
    except (
        OSError,
        zipfile.BadZipFile,
        SyntaxError,
        ValueError,
        RecursionError,
        KeyError,
        IndexError,
    ):
        _emit({"status": "unknown", "reason": "parse_error", "detail": "module could not be read"})
        return 0
    _emit({"status": "complete", "exports": names})
    return 0


def _main_check(argv: list[str]) -> int:
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
    except MemoryError:
        _emit({"status": "unknown", "reason": "limit", "detail": "memory limit reached"})
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


def main(argv: list[str]) -> int:
    if argv and argv[0] == "extract":
        return _main_extract(argv[1:])
    return _main_check(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
