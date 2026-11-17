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
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import IO, Any

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
    """Qualified names for every module, bare names for top-level modules, and submodule paths."""
    known = set(modules)
    names: set[str] = set()
    for name, module in modules.items():
        exported = set(module.names)
        for level, target in module.stars:
            source = modules[_star_target(name, module.package, level, target, known)]
            if source.stars:
                raise Dynamic("star import of a module that itself has a star import")
            exported |= source.names
        if "." in name:
            names.add(
                name
            )  # a submodule path is a name; the root package's own name is not (R-C-2)
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


# ---- npm export extraction (R-C-3) ----------------------------------------------------------
#
# A tokenizer and a token-level matcher for the modelled forms. There is no JavaScript parser in
# the standard library, so every rule here is a token pattern, and anything that is not a pattern
# gives Dynamic. The tokenizer raises TokError when it cannot finish; the caller maps that to
# parse_error.


class TokError(Exception):
    """The tokenizer cannot finish: an unterminated token, or a slash it cannot classify."""


@dataclass(frozen=True)
class _Tok:
    kind: str  # "id", "str", "num", "re", or "p"
    value: str
    nl: bool  # a line break comes before this token
    regex_after: bool = False  # for ")": a slash after it starts a regular expression


_JS_EXTS = (".js", ".cjs", ".mjs")
_DTS_EXTS = (".d.ts", ".d.mts", ".d.cts")
_CONDITIONS = frozenset({"import", "require", "node", "default", "types"})
_REGEX_AFTER_WORDS = frozenset(
    {
        "return",
        "typeof",
        "instanceof",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "case",
        "do",
        "else",
        "yield",
        "await",
    }
)
_HELPERS = frozenset({"__export", "__exportStar", "__reExport", "__createBinding"})
_PUNCTUATORS = sorted(
    [
        ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
        "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=",
        "*=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
        "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "%", "&",
        "|", "^", "!", "~", "?", ":", "=", ".", "@", "#",
    ],
    key=len,
    reverse=True,
)  # fmt: skip
_IDENT = re.compile(r"(?:[^\W\d]|\$)[\w$]*")
_NUMBER = re.compile(r"(?:\d|\.\d)[\w.]*")
_WS = frozenset(" \t\r\n\f\v\ufeff\u00a0\u2028\u2029")
_LINE_BREAKS = frozenset("\r\n\u2028\u2029")


def _template_piece(text: str, j: int) -> tuple[int, str]:
    """Scan template text from j. Returns (index after it, "end" or "sub")."""
    n = len(text)
    while True:
        if j >= n:
            raise TokError("unterminated template literal")
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "`":
            return j + 1, "end"
        if text.startswith("${", j):
            return j + 2, "sub"
        j += 1


def _regex_allowed(toks: list[_Tok]) -> bool:
    if not toks:
        return True
    prev = toks[-1]
    if prev.kind == "id":
        return prev.value in _REGEX_AFTER_WORDS
    if prev.kind in ("str", "num", "re"):
        return False
    if prev.value == ")":
        return prev.regex_after
    if prev.value == "}":
        raise TokError("a slash after a closing brace cannot be classified")
    return prev.value not in ("]", "++", "--")


def tokenize(text: str) -> list[_Tok]:
    """Tokens of a JavaScript or TypeScript file. Comments are dropped. Strings and template text
    are kept as one token each, with no value that matters to the rules. Regular expressions are
    one token. Raises TokError when a token does not end, or a slash cannot be classified."""
    toks: list[_Tok] = []
    braces: list[str] = []  # "{" or "T" (a template substitution)
    parens: list[bool] = []  # per open "(": preceded by if, while, for, or with
    n = len(text)
    i = 0
    nl = False
    if text.startswith("#!"):
        while i < n and text[i] not in _LINE_BREAKS:
            i += 1
    while i < n:
        c = text[i]
        if c in _WS:
            if c in _LINE_BREAKS:
                nl = True
            i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] not in _LINE_BREAKS:
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise TokError("unterminated block comment")
            if "\n" in text[i:end] or "\r" in text[i:end]:
                nl = True
            i = end + 2
            continue
        if c in "'\"":
            j = i + 1
            while True:
                if j >= n or text[j] in _LINE_BREAKS:
                    raise TokError("unterminated string literal")
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    break
                j += 1
            toks.append(_Tok("str", text[i + 1 : j], nl))
            nl = False
            i = j + 1
            continue
        if c == "`" or (c == "}" and braces and braces[-1] == "T"):
            if c == "}":
                # The closing brace of a substitution is a real token, so brace depth stays exact.
                braces.pop()
                toks.append(_Tok("p", "}", nl))
                nl = False
            j, piece = _template_piece(text, i + 1)
            if piece == "end":
                toks.append(_Tok("str", "", nl))
            else:
                toks.append(_Tok("p", "${", nl))
                braces.append("T")
            nl = False
            i = j
            continue
        if c == "/":
            if _regex_allowed(toks):
                j = i + 1
                in_class = False
                while True:
                    if j >= n or text[j] in _LINE_BREAKS:
                        raise TokError("unterminated regular expression")
                    ch = text[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if in_class:
                        if ch == "]":
                            in_class = False
                    elif ch == "[":
                        in_class = True
                    elif ch == "/":
                        break
                    j += 1
                j += 1
                while j < n and (text[j].isalnum() or text[j] in "_$"):
                    j += 1
                toks.append(_Tok("re", "", nl))
                nl = False
                i = j
                continue
            if text.startswith("/=", i):
                toks.append(_Tok("p", "/=", nl))
                i += 2
            else:
                toks.append(_Tok("p", "/", nl))
                i += 1
            nl = False
            continue
        if c == "_" or c == "$" or c.isalpha():
            m = _IDENT.match(text, i)
            if m is None:  # pragma: no cover - the character class above guarantees a match
                raise TokError("bad identifier")
            toks.append(_Tok("id", m.group(0), nl))
            nl = False
            i = m.end()
            continue
        if c.isdigit() or (c == "." and i + 1 < n and text[i + 1].isdigit()):
            m = _NUMBER.match(text, i)
            if m is None:  # pragma: no cover
                raise TokError("bad number")
            toks.append(_Tok("num", m.group(0), nl))
            nl = False
            i = m.end()
            continue
        for punct in _PUNCTUATORS:
            if text.startswith(punct, i):
                if punct == "?." and i + 2 < n and text[i + 2].isdigit():
                    continue
                break
        else:
            raise TokError("unexpected character")
        if punct == "{":
            braces.append("{")
        elif punct == "}":
            if braces:
                braces.pop()
        elif punct == "(":
            previous = toks[-1] if toks else None
            parens.append(
                previous is not None
                and previous.kind == "id"
                and previous.value in ("if", "while", "for", "with")
            )
        elif punct == ")":
            flag = parens.pop() if parens else False
            toks.append(_Tok("p", ")", nl, regex_after=flag))
            nl = False
            i += 1
            continue
        toks.append(_Tok("p", punct, nl))
        nl = False
        i += len(punct)
    return toks


def _is_p(toks: list[_Tok], k: int, value: str) -> bool:
    return k < len(toks) and toks[k].kind == "p" and toks[k].value == value


def _is_id(toks: list[_Tok], k: int, value: str | None = None) -> bool:
    return k < len(toks) and toks[k].kind == "id" and (value is None or toks[k].value == value)


def _after_dot(toks: list[_Tok], k: int) -> bool:
    return k > 0 and _is_p(toks, k - 1, ".")


def _name_token(toks: list[_Tok], k: int) -> str:
    """An identifier or a string used as a name, or Dynamic."""
    if k < len(toks) and toks[k].kind in ("id", "str"):
        return toks[k].value
    raise Dynamic("a name the model does not follow")


def _object_literal(toks: list[_Tok], b: int, names: set[str]) -> int:
    """Parse `{ ... }` at b (a module.exports literal, Q2 and Q5). Returns the index after it."""
    n = len(toks)
    j = b + 1
    while True:
        if j >= n:
            raise Dynamic("module.exports literal is not closed")
        if _is_p(toks, j, "}"):
            j += 1
            break
        tok = toks[j]
        if tok.kind not in ("id", "str"):
            raise Dynamic("a computed key, a spread, or another form in module.exports")
        key = tok.value
        if tok.kind == "id" and key in ("exports", "module"):
            raise Dynamic("exports or module used inside the literal")
        if key == "default":
            raise Dynamic("a key named default is not a rule that adds default (Q4)")
        if _is_p(toks, j + 1, ":"):
            k = j + 2
            depth = 0
            while True:
                if k >= n:
                    raise Dynamic("module.exports literal is not closed")
                value_tok = toks[k]
                if value_tok.kind == "p" and value_tok.value == "${":
                    raise Dynamic("a template substitution inside module.exports")
                if value_tok.kind == "id" and value_tok.value in ("exports", "module"):
                    raise Dynamic("exports or module used inside the literal")
                if value_tok.kind == "p" and value_tok.value in ("(", "[", "{"):
                    depth += 1
                elif value_tok.kind == "p" and value_tok.value in (")", "]", "}"):
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0 and value_tok.kind == "p" and value_tok.value == ",":
                    break
                k += 1
            names.add(key)
            j = k
        elif tok.kind == "id" and (_is_p(toks, j + 1, ",") or _is_p(toks, j + 1, "}")):
            names.add(key)
            j += 1
        else:
            raise Dynamic("a method, an accessor, or another form in module.exports")
        if _is_p(toks, j, ","):
            j += 1
            continue
        if _is_p(toks, j, "}"):
            continue
        raise Dynamic("module.exports literal is not well formed")
    # The statement must end here: a semicolon, end of file, or a new line that starts a statement.
    if j < n:
        tail = toks[j]
        if not (
            (tail.kind == "p" and tail.value in (";", "}"))
            or (tail.nl and tail.kind in ("id", "str", "num", "re"))
        ):
            raise Dynamic("module.exports literal is part of a larger expression")
    return j


def _declarator_has_list(toks: list[_Tok], k: int) -> bool:
    """True when a top-level comma follows at k, before the statement ends (multi-declarator)."""
    depth = 0
    n = len(toks)
    while k < n:
        tok = toks[k]
        if tok.kind == "p" and tok.value in ("(", "[", "{", "${"):
            depth += 1
        elif tok.kind == "p" and tok.value in (")", "]", "}"):
            if depth == 0:
                return False
            depth -= 1
        elif depth == 0 and tok.kind == "p" and tok.value == ";":
            return False
        elif depth == 0 and tok.kind == "p" and tok.value == ",":
            return True
        elif depth == 0 and tok.nl and tok.kind == "id" and k > 0 and tok.value in _STATEMENT_WORDS:
            return False
        k += 1
    return False


_STATEMENT_WORDS = frozenset({"export", "import", "const", "let", "var", "function", "class"})


def _export_list(toks: list[_Tok], j: int, names: set[str], *, relative_only: bool) -> int:
    """`{ a, b as c } [from "./x"]` starting at the "{" at j. Returns the index after the list."""
    n = len(toks)
    if not _is_p(toks, j, "{"):
        raise Dynamic("an export list must start with {")
    j += 1
    while True:
        if j >= n:
            raise Dynamic("export list is not closed")
        if _is_p(toks, j, "}"):
            j += 1
            break
        exported = _name_token(toks, j)
        j += 1
        if _is_id(toks, j, "as"):
            exported = _name_token(toks, j + 1)
            j += 2
        if exported == "default":
            raise Dynamic("an export list that names default (Q4 is only export default)")
        names.add(exported)
        if _is_p(toks, j, ","):
            j += 1
        elif not _is_p(toks, j, "}"):
            raise Dynamic("export list is not well formed")
    if _is_id(toks, j, "from"):
        if j + 1 >= n or toks[j + 1].kind != "str":
            raise Dynamic("export from needs a string")
        spec = toks[j + 1].value
        if relative_only and not spec.startswith(("./", "../")):
            raise Dynamic("a re-export from a bare package name is not modelled")
        j += 2
    return j


def _analyze_js(toks: list[_Tok], read_star: Callable[[str], set[str]] | None) -> set[str]:
    """Names of one JavaScript entry under the accounted-for rule. Raises Dynamic on any gap."""
    names: set[str] = set()
    consumed: set[int] = set()
    n = len(toks)
    depths = _brace_depths(toks)
    for i, tok in enumerate(toks):
        if i in consumed or tok.kind != "id":
            continue
        value = tok.value
        if value in _HELPERS:
            raise Dynamic(f"bundler helper {value} (Q5)")
        if value == "this" and depths[i] == 0:
            raise Dynamic("a top-level this is module.exports in CommonJS")
        if value == "export" and not _after_dot(toks, i):
            consumed |= _esm_export(toks, i, names, read_star)
            continue
        if (
            value == "Object"
            and _is_p(toks, i + 1, ".")
            and _is_id(toks, i + 2, "defineProperty")
            and _is_p(toks, i + 3, "(")
            and _is_id(toks, i + 4, "exports")
            and _is_p(toks, i + 5, ",")
            and i + 6 < n
            and toks[i + 6].kind == "str"
            and toks[i + 6].value == "__esModule"
        ):
            close = _matching_close(toks, i + 3)
            for k in range(i + 7, close):
                if toks[k].kind == "id" and toks[k].value in ("exports", "module"):
                    raise Dynamic("exports used in the __esModule call")
            consumed |= set(range(i, close + 1))
            continue
        head = None
        is_module = False
        if value == "exports" and not _after_dot(toks, i):
            head = i
        elif (
            value == "module"
            and not _after_dot(toks, i)
            and _is_p(toks, i + 1, ".")
            and _is_id(toks, i + 2, "exports")
        ):
            head = i + 2
            is_module = True
        else:
            if value in ("exports", "module"):
                raise Dynamic("exports or module in a form the model does not follow")
            continue
        if _is_p(toks, head + 1, "="):
            if is_module and _is_p(toks, head + 2, "{"):
                end = _object_literal(toks, head + 2, names)
                consumed |= set(range(i, end))
                continue
            raise Dynamic(
                "module.exports is assigned a value that is not a plain object literal (Q2, Q3)"
            )
        if _is_p(toks, head + 1, ".") and _is_id(toks, head + 2) and _is_p(toks, head + 3, "="):
            names.add(toks[head + 2].value)  # Q4: `default` is a plain name here
            consumed |= set(range(i, head + 4))
            continue
        raise Dynamic("exports or module read or changed in a form the model does not follow")
    return names


def _brace_depths(toks: list[_Tok]) -> list[int]:
    """The brace depth before each token. A "${" opens a depth, and its "}" closes it."""
    depths: list[int] = []
    depth = 0
    for tok in toks:
        if tok.kind == "p" and tok.value == "}":
            depth = max(depth - 1, 0)
        depths.append(depth)
        if tok.kind == "p" and tok.value in ("{", "${"):
            depth += 1
    return depths


def _matching_close(toks: list[_Tok], open_index: int) -> int:
    depth = 0
    for k in range(open_index, len(toks)):
        if toks[k].kind == "p" and toks[k].value in ("(", "[", "{", "${"):
            depth += 1
        elif toks[k].kind == "p" and toks[k].value in (")", "]", "}"):
            depth -= 1
            if depth == 0:
                return k
    raise Dynamic("unclosed call")


def _esm_export(
    toks: list[_Tok], i: int, names: set[str], read_star: Callable[[str], set[str]] | None
) -> set[int]:
    """One ESM export statement at i. Adds its names. Returns the token indices it consumed."""
    n = len(toks)
    if _is_id(toks, i + 1, "default"):
        names.add("default")
        return {i, i + 1}
    if _is_p(toks, i + 1, "{"):
        end = _export_list(toks, i + 1, names, relative_only=True)
        if _is_p(toks, end, ";"):
            end += 1
        return set(range(i, end))
    if _is_p(toks, i + 1, "*"):
        if not (_is_id(toks, i + 2, "from") and i + 3 < n and toks[i + 3].kind == "str"):
            raise Dynamic("export * as, or an export * without from, is not modelled")
        spec = toks[i + 3].value
        if not spec.startswith(("./", "../")):
            raise Dynamic("export * from a bare package name is not modelled")
        if read_star is None:
            raise Dynamic("export * from a second hop (R-C-3)")
        names.update(read_star(spec))
        end = i + 4
        if _is_p(toks, end, ";"):
            end += 1
        return set(range(i, end))
    if _is_id(toks, i + 1, "const") or _is_id(toks, i + 1, "let") or _is_id(toks, i + 1, "var"):
        if not _is_id(toks, i + 2):
            raise Dynamic("a destructuring export is not modelled")
        if _declarator_has_list(toks, i + 3):
            raise Dynamic("more than one declarator in an export is not modelled")
        names.add(toks[i + 2].value)
        return {i, i + 1, i + 2}
    k = i + 1
    if _is_id(toks, k, "async") and _is_id(toks, k + 1, "function"):
        k += 1
    if _is_id(toks, k, "function"):
        k += 1
        if _is_p(toks, k, "*"):
            k += 1
        if not _is_id(toks, k):
            raise Dynamic("an anonymous export function is not modelled")
        names.add(toks[k].value)
        return set(range(i, k + 1))
    if _is_id(toks, k, "class") and _is_id(toks, k + 1):
        names.add(toks[k + 1].value)
        return {i, k, k + 1}
    raise Dynamic("an export form that is not modelled")


def _analyze_dts(toks: list[_Tok], read_star: Callable[[str], set[str]] | None) -> set[str]:
    """Names of one declaration file (R-C-3, .d.ts). Raises Dynamic on any gap."""
    names: set[str] = set()
    n = len(toks)
    for i, tok in enumerate(toks):
        if tok.kind != "id":
            continue
        if tok.value == "declare" and _is_id(toks, i + 1, "module"):
            raise Dynamic("a declare module block is not modelled")
        if tok.value != "export" or _after_dot(toks, i):
            continue
        if _is_p(toks, i + 1, "="):
            raise Dynamic("export = is not modelled (Q3)")
        if _is_id(toks, i + 1, "as"):
            raise Dynamic("export as namespace is not modelled")
        if _is_p(toks, i + 1, "{"):
            _export_list(toks, i + 1, names, relative_only=True)
            continue
        if _is_p(toks, i + 1, "*"):
            if not (_is_id(toks, i + 2, "from") and i + 3 < n and toks[i + 3].kind == "str"):
                raise Dynamic("export * as is not modelled")
            spec = toks[i + 3].value
            if not spec.startswith(("./", "../")):
                raise Dynamic("export * from a bare package name is not modelled")
            if read_star is None:
                raise Dynamic("export * from a second hop (R-C-3)")
            names.update(read_star(spec))
            continue
        if _is_id(toks, i + 1, "default"):
            names.add("default")
            continue
        j = i + 1
        if _is_id(toks, j, "declare"):
            j += 1
        if _is_id(toks, j, "const") and _is_id(toks, j + 1, "enum"):
            j += 1
        if _is_id(toks, j, "abstract") and _is_id(toks, j + 1, "class"):
            j += 1
        keyword = toks[j].value if j < n and toks[j].kind == "id" else ""
        if keyword in _DTS_DECLARATIONS and _is_id(toks, j + 1):
            names.add(toks[j + 1].value)
            continue
        raise Dynamic("an export form that is not modelled in a declaration file")
    return names


_DTS_DECLARATIONS = frozenset(
    {"const", "let", "var", "function", "class", "interface", "type", "enum", "namespace"}
)


@dataclass(frozen=True)
class _Entry:
    spec: str  # the specifier: the package name, or name/subpath
    member: str  # the tarball member of the entry file
    root: bool  # the root entry: its symbols also get bare names
    dts: bool  # a declaration file


def _member_name(prefix: str, leaf: object) -> str:
    """The tarball member of a package-relative path, or Unsafe for an unsafe path (R-C-3)."""
    if not isinstance(leaf, str):
        raise Unsafe("entry is not a string")
    if leaf.startswith("/") or "\\" in leaf or "\x00" in leaf:
        raise Unsafe("unsafe entry path")
    parts = [part for part in leaf.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise Unsafe("unsafe entry path")
    return "/".join(([prefix] if prefix else []) + parts)


def _leaf_is_dts(leaf: str) -> bool:
    if leaf.endswith(_DTS_EXTS):
        return True
    if leaf.endswith(_JS_EXTS):
        return False
    raise Dynamic("an entry that is neither JavaScript nor a declaration file")


def _leaves(target: object) -> list[str]:
    """The leaf strings of an exports target: strings, fallback lists, and condition objects."""
    if target is None:
        return []
    if isinstance(target, str):
        return [target]
    if isinstance(target, list):
        found: list[str] = []
        for item in target:
            found.extend(_leaves(item))
        return found
    if isinstance(target, dict):
        found = []
        for key, value in target.items():
            if not isinstance(key, str) or "*" in key or key not in _CONDITIONS:
                raise Dynamic("a condition or pattern the model does not resolve")
            found.extend(_leaves(value))
        return found
    raise Unsafe("exports target has an unexpected type")


def _subpaths(exports: object) -> dict[str, object]:
    if isinstance(exports, (str, list)):
        return {".": exports}
    if isinstance(exports, dict):
        if all(isinstance(key, str) and key.startswith(".") for key in exports):
            return dict(exports)
        if any(isinstance(key, str) and key.startswith(".") for key in exports):
            raise Unsafe("exports mixes subpaths and conditions")
        return {".": exports}
    raise Unsafe("exports has an unexpected type")


# Probe order for an extensionless declared path (R-C-3, ruled at the 2.14 review).
_JS_PROBES = (".js", ".cjs", ".mjs")
_DTS_PROBES = (".d.ts",)


def _resolve_entries(manifest: dict[str, Any], prefix: str, present: set[str]) -> list[_Entry]:
    """The entry points of the package (R-C-3, entry points). `present` holds the tarball members.

    A declared main, module, types, or typings path with no extension is probed in a fixed order.
    A path that no probe finds is an entry that is missing from the tarball, so it gives
    parse_error for that entry only.
    """
    if "typesVersions" in manifest:
        raise Dynamic("typesVersions is not modelled")
    name = manifest.get("name")
    if not isinstance(name, str) or not name:
        raise Unsafe("package.json has no name")
    entries: dict[str, _Entry] = {}

    def add(spec: str, leaf: str, root: bool) -> None:
        member = _member_name(prefix, leaf)
        entries.setdefault(member, _Entry(spec, member, root, _leaf_is_dts(leaf)))

    exports = manifest.get("exports")
    if exports is not None:
        for subpath, target in _subpaths(exports).items():
            if "*" in subpath:
                raise Dynamic("a wildcard subpath is not modelled")
            spec = name if subpath == "." else f"{name}/{subpath[2:]}"
            for leaf in _leaves(target):
                add(spec, leaf, subpath == ".")
    else:
        for field in ("module", "main", "types", "typings"):
            value = manifest.get(field)
            if value == "":
                continue  # an empty string is absent, as Node treats it (R-C-3)
            if value is not None:
                if not isinstance(value, str):
                    raise Unsafe(f"{field} is not a string")
                _add_declared(name, value, field, entries, present, prefix)
        if not entries:
            add(name, "index.js", True)
    if not entries:
        raise Unsafe("no entry point")
    return list(entries.values())


def _add_declared(
    spec: str,
    leaf: str,
    field: str,
    entries: dict[str, _Entry],
    present: set[str],
    prefix: str,
) -> None:
    """One declared main, module, types, or typings path (R-C-3, extensionless probes)."""
    declared_dts = field in ("types", "typings")
    if "." in leaf.rsplit("/", 1)[-1]:
        member = _member_name(prefix, leaf)
        entries.setdefault(member, _Entry(spec, member, True, _leaf_is_dts(leaf)))
        return
    for extension in _DTS_PROBES if declared_dts else _JS_PROBES:
        member = _member_name(prefix, leaf + extension)
        if member in present:
            entries.setdefault(member, _Entry(spec, member, True, declared_dts))
            return
    missing = _member_name(prefix, leaf)  # not in the tarball: analysed as parse_error
    entries.setdefault(missing, _Entry(spec, missing, True, declared_dts))


def _join_inside(prefix: str, base: str, relative: str) -> str:
    """A path relative to base, kept inside the package prefix (R-C-3). Otherwise Dynamic."""
    parts = base.split("/") if base else []
    for segment in relative.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not parts:
                raise Dynamic("a relative star import leaves the package")
            parts.pop()
        else:
            parts.append(segment)
    target = "/".join(parts)
    if prefix and not (target == prefix or target.startswith(prefix + "/")):
        raise Dynamic("a relative star import leaves the package")
    return target


def _read_member(archive: tarfile.TarFile, info: tarfile.TarInfo, max_file_bytes: int) -> bytes:
    stream = archive.extractfile(info)
    if stream is None:
        raise Unsafe("member has no data")
    with stream:
        data = stream.read(max_file_bytes + 1)
    if len(data) > max_file_bytes:
        raise Limit("source file is larger than the limit")
    return data


def _regular_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    """Regular files of the tarball, by normalized member name. Links and devices were refused
    by the archive check before this runs."""
    members: dict[str, tarfile.TarInfo] = {}
    for info in archive.getmembers():
        if info.isreg():
            members[info.name.removeprefix("./")] = info
    return members


def _analyze_member(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    member: str,
    max_file_bytes: int,
    prefix: str,
    allow_star: bool,
) -> set[str]:
    info = members.get(member)
    if info is None:
        raise Unsafe("an entry file is missing from the tarball")
    text = _read_member(archive, info, max_file_bytes).decode("utf-8")
    toks = tokenize(text)
    analyse = _analyze_dts if member.endswith(_DTS_EXTS) else _analyze_js
    base = member.rsplit("/", 1)[0] if "/" in member else ""

    def reader(relative: str) -> set[str]:
        target = _join_inside(prefix, base, relative)
        for candidate in (
            target,
            target + ".js",
            target + ".cjs",
            target + ".mjs",
            target + ".d.ts",
            target + "/index.js",
            target + "/index.d.ts",
        ):
            if candidate in members:
                return _analyze_member(
                    archive, members, candidate, max_file_bytes, prefix, allow_star=False
                )
        raise Dynamic("a star import target is outside the artifact")

    return analyse(toks, reader if allow_star else None)


def _entry_names(entry: _Entry, symbols: set[str]) -> set[str]:
    # The root package's own name is not an export name (R-C-3). A subpath specifier is.
    out: set[str] = set() if entry.root else {entry.spec}
    for symbol in symbols:
        out.add(f"{entry.spec}.{symbol}")
        if entry.root:
            out.add(symbol)
    return out


def extract_npm(path: str, root: str, max_file_bytes: int, max_names: int) -> dict[str, object]:
    """The contract of an npm artifact: complete, or UNKNOWN (with partial names for two entry
    points). Standard library only. Raises Unsafe, Limit, Dynamic, or TokError."""
    with tarfile.open(path, "r:*") as archive:
        members = _regular_members(archive)
        manifest_name = f"{root}/package.json" if root else "package.json"
        manifest_info = members.get(manifest_name)
        if manifest_info is None:
            raise Unsafe("no package.json at the selected root")
        manifest = json.loads(_read_member(archive, manifest_info, max_file_bytes).decode("utf-8"))
        if not isinstance(manifest, dict):
            raise Unsafe("package.json is not an object")
        entries = _resolve_entries(manifest, root, set(members))
        outcomes: list[tuple[_Entry, set[str] | None, tuple[str, str] | None]] = []
        for entry in entries:
            try:
                symbols = _analyze_member(
                    archive, members, entry.member, max_file_bytes, root, allow_star=True
                )
                outcomes.append((entry, symbols, None))
            except Dynamic as exc:
                outcomes.append((entry, None, ("dynamic_exports", str(exc))))
            except Limit as exc:
                outcomes.append((entry, None, ("limit", str(exc))))
            except (Unsafe, TokError, UnicodeDecodeError) as exc:
                outcomes.append((entry, None, ("parse_error", str(exc) or "entry cannot be read")))
    complete = [(entry, symbols) for entry, symbols, failed in outcomes if symbols is not None]
    names: set[str] = set()
    for entry, symbols in complete:
        names |= _entry_names(entry, symbols)
    if len(names) > max_names:
        raise Limit("export count is larger than the limit")
    if len(complete) == len(outcomes):
        return {"status": "complete", "exports": sorted(names)}
    if complete:
        # Two entry points, not all complete (R-C-3): the complete entries' names are kept.
        return {
            "status": "unknown",
            "reason": "dynamic_exports",
            "detail": "one entry point is not complete",
            "partial": sorted(names),
        }
    if len(outcomes) == 1:
        _, _, failed = outcomes[0]
        reason, detail = failed or ("parse_error", "entry cannot be read")
        return {"status": "unknown", "reason": reason, "detail": detail[:200]}
    return {
        "status": "unknown",
        "reason": "dynamic_exports",
        "detail": "no entry point is complete",
    }


# ---- entry point ----------------------------------------------------------------------------


def _apply_limits(cpu: int, address: int, open_files: int) -> str | None:
    """Set resource limits before any archive is opened. Returns a detail if they cannot be set."""
    try:
        import resource
    except ImportError:
        return "resource limits are not available on this platform"
    calls: tuple[tuple[str, int, tuple[int, int]], ...] = (
        ("RLIMIT_CPU", resource.RLIMIT_CPU, (cpu, cpu)),
        ("RLIMIT_AS", resource.RLIMIT_AS, (address, address)),
        ("RLIMIT_FSIZE", resource.RLIMIT_FSIZE, (0, 0)),
        ("RLIMIT_NOFILE", resource.RLIMIT_NOFILE, (open_files, open_files)),
        ("RLIMIT_CORE", resource.RLIMIT_CORE, (0, 0)),
    )
    for name, which, value in calls:
        try:
            resource.setrlimit(which, value)
        except (ValueError, OSError) as error:
            return f"resource limits could not be set: {name} {value}: {error}"
    return None


def _main_extract(argv: list[str]) -> int:
    kind, path, root = argv[0], argv[1], argv[2]
    max_file_bytes, max_names = int(argv[3]), int(argv[4])
    cpu, address, open_files = int(argv[5]), int(argv[6]), int(argv[7])
    limit_detail = _apply_limits(cpu, address, open_files)
    if limit_detail is not None:
        _emit({"status": "unknown", "reason": "limit", "detail": limit_detail})
        return 0
    try:
        if kind == "wheel":
            payload: dict[str, object] = {
                "status": "complete",
                "exports": extract_wheel(path, max_file_bytes, max_names),
            }
        elif kind == "npm":
            payload = extract_npm(path, root, max_file_bytes, max_names)
        else:
            raise Unsafe("unknown artifact kind")
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
    except (TokError, tarfile.TarError, TypeError, AttributeError, OSError):
        _emit(
            {"status": "unknown", "reason": "parse_error", "detail": "artifact could not be read"}
        )
        return 0
    except (zipfile.BadZipFile, SyntaxError, ValueError, RecursionError, KeyError, IndexError):
        _emit({"status": "unknown", "reason": "parse_error", "detail": "module could not be read"})
        return 0
    except Exception:  # last resort: the worker always answers with JSON (R-C-3, P-C-1)
        _emit(
            {"status": "unknown", "reason": "parse_error", "detail": "artifact could not be read"}
        )
        return 0
    _emit(payload)
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
