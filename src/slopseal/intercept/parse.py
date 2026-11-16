"""Parse pip and npm command lines into what SlopSeal can verify.

Three outcomes:
- Passthrough: not an install (for example `pip list`, `npm run`). The real tool runs unchanged.
- Install: a list of (name, exact version) to verify. Every package must be pinned.
- Blocked: an install SlopSeal cannot verify (a local path, a URL, a version range, a flag
  that redirects the index, or an option it does not understand). It is refused, never passed.

The parser is conservative on purpose. An unknown option blocks, because an option the parser
does not understand could change what gets installed.

Requirements: R-1.1, R-1.3. Layer 5. Pure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_PIP_NAME = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[A-Za-z0-9._,\s-]*\])?$")
_PIP_EXACT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[A-Za-z0-9._,\s-]*\])?"
    r"==(?P<version>[A-Za-z0-9.!+_-]+)$"
)
_NPM_EXACT = re.compile(
    r"^(?P<name>(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)"
    r"@(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$"
)
_NPM_NAME = re.compile(r"^(?P<name>(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)$")
_ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".zip", ".tgz", ".tar", ".egg")
# npm spec prefixes that name a non-registry source (file, git, URL, hosted repo).
_NPM_SOURCE_PREFIXES = (
    "file:",
    "git+",
    "git:",
    "git@",
    "http:",
    "https:",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
)
# npm verbs that install packages without naming them, or that install from a lockfile.
# SlopSeal cannot verify those installs, so they are refused.
_NPM_UNVERIFIED_VERBS = frozenset(
    {"ci", "clean-install", "ic", "install-clean", "install-test", "it", "update", "up", "upgrade"}
)

# pip options that change nothing about what is installed.
_PIP_FLAGS = frozenset(
    {
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "--no-deps",
        "-U",
        "--upgrade",
        "--user",
        "--no-cache-dir",
        "--disable-pip-version-check",
        "--no-input",
        "--pre",
    }
)
# pip options that take a value and point at a directory the user owns (safe to pass through).
_PIP_VALUE_FLAGS = frozenset({"-t", "--target"})
# pip options that would redirect or widen what is installed. Refused.
_PIP_REFUSED = frozenset(
    {
        "-r",
        "--requirement",
        "-e",
        "--editable",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "-c",
        "--constraint",
        "--trusted-host",
        "--no-index",
    }
)

_NPM_FLAGS = frozenset(
    {
        "-g",
        "--global",
        "-D",
        "--save-dev",
        "-S",
        "--save",
        "-P",
        "--save-prod",
        "-O",
        "--save-optional",
        "-E",
        "--save-exact",
        "--no-save",
        "-q",
        "--quiet",
        "--silent",
        "--no-audit",
        "--no-fund",
        "--ignore-scripts",
        "--legacy-peer-deps",
    }
)
_NPM_VALUE_FLAGS = frozenset({"--prefix"})
_NPM_REFUSED = frozenset({"--registry", "--userconfig", "--workspace", "-w", "--workspaces"})

_PIP_INSTALL = frozenset({"install"})
_NPM_INSTALL = frozenset({"install", "i", "add"})
# npm verbs that download a package and run it (R-1.6). `npm exec` and `npm x` are aliases.
_NPM_EXEC_VERBS = frozenset({"exec", "x"})
# npm verbs that run a create-<name> package when given an initializer (R-1.6).
_NPM_CREATE_VERBS = frozenset({"init", "create"})
# Exec-style options. -p/--package names a package to pin. -c/--call runs a shell string.
_EXEC_FLAGS = frozenset({"-y", "--yes", "-q", "--quiet", "--silent"})
_EXEC_VALUE_FLAGS = frozenset({"-p", "--package"})
_EXEC_REFUSED = frozenset(
    {"-c", "--call", "--shell", "--registry", "--userconfig", "-w", "--workspace", "--workspaces"}
)


@dataclass(frozen=True)
class Passthrough:
    """Not an install: run the real tool unchanged."""


@dataclass(frozen=True)
class Install:
    """Packages to verify. A version of None means the command named the package without a
    pin. Only parse(allow_unpinned=True) produces that, and `positions` then holds the index of
    each such word in args, so the shim can rewrite exactly that word (R-1.7)."""

    ecosystem: str
    specs: tuple[tuple[str, str | None], ...]
    positions: tuple[int, ...] = field(default=(), compare=False)


@dataclass(frozen=True)
class Blocked:
    reason: str


Parsed = Passthrough | Install | Blocked


def _looks_local(word: str) -> bool:
    lowered = word.lower()
    return (
        "/" in word
        or "\\" in word
        or "://" in word
        or word.startswith(".")
        or word.startswith("~")
        or lowered.endswith(_ARCHIVE_SUFFIXES)
        or Path(word).exists()
    )


def _looks_local_npm(token: str) -> bool:
    # A scoped name such as @scope/pkg contains "/" but is a registry name, not a path.
    if token.startswith("@") and "/" in token and not token.startswith(("./", "../")):
        return False
    lowered = token.lower()
    return (
        "\\" in token
        or "://" in token
        or token.startswith((".", "/", "~"))
        or lowered.endswith(_ARCHIVE_SUFFIXES)
        or Path(token).exists()
    )


def parse_pip(args: list[str], *, allow_unpinned: bool = False) -> Parsed:
    if not args or args[0] not in _PIP_INSTALL:
        return Passthrough()

    specs: list[tuple[str, str | None]] = []
    positions: list[int] = []
    rest = args[1:]
    index = 0
    options_done = False
    while index < len(rest):
        word = rest[index]
        index += 1
        if not options_done and word == "--":
            options_done = True
            continue
        if not options_done and word.startswith("-"):
            flag, _, inline = word.partition("=")
            if flag in _PIP_REFUSED:
                return Blocked(f"pip option {flag} would change what is installed; refused")
            if flag in _PIP_VALUE_FLAGS:
                if not inline:
                    index += 1
                continue
            if flag in _PIP_FLAGS:
                continue
            return Blocked(f"pip option {flag} is not understood by SlopSeal; refused")

        spec = word
        if _looks_local(spec):
            return Blocked(f"'{spec}' is a local path or URL; only registry packages are verified")
        exact = _PIP_EXACT.match(spec)
        if exact:
            specs.append((exact.group("name"), exact.group("version")))
            positions.append(index)
            continue
        bare_pip = _PIP_NAME.match(spec)
        if allow_unpinned and bare_pip:
            specs.append((bare_pip.group("name"), None))
            positions.append(index)
            continue
        # A bare name or a range would let pip pick a version SlopSeal did not verify.
        return Blocked(
            f"'{spec}' is not pinned; use name==x.y.z so the verified version is installed"
        )

    if not specs:
        # `pip install` with nothing to install fails inside pip. Nothing is installed.
        return Passthrough()
    return Install("pypi", tuple(specs), tuple(positions))


def parse_exec(args: list[str]) -> Parsed:
    """npx, npm exec, and npm x: the named package is downloaded and run (R-1.6).

    The package must be pinned exactly. Options come before the first positional word or
    before `--`. Once the package word is read, the rest are arguments to the package's
    command and are not verified. A bare command name is accepted only when `-p` pins a
    package of that name.
    """
    pinned_flags: list[str] = []
    index = 0
    while index < len(args):
        word = args[index]
        if word == "--":
            index += 1
            break
        if not word.startswith("-"):
            break
        index += 1
        flag, _, inline = word.partition("=")
        if flag in _EXEC_REFUSED:
            return Blocked(
                f"exec option {flag} runs unverified code or changes its source; refused"
            )
        if flag in _EXEC_VALUE_FLAGS:
            if inline:
                pinned_flags.append(inline)
            elif index < len(args):
                pinned_flags.append(args[index])
                index += 1
            else:
                return Blocked(f"exec option {flag} has no package; refused")
            continue
        if flag in _EXEC_FLAGS:
            continue
        return Blocked(f"exec option {flag} is not understood by SlopSeal; refused")

    rest = args[index:]
    if not rest:
        return Blocked("exec names no package; refused")
    target = rest[0]

    specs: list[tuple[str, str]] = []
    for raw in pinned_flags:
        if _looks_local_npm(raw) or raw.startswith(_NPM_SOURCE_PREFIXES):
            return Blocked(f"'{raw}' is a local path, URL, or repository; refused")
        pinned = _NPM_EXACT.match(raw)
        if pinned is None:
            return Blocked(f"'{raw}' is not pinned; use name@x.y.z so the verified version runs")
        specs.append((pinned.group("name"), pinned.group("version")))

    if _looks_local_npm(target) or target.startswith(_NPM_SOURCE_PREFIXES):
        return Blocked(f"'{target}' is a local path, URL, or repository; refused")
    target_pin = _NPM_EXACT.match(target)
    if target_pin is not None:
        specs.append((target_pin.group("name"), target_pin.group("version")))
    elif pinned_flags and target in {name for name, _ in specs}:
        # `npx -p a@1.0.0 a`: the command is a bin of a package that is already pinned.
        pass
    else:
        return Blocked(f"'{target}' is not pinned; use name@x.y.z so the verified version runs")
    return Install("npm", tuple(specs))


def parse_npm(args: list[str], *, allow_unpinned: bool = False) -> Parsed:
    if not args:
        return Passthrough()
    verb = args[0]
    if verb in _NPM_UNVERIFIED_VERBS:
        return Blocked(f"npm {verb} installs packages SlopSeal cannot name; refused")
    if verb in _NPM_EXEC_VERBS:
        return parse_exec(args[1:])
    if verb in _NPM_CREATE_VERBS:
        # `npm init` alone writes package.json. `npm init <name>` runs create-<name> unverified.
        if any(not word.startswith("-") for word in args[1:]):
            return Blocked(f"npm {verb} with an initializer runs an unverified package; refused")
        return Passthrough()
    if verb not in _NPM_INSTALL:
        return Passthrough()

    specs: list[tuple[str, str | None]] = []
    positions: list[int] = []
    rest = args[1:]
    index = 0
    options_done = False
    while index < len(rest):
        word = rest[index]
        index += 1
        if not options_done and word == "--":
            options_done = True
            continue
        if not options_done and word.startswith("-"):
            flag, _, inline = word.partition("=")
            if flag in _NPM_REFUSED:
                return Blocked(f"npm option {flag} would change where packages come from; refused")
            if flag in _NPM_VALUE_FLAGS:
                if not inline:
                    index += 1
                continue
            if flag in _NPM_FLAGS:
                continue
            return Blocked(f"npm option {flag} is not understood by SlopSeal; refused")

        spec = word
        if _looks_local_npm(spec) or spec.startswith(_NPM_SOURCE_PREFIXES):
            return Blocked(f"'{spec}' is a local path, URL, or repository; refused")
        exact = _NPM_EXACT.match(spec)
        if exact:
            specs.append((exact.group("name"), exact.group("version")))
            positions.append(index)
            continue
        bare_npm = _NPM_NAME.match(spec)
        if allow_unpinned and bare_npm:
            specs.append((bare_npm.group("name"), None))
            positions.append(index)
            continue
        # A bare name, range, or tag would let npm pick a version SlopSeal did not verify.
        return Blocked(
            f"'{spec}' is not pinned; use name@x.y.z so the verified version is installed"
        )

    if not specs:
        # `npm install` with no packages installs everything in package.json. Not verified.
        return Blocked("npm install with no packages installs package.json; refused")
    return Install("npm", tuple(specs), tuple(positions))


def parse(tool: str, args: list[str], *, allow_unpinned: bool = False) -> Parsed:
    """Parse one command. With allow_unpinned, bare package names become unpinned specs (R-1.7)
    for the shim to resolve. Otherwise they are refused, as before."""
    if tool == "pip":
        return parse_pip(args, allow_unpinned=allow_unpinned)
    if tool == "npm":
        return parse_npm(args, allow_unpinned=allow_unpinned)
    if tool == "npx":
        return parse_exec(args)
    return Passthrough()
