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
from dataclasses import dataclass
from pathlib import Path

_PIP_EXACT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[A-Za-z0-9._,\s-]*\])?"
    r"==(?P<version>[A-Za-z0-9.!+_-]+)$"
)
_NPM_EXACT = re.compile(
    r"^(?P<name>(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)"
    r"@(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$"
)
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


@dataclass(frozen=True)
class Passthrough:
    """Not an install: run the real tool unchanged."""


@dataclass(frozen=True)
class Install:
    ecosystem: str
    specs: tuple[tuple[str, str], ...]


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


def parse_pip(args: list[str]) -> Parsed:
    if not args or args[0] not in _PIP_INSTALL:
        return Passthrough()

    specs: list[tuple[str, str]] = []
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
            continue
        # A bare name or a range would let pip pick a version SlopSeal did not verify.
        return Blocked(
            f"'{spec}' is not pinned; use name==x.y.z so the verified version is installed"
        )

    if not specs:
        # `pip install` with nothing to install fails inside pip. Nothing is installed.
        return Passthrough()
    return Install("pypi", tuple(specs))


def parse_npm(args: list[str]) -> Parsed:
    if not args:
        return Passthrough()
    verb = args[0]
    if verb in _NPM_UNVERIFIED_VERBS:
        return Blocked(f"npm {verb} installs packages SlopSeal cannot name; refused")
    if verb not in _NPM_INSTALL:
        return Passthrough()

    specs: list[tuple[str, str]] = []
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
            continue
        # A bare name, range, or tag would let npm pick a version SlopSeal did not verify.
        return Blocked(
            f"'{spec}' is not pinned; use name@x.y.z so the verified version is installed"
        )

    if not specs:
        # `npm install` with no packages installs everything in package.json. Not verified.
        return Blocked("npm install with no packages installs package.json; refused")
    return Install("npm", tuple(specs))


def parse(tool: str, args: list[str]) -> Parsed:
    if tool == "pip":
        return parse_pip(args)
    if tool == "npm":
        return parse_npm(args)
    return Passthrough()
