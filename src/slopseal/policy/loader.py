"""Load the trust policy from the fenced block in `.kiro/steering/dependency-trust.md`.

This module is the only implementation of the extraction rule (design.md section 7). The
pre-commit guard, the CLI, and the property tests import it, so the rule cannot drift.

Every failure is a `PolicyError`. The CLI maps it to exit 78 (R-1.4). That covers a missing
or unreadable file, a wrong block count, malformed TOML, an unknown key at any level, a
missing required key, a wrong value type, an invalid level, and an unsupported
`schema_version`.

Requirements: R-1.4. Properties: P-FC-1, P-SM-*. Layer 2.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMA_VERSIONS = frozenset({1})
VALID_LEVELS = frozenset({"warn", "block"})
# Top-level tables that may be absent. A missing table means "no entries", never "allowed".
OPTIONAL_SECTIONS = frozenset({"compiled_wheels"})

# A backtick is \x60, so the fence can be written here without opening a fence in this file.
_OPEN_FENCE = re.compile(r"^\x60{3}toml slopseal-policy[ \t]*$")
_CLOSE_FENCE = re.compile(r"^\x60{3}[ \t]*$")


class PolicyError(Exception):
    """The policy is missing, unreadable, or invalid. Callers must fail closed (exit 78)."""


@dataclass(frozen=True)
class Policy:
    schema_version: int
    typosquat_max_distance: int
    typosquat_max_age_days: int
    new_package_max_age_days: int
    new_package_max_releases: int
    levenshtein_max: int
    jaro_winkler_min: float
    keyboard_distance_max: int
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    slopsquat_max_distance: int
    slopsquat_signatures: tuple[tuple[str, str], ...]
    level_install_scripts: str
    level_license: str
    level_license_undeclared: str
    level_maintainer: str
    license_allow: tuple[str, ...]
    license_deny: tuple[str, ...]
    maintainer_min_account_age_days: int
    max_installs_per_minute: int
    retry_budget: int
    max_seconds: int
    semantic_enabled: bool
    confidence_threshold: float
    policy_hash: str
    compiled_wheels: tuple[CompiledWheelException, ...] = ()


@dataclass(frozen=True)
class WheelPin:
    """One reviewed wheel for one host platform. The digest must match the registry's digest."""

    platform: str
    filename: str
    sha256: str


@dataclass(frozen=True)
class CompiledWheelException:
    """A reviewed exception for a compiled (non-universal) wheel. See `.kiro/steering/`."""

    name: str
    version: str
    publisher: str
    reviewed_by: str
    reviewed_on: str
    adr: str
    pins: tuple[WheelPin, ...]


# Schema: section name -> key -> expected type. The top level is the empty section name.
# `float` accepts TOML integers as well, because `1` is a valid threshold.
_SCHEMA: dict[str, dict[str, type]] = {
    "": {"schema_version": int},
    "thresholds": {
        "typosquat_max_distance": int,
        "typosquat_max_age_days": int,
        "new_package_max_age_days": int,
        "new_package_max_releases": int,
    },
    "near_name": {
        "levenshtein_max": int,
        "jaro_winkler_min": float,
        "keyboard_distance_max": int,
    },
    "lists": {"allow": list, "deny": list},
    "slopsquat": {"max_distance": int, "signatures": list},
    "levels": {
        "install_scripts": str,
        "license": str,
        "license_undeclared": str,
        "maintainer": str,
    },
    "licenses": {"allow": list, "deny": list},
    "maintainers": {"min_account_age_days": int},
    "limits": {"max_installs_per_minute": int},
    "quarantine": {"retry_budget": int, "max_seconds": int},
    "semantic": {"enabled": bool, "confidence_threshold": float},
}


def extract_policy_block(text: str) -> str:
    """Return the body of the single `toml slopseal-policy` fence in `text`.

    Zero blocks, two or more blocks, or an opening fence with no closing fence is a PolicyError.
    """
    blocks: list[str] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if current is None:
            if _OPEN_FENCE.match(line):
                current = []
        elif _CLOSE_FENCE.match(line):
            blocks.append("\n".join(current))
            current = None
        else:
            current.append(line)

    if current is not None:
        raise PolicyError("policy block is opened but never closed")
    if len(blocks) != 1:
        raise PolicyError(f"expected exactly one policy block, found {len(blocks)}")
    return blocks[0]


def _check_section(section: str, table: dict[str, Any], expected: dict[str, type]) -> None:
    where = section or "top level"
    unknown = sorted(set(table) - set(expected))
    if unknown:
        raise PolicyError(f"unknown key(s) in {where}: {', '.join(unknown)}")
    missing = sorted(set(expected) - set(table))
    if missing:
        raise PolicyError(f"missing required key(s) in {where}: {', '.join(missing)}")
    for key, kind in expected.items():
        value = table[key]
        if kind is float:
            ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        elif kind is int:
            ok = isinstance(value, int) and not isinstance(value, bool)
        else:
            ok = isinstance(value, kind)
        if not ok:
            raise PolicyError(f"{where}.{key} must be {kind.__name__}")


def _canonical_hash(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _strings(where: str, values: list[Any]) -> tuple[str, ...]:
    if not all(isinstance(item, str) for item in values):
        raise PolicyError(f"{where} must be a list of strings")
    return tuple(values)


def _signatures(values: list[Any]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for item in values:
        if not (
            isinstance(item, list)
            and len(item) == 2
            and all(isinstance(part, str) and part for part in item)
        ):
            raise PolicyError("slopsquat.signatures must be a list of [pattern, mimics] pairs")
        pairs.append((item[0], item[1]))
    return tuple(pairs)


def _level(where: str, value: str) -> str:
    if value not in VALID_LEVELS:
        raise PolicyError(f"{where} must be 'warn' or 'block'")
    return value


_EXCEPTION_KEYS: dict[str, type] = {
    "version": str,
    "publisher": str,
    "reviewed_by": str,
    "reviewed_on": str,
    "adr": str,
    "platforms": dict,
}
_PIN_KEYS: dict[str, type] = {"wheel": str, "sha256": str}
_EXACT_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLISHER = re.compile(r"^github\.com/[a-z0-9_.-]+/[a-z0-9_.-]+$")


def _compiled_wheels(table: Any) -> tuple[CompiledWheelException, ...]:
    """Validate the optional `[compiled_wheels]` table. A missing table means no exceptions."""
    if not isinstance(table, dict):
        raise PolicyError("[compiled_wheels] must be a table")
    exceptions: list[CompiledWheelException] = []
    for name in sorted(table):
        where = f"compiled_wheels.{name}"
        body = table[name]
        if not isinstance(body, dict):
            raise PolicyError(f"{where} must be a table")
        if name != name.lower():
            raise PolicyError(f"{where}: the package name must be lowercase")
        _check_section(where, body, _EXCEPTION_KEYS)
        version = body["version"]
        if not _EXACT_VERSION.match(version):
            raise PolicyError(f"{where}.version must be an exact version such as 1.2.3")
        publisher = body["publisher"].lower()
        if not _PUBLISHER.match(publisher):
            raise PolicyError(f"{where}.publisher must look like github.com/owner/repo")
        if not body["reviewed_by"].strip() or not body["reviewed_on"].strip():
            raise PolicyError(f"{where} needs reviewed_by and reviewed_on")
        if not body["platforms"]:
            raise PolicyError(f"{where}.platforms must name at least one reviewed wheel")
        pins: list[WheelPin] = []
        for platform in sorted(body["platforms"]):
            pin_where = f"{where}.platforms.{platform}"
            pin = body["platforms"][platform]
            if not isinstance(pin, dict):
                raise PolicyError(f"{pin_where} must be a table")
            _check_section(pin_where, pin, _PIN_KEYS)
            filename = pin["wheel"]
            if not (filename.endswith(".whl") and filename.startswith(f"{name}-{version}-")):
                raise PolicyError(f"{pin_where}.wheel must be a wheel of {name} {version}")
            if not _SHA256.match(pin["sha256"]):
                raise PolicyError(f"{pin_where}.sha256 must be 64 lowercase hex characters")
            pins.append(WheelPin(platform, filename, pin["sha256"]))
        exceptions.append(
            CompiledWheelException(
                name=name,
                version=version,
                publisher=publisher,
                reviewed_by=body["reviewed_by"],
                reviewed_on=body["reviewed_on"],
                adr=body["adr"],
                pins=tuple(pins),
            )
        )
    return tuple(exceptions)


def parse_policy(text: str) -> Policy:
    """Parse and validate the policy in the full text of the steering file."""
    body = extract_policy_block(text)
    try:
        data = tomllib.loads(body)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"malformed TOML in policy block: {exc}") from exc

    section_names = {name for name in _SCHEMA if name}
    top_level = {
        key: value
        for key, value in data.items()
        if key not in section_names and key not in OPTIONAL_SECTIONS
    }
    _check_section("", top_level, _SCHEMA[""])

    if top_level["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS:
        raise PolicyError(
            f"unsupported schema_version {top_level['schema_version']}; "
            f"supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )

    sections: dict[str, dict[str, Any]] = {}
    for name in sorted(section_names):
        if name not in data:
            raise PolicyError(f"missing required section [{name}]")
        if not isinstance(data[name], dict):
            raise PolicyError(f"[{name}] must be a table")
        _check_section(name, data[name], _SCHEMA[name])
        sections[name] = data[name]

    t = sections["thresholds"]
    n = sections["near_name"]
    lists = sections["lists"]
    sq = sections["slopsquat"]
    lv = sections["levels"]
    lic = sections["licenses"]
    mt = sections["maintainers"]
    lim = sections["limits"]
    q = sections["quarantine"]
    sem = sections["semantic"]

    return Policy(
        schema_version=top_level["schema_version"],
        typosquat_max_distance=t["typosquat_max_distance"],
        typosquat_max_age_days=t["typosquat_max_age_days"],
        new_package_max_age_days=t["new_package_max_age_days"],
        new_package_max_releases=t["new_package_max_releases"],
        levenshtein_max=n["levenshtein_max"],
        jaro_winkler_min=float(n["jaro_winkler_min"]),
        keyboard_distance_max=n["keyboard_distance_max"],
        allow=_strings("lists.allow", lists["allow"]),
        deny=_strings("lists.deny", lists["deny"]),
        slopsquat_max_distance=sq["max_distance"],
        slopsquat_signatures=_signatures(sq["signatures"]),
        level_install_scripts=_level("levels.install_scripts", lv["install_scripts"]),
        level_license=_level("levels.license", lv["license"]),
        level_license_undeclared=_level("levels.license_undeclared", lv["license_undeclared"]),
        level_maintainer=_level("levels.maintainer", lv["maintainer"]),
        license_allow=_strings("licenses.allow", lic["allow"]),
        license_deny=_strings("licenses.deny", lic["deny"]),
        maintainer_min_account_age_days=mt["min_account_age_days"],
        max_installs_per_minute=lim["max_installs_per_minute"],
        retry_budget=q["retry_budget"],
        max_seconds=q["max_seconds"],
        semantic_enabled=sem["enabled"],
        confidence_threshold=float(sem["confidence_threshold"]),
        policy_hash=_canonical_hash(data),
        compiled_wheels=_compiled_wheels(data.get("compiled_wheels", {})),
    )


BUNDLED_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "defaults" / "dependency-trust.md"
WORKSPACE_POLICY_PATH = Path(".kiro") / "steering" / "dependency-trust.md"


def load_policy(path: str) -> Policy:
    """Read and parse the policy file. Any read failure is a PolicyError."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise PolicyError(f"policy file unreadable: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyError("policy file is not valid UTF-8") from exc
    return parse_policy(text)


def load_policy_or_bundled_default() -> Policy:
    """Load policy from the fallback chain: env var -> workspace -> bundled default.

    1. SLOPSEAL_POLICY_PATH environment variable (if set).
    2. .kiro/steering/dependency-trust.md in the current workspace (if it exists).
    3. The bundled defaults/dependency-trust.md (Zero-config fallback).

    Any failure to load ANY source is a PolicyError. The bundled default is always valid.
    """
    env_path = os.environ.get("SLOPSEAL_POLICY_PATH")
    if env_path is not None:
        return load_policy(env_path)

    if WORKSPACE_POLICY_PATH.exists():
        return load_policy(str(WORKSPACE_POLICY_PATH))

    if not BUNDLED_DEFAULT_PATH.is_file():
        raise PolicyError(
            "no policy found: SLOPSEAL_POLICY_PATH is unset, the workspace policy is missing, "
            "and the bundled default is unavailable"
        )
    return load_policy(str(BUNDLED_DEFAULT_PATH))
