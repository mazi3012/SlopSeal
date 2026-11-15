"""Load the trust policy from the fenced block in `.kiro/steering/dependency-trust.md`.

This module is the only implementation of the extraction rule (design.md section 7). The
pre-commit guard and the property tests import it, so the rule cannot drift between them.

Every failure is a `PolicyError`. The CLI maps it to exit 78 (R-1.4). That covers a missing
or unreadable file, a wrong block count, malformed TOML, an unknown key at any level, a
missing required key, a wrong value type, and an unsupported `schema_version`.

Requirements: R-1.4. Properties: P-FC-1, P-SM-*. Layer 2.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from typing import Any

SUPPORTED_SCHEMA_VERSIONS = frozenset({1})

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
    retry_budget: int
    max_seconds: int
    semantic_enabled: bool
    confidence_threshold: float
    policy_hash: str


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


def parse_policy(text: str) -> Policy:
    """Parse and validate the policy in the full text of the steering file."""
    body = extract_policy_block(text)
    try:
        data = tomllib.loads(body)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"malformed TOML in policy block: {exc}") from exc

    section_names = {name for name in _SCHEMA if name}
    top_level = {key: value for key, value in data.items() if key not in section_names}
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

    thresholds = sections["thresholds"]
    near = sections["near_name"]
    lists = sections["lists"]
    quarantine = sections["quarantine"]
    semantic = sections["semantic"]

    return Policy(
        schema_version=top_level["schema_version"],
        typosquat_max_distance=thresholds["typosquat_max_distance"],
        typosquat_max_age_days=thresholds["typosquat_max_age_days"],
        new_package_max_age_days=thresholds["new_package_max_age_days"],
        new_package_max_releases=thresholds["new_package_max_releases"],
        levenshtein_max=near["levenshtein_max"],
        jaro_winkler_min=float(near["jaro_winkler_min"]),
        keyboard_distance_max=near["keyboard_distance_max"],
        allow=tuple(_as_strings("lists.allow", lists["allow"])),
        deny=tuple(_as_strings("lists.deny", lists["deny"])),
        retry_budget=quarantine["retry_budget"],
        max_seconds=quarantine["max_seconds"],
        semantic_enabled=semantic["enabled"],
        confidence_threshold=float(semantic["confidence_threshold"]),
        policy_hash=_canonical_hash(data),
    )


def _as_strings(where: str, values: list[Any]) -> list[str]:
    if not all(isinstance(item, str) for item in values):
        raise PolicyError(f"{where} must be a list of strings")
    return list(values)


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
