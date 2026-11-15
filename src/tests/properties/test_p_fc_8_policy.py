"""Property tests for the trust policy: loader (R-1.4) and invariant floors (P-FC-7, P-FC-8).

These tests are what make a weakening edit to `.kiro/steering/dependency-trust.md` fail.
They read the real file, and they generate weakened and malformed variants.
Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.policy.invariants import FLOORS, enforce_floors
from slopseal.policy.loader import (
    Policy,
    PolicyError,
    extract_policy_block,
    load_policy,
    parse_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_PATH = REPO_ROOT / ".kiro" / "steering" / "dependency-trust.md"
FENCE = "\x60" * 3

FLOOR_ATTRIBUTES = {floor.attribute for floor in FLOORS}


def render(values: dict[str, object]) -> str:
    """Render a policy block from a flat dict of section -> key -> value (see loader schema)."""
    lines = [f"{FENCE}toml slopseal-policy"]
    top = values.get("", {})
    for key, value in top.items():  # type: ignore[union-attr]
        lines.append(f"{key} = {_toml(value)}")
    for section, table in values.items():
        if section == "":
            continue
        lines.append(f"[{section}]")
        for key, value in table.items():  # type: ignore[union-attr]
            lines.append(f"{key} = {_toml(value)}")
    lines.append(FENCE)
    return "\n".join(lines) + "\n"


def _toml(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    return repr(value)


def valid_values() -> dict[str, dict[str, object]]:
    return {
        "": {"schema_version": 1},
        "thresholds": {
            "typosquat_max_distance": 2,
            "typosquat_max_age_days": 30,
            "new_package_max_age_days": 7,
            "new_package_max_releases": 3,
        },
        "near_name": {
            "levenshtein_max": 3,
            "jaro_winkler_min": 0.92,
            "keyboard_distance_max": 1,
        },
        "lists": {"allow": [], "deny": []},
        "slopsquat": {"max_distance": 1, "signatures": [["react-codeshift", "react-codemod"]]},
        "levels": {
            "install_scripts": "block",
            "license": "block",
            "license_undeclared": "warn",
            "maintainer": "warn",
        },
        "licenses": {"allow": [], "deny": []},
        "maintainers": {"min_account_age_days": 90},
        "quarantine": {"retry_budget": 1, "max_seconds": 900},
        "semantic": {"enabled": False, "confidence_threshold": 0.0},
    }


def policy_with(overrides: dict[str, object]) -> Policy:
    """Build a Policy directly, so floor properties do not depend on TOML parsing."""
    base = {
        "schema_version": 1,
        "typosquat_max_distance": 2,
        "typosquat_max_age_days": 30,
        "new_package_max_age_days": 7,
        "new_package_max_releases": 3,
        "levenshtein_max": 3,
        "jaro_winkler_min": 0.92,
        "keyboard_distance_max": 1,
        "allow": (),
        "deny": (),
        "slopsquat_max_distance": 1,
        "slopsquat_signatures": (("react-codeshift", "react-codemod"),),
        "level_install_scripts": "block",
        "level_license": "block",
        "level_license_undeclared": "warn",
        "level_maintainer": "warn",
        "license_allow": (),
        "license_deny": (),
        "maintainer_min_account_age_days": 90,
        "retry_budget": 1,
        "max_seconds": 900,
        "semantic_enabled": False,
        "confidence_threshold": 0.0,
        "policy_hash": "0" * 64,
    }
    base.update(overrides)
    return Policy(**base)  # type: ignore[arg-type]


# ---- Committed policy -----------------------------------------------------------------


def test_committed_policy_parses_and_meets_every_floor() -> None:
    policy = load_policy(str(POLICY_PATH))
    assert enforce_floors(policy) == ()


def test_committed_policy_block_is_extracted_exactly_once() -> None:
    block = extract_policy_block(POLICY_PATH.read_text(encoding="utf-8"))
    assert "schema_version = 1" in block


# ---- Floors (P-FC-7, P-FC-8) ----------------------------------------------------------


@given(
    distance=st.integers(min_value=-2, max_value=6),
    age=st.integers(min_value=0, max_value=400),
    jaro=st.floats(min_value=0.0, max_value=1.0),
    budget=st.integers(min_value=-1, max_value=5),
)
def test_p_fc_8_floor_violation_iff_outside_bounds(
    distance: int, age: int, jaro: float, budget: int
) -> None:
    """A value weaker than its floor or ceiling is reported. A tighter value is not."""
    policy = policy_with(
        {
            "typosquat_max_distance": distance,
            "typosquat_max_age_days": age,
            "jaro_winkler_min": jaro,
            "retry_budget": budget,
        }
    )
    violations = enforce_floors(policy)
    expected_violations = (distance < 2) + (age < 30) + (jaro > 0.92) + (budget < 0) + (budget > 1)
    assert len(violations) == expected_violations


@given(
    distance=st.integers(min_value=2, max_value=10), age=st.integers(min_value=30, max_value=1000)
)
def test_p_fc_7_stricter_values_never_violate(distance: int, age: int) -> None:
    """Raising a typosquat threshold is always allowed. It only blocks more."""
    policy = policy_with({"typosquat_max_distance": distance, "typosquat_max_age_days": age})
    assert not [v for v in enforce_floors(policy) if "typosquat" in v]


@pytest.mark.parametrize(
    ("attribute", "weakened_value"),
    [
        ("typosquat_max_distance", 1),
        ("typosquat_max_age_days", 29),
        ("new_package_max_age_days", 6),
        ("new_package_max_releases", 2),
        ("levenshtein_max", 2),
        ("jaro_winkler_min", 0.95),
        ("keyboard_distance_max", 0),
        ("retry_budget", 2),
    ],
)
def test_p_fc_8_each_weakening_is_reported(attribute: str, weakened_value: object) -> None:
    assert attribute in FLOOR_ATTRIBUTES
    violations = enforce_floors(policy_with({attribute: weakened_value}))
    assert any(attribute in message for message in violations)


def test_p_fc_8_weakened_committed_file_fails_the_floors(tmp_path: Path) -> None:
    """The gate: a weakened copy of the real policy file fails the floor check."""
    text = POLICY_PATH.read_text(encoding="utf-8").replace(
        "typosquat_max_distance = 2", "typosquat_max_distance = 1"
    )
    weakened = tmp_path / "dependency-trust.md"
    weakened.write_text(text, encoding="utf-8")
    assert enforce_floors(load_policy(str(weakened)))


# ---- Loader and fail closed (R-1.4) ---------------------------------------------------


@given(key=st.from_regex(r"[a-z]{3,12}_(typo|extra|bogus)[a-z]{0,6}", fullmatch=True))
def test_r_1_4_unknown_key_is_a_policy_error(key: str) -> None:
    values = valid_values()
    values["thresholds"] = {**values["thresholds"], key: 1}  # type: ignore[dict-item]
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(render(values))


@given(version=st.integers().filter(lambda v: v != 1))
def test_r_1_4_unsupported_schema_version_is_a_policy_error(version: int) -> None:
    values = valid_values()
    values[""] = {"schema_version": version}
    with pytest.raises(PolicyError, match="schema_version"):
        parse_policy(render(values))


@given(
    section=st.sampled_from(
        [
            "thresholds",
            "near_name",
            "lists",
            "slopsquat",
            "levels",
            "licenses",
            "maintainers",
            "quarantine",
            "semantic",
        ]
    )
)
def test_r_1_4_missing_section_is_a_policy_error(section: str) -> None:
    values = valid_values()
    del values[section]
    with pytest.raises(PolicyError):
        parse_policy(render(values))


@given(data=st.data())
def test_r_1_4_missing_key_is_a_policy_error(data: st.DataObject) -> None:
    values = valid_values()
    section = data.draw(
        st.sampled_from(
            [
                "thresholds",
                "near_name",
                "slopsquat",
                "levels",
                "maintainers",
                "quarantine",
                "semantic",
            ]
        )
    )
    key = data.draw(st.sampled_from(sorted(values[section])))  # type: ignore[arg-type]
    table = dict(values[section])  # type: ignore[arg-type]
    del table[key]
    values[section] = table  # type: ignore[index]
    with pytest.raises(PolicyError, match="missing required"):
        parse_policy(render(values))


@given(value=st.one_of(st.text(max_size=5), st.booleans()))
def test_r_1_4_wrong_type_is_a_policy_error(value: object) -> None:
    """Strings and booleans are never valid integer thresholds."""
    values = valid_values()
    values["thresholds"] = {**values["thresholds"], "typosquat_max_distance": value}  # type: ignore[dict-item]
    with pytest.raises(PolicyError):
        parse_policy(render(values))


def test_r_1_4_zero_blocks_is_a_policy_error() -> None:
    with pytest.raises(PolicyError, match="found 0"):
        parse_policy("# no policy here\n")


def test_r_1_4_two_blocks_is_a_policy_error() -> None:
    one = render(valid_values())
    with pytest.raises(PolicyError, match="found 2"):
        parse_policy(one + "\n" + one)


def test_r_1_4_unclosed_block_is_a_policy_error() -> None:
    with pytest.raises(PolicyError, match="never closed"):
        parse_policy(f"{FENCE}toml slopseal-policy\nschema_version = 1\n")


def test_r_1_4_malformed_toml_is_a_policy_error() -> None:
    with pytest.raises(PolicyError, match="malformed TOML"):
        parse_policy(f"{FENCE}toml slopseal-policy\nthresholds = [\n{FENCE}\n")


def test_r_1_4_missing_file_is_a_policy_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="unreadable"):
        load_policy(str(tmp_path / "absent.md"))


@given(prose=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200))
def test_prose_outside_the_block_does_not_change_the_hash(prose: str) -> None:
    """The hash covers the parsed block only, so reviewing prose never changes the policy hash."""
    assume(FENCE not in prose)
    base = render(valid_values())
    original = parse_policy(base).policy_hash
    with_prose = parse_policy(f"{prose}\n\n{base}\n{prose}").policy_hash
    assert original == with_prose
