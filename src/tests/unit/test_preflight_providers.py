"""Preflight providers: each branch, and every unreadable fact gives NOT_RUN (D2 section 7.4).

Requirement: R-PF-2 (unreadable facts are never PASS). Covers AC-35.
"""

from __future__ import annotations

import hashlib

import pytest

from slopseal.preflight.model import Result
from slopseal.preflight.providers import (
    check_a1,
    check_a2,
    check_a3,
    check_a4,
    check_a7,
    parse_cap_eff,
    parse_ptrace_scope,
    probe,
)

# A1: sudo, su, and polkit routes ---------------------------------------------------------


def test_a1_unreadable_source_is_not_run_not_pass() -> None:
    result = check_a1({"sudoers": "root ALL=(ALL) ALL", "polkit/x": None}, "agent", frozenset())
    assert result.result is Result.NOT_RUN


def test_a1_missing_group_list_is_not_run() -> None:
    assert check_a1({"sudoers": ""}, "agent", None).result is Result.NOT_RUN


def test_a1_account_named_in_sudoers_fails() -> None:
    result = check_a1({"sudoers": "agent ALL=(ALL) NOPASSWD: ALL"}, "agent", frozenset())
    assert result.result is Result.FAIL
    assert "sudoers" in result.detail


def test_a1_account_name_inside_another_word_does_not_match() -> None:
    result = check_a1({"sudoers": "magentacorp ALL=(ALL) ALL"}, "agent", frozenset())
    assert result.result is Result.PASS


def test_a1_privilege_group_membership_fails() -> None:
    result = check_a1({"sudoers": ""}, "agent", frozenset({"sudo", "users"}))
    assert result.result is Result.FAIL
    assert "sudo" in result.detail


def test_a1_clean_readable_sources_pass_with_the_approximation_stated() -> None:
    result = check_a1({"sudoers": "root ALL=(ALL) ALL"}, "agent", frozenset({"users"}))
    assert result.result is Result.PASS
    assert "approximate" in result.detail


# A2: Docker -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("groups", "socket", "expected"),
    [
        (None, True, Result.NOT_RUN),
        (frozenset({"users"}), None, Result.NOT_RUN),
        (frozenset({"docker"}), False, Result.FAIL),
        (frozenset({"users"}), True, Result.FAIL),
        (frozenset({"users"}), False, Result.PASS),
    ],
)
def test_a2_docker_route(
    groups: frozenset[str] | None, socket: bool | None, expected: Result
) -> None:
    assert check_a2(groups, socket).result is expected


# A3: service state directory --------------------------------------------------------------


@pytest.mark.parametrize(
    ("owner", "mode", "expected"),
    [
        (None, 0o700, Result.NOT_RUN),
        (0, None, Result.NOT_RUN),
        (1001, 0o700, Result.FAIL),  # owned by the agent account
        (0, 0o750, Result.FAIL),  # group can read
        (0, 0o702, Result.FAIL),  # others can write
        (0, 0o700, Result.PASS),
    ],
)
def test_a3_service_directory(owner: int | None, mode: int | None, expected: Result) -> None:
    assert check_a3(owner, mode, 1001).result is expected


def test_a3_pass_states_its_limit() -> None:
    assert "directory only" in check_a3(0, 0o700, 1001).detail


# A4: ptrace and capabilities -------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "cap", "expected"),
    [
        (None, 0, Result.NOT_RUN),
        (1, None, Result.NOT_RUN),
        (0, 0, Result.FAIL),
        (1, 1 << 19, Result.FAIL),  # CAP_SYS_PTRACE
        (1, 0, Result.PASS),
        (2, 0, Result.PASS),
    ],
)
def test_a4_ptrace_and_capability(scope: int | None, cap: int | None, expected: Result) -> None:
    assert check_a4(scope, cap).result is expected


@pytest.mark.parametrize(
    ("owner", "group", "mode", "agent_groups", "expected"),
    [
        (0, "docker", 0o660, frozenset({"docker"}), True),  # group member, group write
        (0, "docker", 0o660, frozenset({"users"}), False),  # not in the group
        (0, "root", 0o600, frozenset({"users"}), False),  # root only
        (1001, "root", 0o600, frozenset({"users"}), True),  # the agent owns it, owner write
        (0, "root", 0o666, frozenset({"users"}), True),  # world writable
        (0, "root", 0o660, frozenset(), False),
    ],
)
def test_socket_usable_by_the_agent_account_not_by_the_checking_process(
    owner: int, group: str, mode: int, agent_groups: frozenset[str], expected: bool
) -> None:
    from slopseal.preflight.providers import socket_usable_by

    assert socket_usable_by(owner, group, mode, 1001, agent_groups) is expected


def test_parse_cap_eff_reads_the_mask() -> None:
    assert parse_cap_eff("Name:\tbash\nCapEff:\t00000000000080000\n") == 0x80000


def test_parse_cap_eff_missing_is_none() -> None:
    assert parse_cap_eff("Name:\tbash\n") is None


def test_parse_ptrace_scope() -> None:
    assert parse_ptrace_scope("1\n") == 1
    assert parse_ptrace_scope("garbage") is None


# A7: policy pin --------------------------------------------------------------------------


def test_a7_matching_pin_passes_and_mismatch_fails() -> None:
    body = b"policy body"
    good = hashlib.sha256(body).hexdigest()
    assert check_a7(body, good).result is Result.PASS
    assert check_a7(body, good.upper()).result is Result.PASS  # case-insensitive hex
    assert check_a7(body, "0" * 64).result is Result.FAIL


def test_a7_missing_policy_or_pin_is_not_run() -> None:
    assert check_a7(None, "0" * 64).result is Result.NOT_RUN
    assert check_a7(b"x", None).result is Result.NOT_RUN


# Probes -----------------------------------------------------------------------------------


def test_probe_none_is_not_run_never_pass() -> None:
    assert probe("A5", None).result is Result.NOT_RUN


def test_probe_true_passes_and_false_fails() -> None:
    assert probe("A6", True).result is Result.PASS
    assert probe("A6", False).result is Result.FAIL
