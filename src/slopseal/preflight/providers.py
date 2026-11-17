"""Check providers for the preflight (D2 section 7.4).

Each function turns facts into a Check. A fact that could not be read is None, and None always
gives NOT_RUN. Nothing here guesses a safe value. Absence of evidence is not evidence of
absence.

Two kinds of check:

- Local checks read facts the host exposes (sudoers text, group membership, /proc, file modes,
  the policy hash). They are implemented here.
- Probe checks (A5, A6, A8, A9, B1, B2) need a live measurement from the anchor sink, the agent's
  execution context, the verdict socket, or the replica. The caller supplies the outcome as
  True (the property holds), False (it does not), or None (not run). The default is None.

Requirements: R-PF-1, R-PF-2. Layer 5.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

from slopseal.preflight.model import REQUIRED, Check, Result

_TITLES = {check_id: title for check_id, _, title in REQUIRED}
_CLASSES = {check_id: cls for check_id, cls, _ in REQUIRED}
CAP_SYS_PTRACE_BIT = 19
PRIVILEGE_GROUPS = frozenset({"sudo", "wheel", "admin"})


def _check(check_id: str, result: Result, detail: str) -> Check:
    return Check(check_id, _CLASSES[check_id], _TITLES[check_id], result, detail)


def probe(check_id: str, holds: bool | None, detail: str = "") -> Check:
    """A check measured by a live probe. True = the property holds, False = it does not."""
    if holds is None:
        return _check(check_id, Result.NOT_RUN, detail or "probe was not run")
    return _check(check_id, Result.PASS if holds else Result.FAIL, detail)


def check_a1(
    privilege_sources: Mapping[str, str | None] | None,
    agent: str,
    groups: frozenset[str] | None,
) -> Check:
    """No sudo, su, or polkit route for the agent account.

    `privilege_sources` maps a source name to its text, or to None if it could not be read. The
    check is an approximation: it looks for the account name as a whole word and for membership of
    a privilege group. A PASS means "no route in the readable sources", and the detail says so.
    """
    if privilege_sources is None or groups is None:
        return _check("A1", Result.NOT_RUN, "privilege sources or group list not read")
    unreadable = sorted(name for name, text in privilege_sources.items() if text is None)
    if unreadable:
        return _check("A1", Result.NOT_RUN, "unreadable sources: " + ", ".join(unreadable))
    word = re.compile(r"(?<![\w.-])" + re.escape(agent) + r"(?![\w.-])")
    for name, text in privilege_sources.items():
        if text is not None and word.search(text):
            return _check("A1", Result.FAIL, "account named in " + name)
    privileged = sorted(groups & PRIVILEGE_GROUPS)
    if privileged:
        return _check("A1", Result.FAIL, "account is in privilege groups: " + ", ".join(privileged))
    return _check("A1", Result.PASS, "no route in the readable sources (approximate)")


def socket_usable_by(
    owner_uid: int,
    group_name: str | None,
    mode: int,
    agent_uid: int,
    agent_groups: frozenset[str],
) -> bool:
    """Whether the agent account can write a socket, from its owner, group, and mode bits.

    This is not `os.access`: that answers for the process running the check, which is often root.
    Only the agent account's own identity counts here.
    """
    if owner_uid == agent_uid and mode & 0o200:
        return True
    if group_name is not None and group_name in agent_groups and mode & 0o020:
        return True
    return bool(mode & 0o002)


def check_a2(groups: frozenset[str] | None, docker_socket_usable: bool | None) -> Check:
    """No Docker group membership and no usable Docker socket for the agent account."""
    if groups is None or docker_socket_usable is None:
        return _check("A2", Result.NOT_RUN, "group list or socket access not read")
    if "docker" in groups:
        return _check("A2", Result.FAIL, "account is in the docker group")
    if docker_socket_usable:
        return _check("A2", Result.FAIL, "Docker socket is usable by the account")
    return _check("A2", Result.PASS, "no docker group and no usable socket")


def check_a3(owner_uid: int | None, mode: int | None, agent_uid: int) -> Check:
    """The service state directory is not owned by the agent and has no group or other access.

    This checks the directory only. The key, the state files, and the service sockets need their
    own checks in the production installer (D2 section 7.2). The detail says so.
    """
    if owner_uid is None or mode is None:
        return _check("A3", Result.NOT_RUN, "service state directory not read")
    if owner_uid == agent_uid:
        return _check("A3", Result.FAIL, "service state directory is owned by the agent account")
    if mode & 0o077:
        return _check("A3", Result.FAIL, "service state directory is open to group or others")
    return _check(
        "A3", Result.PASS, "directory only: owned by another account, no group or other access"
    )


def check_a4(ptrace_scope: int | None, agent_cap_eff: int | None) -> Check:
    """ptrace_scope is at least 1, and the agent process lacks CAP_SYS_PTRACE."""
    if ptrace_scope is None or agent_cap_eff is None:
        return _check("A4", Result.NOT_RUN, "ptrace_scope or agent capabilities not read")
    if ptrace_scope < 1:
        return _check("A4", Result.FAIL, f"ptrace_scope is {ptrace_scope}")
    if agent_cap_eff & (1 << CAP_SYS_PTRACE_BIT):
        return _check("A4", Result.FAIL, "agent holds CAP_SYS_PTRACE")
    return _check("A4", Result.PASS, f"ptrace_scope {ptrace_scope} and no CAP_SYS_PTRACE")


def check_a7(policy_bytes: bytes | None, pinned_sha256: str | None) -> Check:
    """The policy file matches the hash pinned outside the agent's reach."""
    if policy_bytes is None or pinned_sha256 is None:
        return _check("A7", Result.NOT_RUN, "policy file or pin not read")
    actual = hashlib.sha256(policy_bytes).hexdigest()
    if actual != pinned_sha256.lower():
        return _check("A7", Result.FAIL, "policy hash differs from the pin")
    return _check("A7", Result.PASS, "policy hash matches the pin")


def parse_cap_eff(status_text: str) -> int | None:
    """The effective capability mask from a /proc/<pid>/status text, or None."""
    match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)\s*$", status_text, re.M)
    return int(match.group(1), 16) if match else None


def parse_ptrace_scope(text: str) -> int | None:
    """The value in /proc/sys/kernel/yama/ptrace_scope, or None if it is not an integer."""
    text = text.strip()
    return int(text) if text.isdigit() else None
