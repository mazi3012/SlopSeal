"""Run the preflight: gather facts, build the checks, and derive the status (D2 section 7.4).

`run` is pure over its inputs. `gather_local` reads the host. Probe outcomes that the host cannot
show (the anchor, the agent's network, the replica, the artifact route) come in through
`ProbeResults`, and default to not run. A default run therefore never reports ENFORCED.

Requirements: R-PF-1, R-PF-2. Layer 5.
"""

from __future__ import annotations

import contextlib
import grp
import pwd
from dataclasses import dataclass, field
from pathlib import Path

from slopseal.preflight.model import Check, Evaluation
from slopseal.preflight.providers import (
    check_a1,
    check_a2,
    check_a3,
    check_a4,
    check_a7,
    parse_cap_eff,
    parse_ptrace_scope,
    probe,
    socket_usable_by,
)
from slopseal.preflight.rules import evaluate


@dataclass(frozen=True)
class ProbeResults:
    """Outcomes of live probes. True = the property holds. None = not run (the default)."""

    a5_anchor: bool | None = None
    a6_no_registry_route: bool | None = None
    a8_socket_binding: bool | None = None
    a9_escape_routes_disabled: bool | None = None
    b1_replica: bool | None = None
    b2_artifact_route: bool | None = None


@dataclass(frozen=True)
class LocalFacts:
    """Facts read from the host. None means the fact could not be read."""

    privilege_sources: dict[str, str | None] | None = None
    agent_groups: frozenset[str] | None = None
    docker_socket_usable: bool | None = None
    service_dir_owner: int | None = None
    service_dir_mode: int | None = None
    ptrace_scope: int | None = None
    agent_cap_eff: int | None = None
    policy_bytes: bytes | None = None


@dataclass(frozen=True)
class PreflightInputs:
    agent: str
    agent_uid: int
    local: LocalFacts = field(default_factory=LocalFacts)
    pinned_sha256: str | None = None
    probes: ProbeResults = field(default_factory=ProbeResults)


def build_checks(inputs: PreflightInputs) -> list[Check]:
    """The full set of checks. Each one is PASS, FAIL, or NOT_RUN."""
    local = inputs.local
    probes = inputs.probes
    return [
        check_a1(local.privilege_sources, inputs.agent, local.agent_groups),
        check_a2(local.agent_groups, local.docker_socket_usable),
        check_a3(local.service_dir_owner, local.service_dir_mode, inputs.agent_uid),
        check_a4(local.ptrace_scope, local.agent_cap_eff),
        probe("A5", probes.a5_anchor, "anchor receipts and head checked"),
        probe("A6", probes.a6_no_registry_route, "every registry probe failed from the agent"),
        check_a7(local.policy_bytes, inputs.pinned_sha256),
        probe("A8", probes.a8_socket_binding, "SO_PEERCRED binding checked"),
        probe("A9", probes.a9_escape_routes_disabled, "Kiro escape routes checked"),
        probe("B1", probes.b1_replica, "replica present and head-verified"),
        probe("B2", probes.b2_artifact_route, "grant issued and served on a test ALLOW"),
    ]


def run(inputs: PreflightInputs) -> Evaluation:
    """Evaluate the preflight. The status is decided by `rules.evaluate` alone."""
    return evaluate(build_checks(inputs))


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _privilege_sources(root: Path) -> dict[str, str | None]:
    """Text of every sudoers and polkit source. A missing directory is recorded as unreadable."""
    sources: dict[str, str | None] = {}
    sudoers = root / "etc" / "sudoers"
    sources["sudoers"] = _read(sudoers) if sudoers.is_file() else None
    for directory, label in (
        (root / "etc" / "sudoers.d", "sudoers.d"),
        (root / "etc" / "polkit-1" / "rules.d", "polkit"),
    ):
        if not directory.is_dir():
            sources[label] = None  # a missing directory is not evidence that it is empty
            continue
        for entry in sorted(directory.iterdir()):
            if entry.is_file():
                sources[label + "/" + entry.name] = _read(entry)
    return sources


def _docker_socket_usable_by(
    agent: str, socket_path: Path = Path("/var/run/docker.sock")
) -> bool | None:
    """Whether the agent account can use the Docker socket. None if it cannot be determined."""
    if not socket_path.exists():
        return False
    try:
        st = socket_path.stat()
        agent_uid = pwd.getpwnam(agent).pw_uid
        group_name = grp.getgrgid(st.st_gid).gr_name
    except (OSError, KeyError):
        return None
    groups = _agent_groups(agent)
    if groups is None:
        return None
    return socket_usable_by(st.st_uid, group_name, st.st_mode, agent_uid, groups)


def _agent_groups(agent: str) -> frozenset[str] | None:
    try:
        primary = grp.getgrgid(pwd.getpwnam(agent).pw_gid).gr_name
    except (KeyError, OSError):
        return None
    supplementary = {g.gr_name for g in grp.getgrall() if agent in g.gr_mem}
    return frozenset(supplementary | {primary})


def gather_local(agent: str, service_dir: Path, policy: Path, root: Path = Path("/")) -> LocalFacts:
    """Read the host facts for the local checks. `root` lets tests point at a fake tree."""
    docker_usable = _docker_socket_usable_by(agent)

    owner: int | None = None
    mode: int | None = None
    with contextlib.suppress(OSError):
        status = service_dir.stat()
        owner, mode = status.st_uid, status.st_mode & 0o777

    ptrace_text = _read(root / "proc" / "sys" / "kernel" / "yama" / "ptrace_scope")
    ptrace = parse_ptrace_scope(ptrace_text) if ptrace_text is not None else None

    policy_bytes: bytes | None = None
    with contextlib.suppress(OSError):
        policy_bytes = policy.read_bytes()

    return LocalFacts(
        privilege_sources=_privilege_sources(root),
        agent_groups=_agent_groups(agent),
        docker_socket_usable=docker_usable,
        service_dir_owner=owner,
        service_dir_mode=mode,
        ptrace_scope=ptrace,
        agent_cap_eff=None,  # needs the agent's process id; the installer supplies it
        policy_bytes=policy_bytes,
    )


def cap_eff_for_pid(pid: int, root: Path = Path("/")) -> int | None:
    """The effective capability mask of a process, or None if it cannot be read."""
    text = _read(root / "proc" / str(pid) / "status")
    return parse_cap_eff(text) if text is not None else None
