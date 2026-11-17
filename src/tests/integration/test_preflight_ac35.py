"""AC-35: the enforcement status is deterministic (D2 section 7.4).

Five fixtures, one per required outcome. The same input always gives the same status. A default
run, with no probe supplied, never reports ENFORCED.

Requirement: R-PF-1 (deterministic preflight). Covers AC-35.
"""

from __future__ import annotations

from slopseal.preflight.model import REQUIRED, Check, Result, Status
from slopseal.preflight.rules import evaluate
from slopseal.preflight.runner import LocalFacts, PreflightInputs, ProbeResults, run


def _checks(overrides: dict[str, Result] | None = None) -> list[Check]:
    """All required checks. Each one PASSES unless `overrides` names another result."""
    overrides = overrides or {}
    return [
        Check(check_id, cls, title, overrides.get(check_id, Result.PASS), "fixture")
        for check_id, cls, title in REQUIRED
    ]


def test_fixture_1_every_check_passes_gives_enforced() -> None:
    result = evaluate(_checks())
    assert result.status is Status.ENFORCED
    assert result.named == ()


def test_fixture_2_only_a_class_b_check_fails_gives_partial_and_names_it() -> None:
    result = evaluate(_checks({"B1": Result.FAIL}))
    assert result.status is Status.PARTIALLY_ENFORCED
    assert result.named == ("B1",)
    assert "B1" in result.reason


def test_fixture_3_a_class_a_check_fails_gives_not_enforced_even_if_b_passes() -> None:
    result = evaluate(_checks({"A4": Result.FAIL}))
    assert result.status is Status.NOT_ENFORCED
    assert result.named == ("A4",)


def test_fixture_4_a_class_a_check_not_run_gives_not_enforced() -> None:
    result = evaluate(_checks({"A4": Result.NOT_RUN}))
    assert result.status is Status.NOT_ENFORCED
    assert result.named == ("A4",)


def test_fixture_5_direct_registry_route_gives_not_enforced_section_7_4_1() -> None:
    """A6 FAIL means a registry probe from the agent context succeeded (section 7.4.1, item 4)."""
    result = evaluate(_checks({"A6": Result.FAIL}))
    assert result.status is Status.NOT_ENFORCED
    assert result.named == ("A6",)
    assert "A6" in result.reason


def test_same_input_always_gives_the_same_status() -> None:
    checks = _checks({"B2": Result.FAIL, "B1": Result.FAIL})
    first = evaluate(checks)
    second = evaluate(list(reversed(checks)))
    assert first.status is second.status is Status.PARTIALLY_ENFORCED
    assert first.named == second.named == ("B1", "B2")


def test_class_b_not_run_gives_not_enforced_under_the_pr_a_rule() -> None:
    """Stricter than section 7.4 for a Class B NOT RUN. See the PR A description."""
    result = evaluate(_checks({"B1": Result.NOT_RUN}))
    assert result.status is Status.NOT_ENFORCED
    assert result.named == ("B1",)


def test_default_run_with_no_probes_is_never_enforced() -> None:
    """With every probe not run, the status is NOT ENFORCED whatever the local facts say."""
    inputs = PreflightInputs(agent="kiro-agent", agent_uid=1001, pinned_sha256=None)
    result = run(inputs)
    assert result.status is Status.NOT_ENFORCED
    # Class A gaps are named first (rule order); the probes are NOT_RUN in the checks themselves.
    assert {"A5", "A6", "A8", "A9"} <= set(result.named)
    probe_results = {c.id: c.result for c in result.checks if c.id in ("A5", "A6", "B1", "B2")}
    assert set(probe_results.values()) == {Result.NOT_RUN}


def test_probes_supplied_as_true_can_reach_enforced_only_with_every_local_check_passing() -> None:

    local = LocalFacts(
        privilege_sources={"sudoers": "root ALL=(ALL) ALL\n"},
        agent_groups=frozenset({"agents"}),
        docker_socket_usable=False,
        service_dir_owner=0,
        service_dir_mode=0o700,
        ptrace_scope=1,
        agent_cap_eff=0,
        policy_bytes=b"policy",
    )
    everything = ProbeResults(
        a5_anchor=True,
        a6_no_registry_route=True,
        a8_socket_binding=True,
        a9_escape_routes_disabled=True,
        b1_replica=True,
        b2_artifact_route=True,
    )
    import hashlib

    pin = hashlib.sha256(b"policy").hexdigest()
    result = run(PreflightInputs("kiro-agent", 1001, local, pin, everything))
    assert result.status is Status.ENFORCED, result.reason
