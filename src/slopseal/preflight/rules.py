"""The only place that selects an enforcement status (D2 section 7.4).

Rules, in order. The first rule that applies gives the status.

1. Any required check missing from the input is NOT_RUN.
2. Any Class A check that is FAIL or NOT_RUN gives NOT ENFORCED.
3. Any check that is NOT_RUN gives NOT ENFORCED. This is stricter than section 7.4, which allows
   a Class B NOT_RUN to give PARTIALLY ENFORCED. The stricter rule is the approved PR A rule, and
   section 7.4 has to be updated to match (see the PR description).
4. Any Class B check that is FAIL gives PARTIALLY ENFORCED, naming each failed check.
5. Otherwise every check passed, and the status is ENFORCED.

The function is pure: the same checks always give the same status and the same reason.

Requirements: D2 section 7.4, AC-35. Layer 5.
"""

from __future__ import annotations

from collections.abc import Sequence

from slopseal.preflight.model import (
    CLASS_A,
    CLASS_B,
    REQUIRED,
    Check,
    Evaluation,
    Result,
    Status,
)


def _complete(checks: Sequence[Check]) -> tuple[Check, ...]:
    """The checks in REQUIRED order. Any required id not supplied is NOT_RUN (rule 1)."""
    by_id = {check.id: check for check in checks}
    if len(by_id) != len(checks):
        raise ValueError("duplicate check id in preflight input")
    out: list[Check] = []
    for check_id, cls, title in REQUIRED:
        out.append(
            by_id.get(check_id)
            or Check(check_id, cls, title, Result.NOT_RUN, "check was not supplied")
        )
    unknown = set(by_id) - {check_id for check_id, _, _ in REQUIRED}
    if unknown:
        raise ValueError("unknown preflight check id: " + ", ".join(sorted(unknown)))
    return tuple(out)


def evaluate(checks: Sequence[Check]) -> Evaluation:
    """Derive the single enforcement status from the checks."""
    complete = _complete(checks)
    not_run = [c.id for c in complete if c.result is Result.NOT_RUN]
    failed_a = [c.id for c in complete if c.cls == CLASS_A and c.result is Result.FAIL]
    failed_b = [c.id for c in complete if c.cls == CLASS_B and c.result is Result.FAIL]

    if failed_a or any(c.cls == CLASS_A and c.result is Result.NOT_RUN for c in complete):
        named = tuple(
            c.id for c in complete if c.cls == CLASS_A and c.result in (Result.FAIL, Result.NOT_RUN)
        )
        return Evaluation(
            Status.NOT_ENFORCED,
            "a security-critical check failed or was not run: " + ", ".join(named),
            complete,
            named,
        )
    if not_run:
        return Evaluation(
            Status.NOT_ENFORCED,
            "a check was not run, so the status cannot be determined: " + ", ".join(not_run),
            complete,
            tuple(not_run),
        )
    if failed_b:
        return Evaluation(
            Status.PARTIALLY_ENFORCED,
            "coverage or durability check failed: " + ", ".join(failed_b),
            complete,
            tuple(failed_b),
        )
    return Evaluation(Status.ENFORCED, "every required check passed", complete, ())
