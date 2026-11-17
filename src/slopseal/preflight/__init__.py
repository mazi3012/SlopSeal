"""Deterministic enforcement preflight (D2 section 7.4).

`run` gives one status: ENFORCED, PARTIALLY ENFORCED, or NOT ENFORCED. Only `rules.evaluate`
selects the status. Probes that are not supplied are NOT_RUN, which gives NOT ENFORCED.
"""

from slopseal.preflight.model import Check, Evaluation, Result, Status
from slopseal.preflight.rules import evaluate
from slopseal.preflight.runner import PreflightInputs, ProbeResults, run

__all__ = [
    "Check",
    "Evaluation",
    "PreflightInputs",
    "ProbeResults",
    "Result",
    "Status",
    "evaluate",
    "run",
]
