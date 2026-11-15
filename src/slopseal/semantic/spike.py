"""Needle 3 spike: the M1 gate.

Runs the pre-registered labelled set (docs/needle_spike_labels.json) through Needle 3 and writes
per-case results to docs/needle_spike.csv and a gate report to docs/needle_spike_report.md.

Decision rule, fixed before the run (see the pre-registration commit):
  - query = the agent's stated purpose
  - tools = every export of the package, each with its description
  - the model's tool call and its confidence come from run_scored
  - ALLOW if the model calls the declared API and confidence >= threshold, else QUARANTINE

Gate (PRD, L2): match-allow rate >= 0.8 AND mismatch-allow rate <= 0.2.
  match-allow rate    = matches ALLOWed / matches
  mismatch-allow rate = mismatches ALLOWed / mismatches

The model file is verified against a pinned SHA-256 before it is loaded (fail closed). The
runtime is the optional `needle` extra (needle-rs). This module imports it lazily, so the
default install never needs it.

Requirements: R-3.5, R-3.8. Layer 3.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NEEDLE3_SHA256 = "c9d915eca282ed42d1a09b143b592adb4cc6744ffe2d294adf5cfc5548170c38"
NEEDLE3_BYTES = 35_335_380
NEEDLE_RS_VERSION = "0.3.1"
GATE_MATCH_ALLOW_MIN = 0.8
GATE_MISMATCH_ALLOW_MAX = 0.2
CSV_COLUMNS = [
    "case_id",
    "label",
    "ecosystem",
    "package",
    "declared_api",
    "purpose",
    "tool_called",
    "confidence",
    "threshold",
    "l2_verdict",
    "correct",
    "repeat_consistent",
    "tool_call_raw",
    "note",
]


class SpikeError(Exception):
    """The spike cannot run: bad labels, a model that fails its checksum, or no runtime."""


@dataclass(frozen=True)
class Case:
    case_id: str
    label: str
    ecosystem: str
    package: str
    declared_api: str
    purpose: str


@dataclass(frozen=True)
class CaseResult:
    case: Case
    tool_called: str | None
    confidence: float | None
    tool_call_raw: str
    verdict: str
    correct: bool
    repeat_consistent: bool


def verify_model(path: Path) -> None:
    if not path.is_file():
        raise SpikeError(f"model file not found: {path}")
    if path.stat().st_size != NEEDLE3_BYTES:
        raise SpikeError("model file size does not match the pinned Needle 3 checkpoint")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != NEEDLE3_SHA256:
        raise SpikeError("model file SHA-256 does not match the pinned Needle 3 checkpoint")


def load_labels(path: Path) -> tuple[list[Case], dict[str, dict[str, str]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    descriptions: dict[str, dict[str, str]] = document["tool_descriptions"]
    cases = [
        Case(
            **{
                key: row[key]
                for key in ("case_id", "label", "ecosystem", "package", "declared_api", "purpose")
            }
        )
        for row in document["cases"]
    ]
    matches = [c for c in cases if c.label == "match"]
    mismatches = [c for c in cases if c.label == "mismatch"]
    if len(matches) < 5 or len(mismatches) < 5:
        raise SpikeError("the labelled set needs at least 5 matches and 5 mismatches")
    for case in cases:
        exports = descriptions.get(case.package, {})
        if case.declared_api not in exports:
            raise SpikeError(f"{case.case_id}: declared API {case.declared_api} is not an export")
    return cases, descriptions


def build_tools(exports: dict[str, str]) -> str:
    """Needle's tool schema: every export of the package, with its description."""
    return json.dumps(
        [
            {
                "name": name,
                "description": description,
                "parameters": {"type": "object", "properties": {}},
            }
            for name, description in sorted(exports.items())
        ],
        separators=(",", ":"),
    )


def _first_tool_name(tool_call: str | None) -> str | None:
    if not tool_call:
        return None
    try:
        calls = json.loads(tool_call)
    except json.JSONDecodeError:
        return None
    if isinstance(calls, list) and calls and isinstance(calls[0], dict):
        name = calls[0].get("name")
        return name if isinstance(name, str) else None
    return None


def decide(
    tool_called: str | None, confidence: float | None, declared_api: str, threshold: float
) -> str:
    if tool_called == declared_api and confidence is not None and confidence >= threshold:
        return "ALLOW"
    return "QUARANTINE"


def run_case(
    engine: Any, case: Case, descriptions: dict[str, dict[str, str]], threshold: float
) -> CaseResult:
    """Run one case twice. The first output is the result; the second checks repeatability."""
    tools = build_tools(descriptions[case.package])
    first_output, first_confidence = engine.run_scored(case.purpose, tools)
    second_output, second_confidence = engine.run_scored(case.purpose, tools)
    tool_call = first_output.get("tool_call") if isinstance(first_output, dict) else None
    called = _first_tool_name(tool_call)
    verdict = decide(called, float(first_confidence), case.declared_api, threshold)
    expected = "ALLOW" if case.label == "match" else "QUARANTINE"
    repeated = first_output.get("tool_call") == second_output.get("tool_call") and float(
        first_confidence
    ) == float(second_confidence)
    return CaseResult(
        case=case,
        tool_called=called,
        confidence=float(first_confidence),
        tool_call_raw=tool_call or "",
        verdict=verdict,
        correct=verdict == expected,
        repeat_consistent=repeated,
    )


def gate(results: list[CaseResult]) -> dict[str, Any]:
    matches = [r for r in results if r.case.label == "match"]
    mismatches = [r for r in results if r.case.label == "mismatch"]
    match_allow = sum(r.verdict == "ALLOW" for r in matches) / len(matches)
    mismatch_allow = sum(r.verdict == "ALLOW" for r in mismatches) / len(mismatches)
    passed = match_allow >= GATE_MATCH_ALLOW_MIN and mismatch_allow <= GATE_MISMATCH_ALLOW_MAX
    return {
        "n_match": len(matches),
        "n_mismatch": len(mismatches),
        "match_allow_rate": match_allow,
        "mismatch_allow_rate": mismatch_allow,
        "passed": passed,
    }


def note_for(r: CaseResult, threshold: float) -> str:
    declared = r.case.declared_api
    if r.tool_called is None:
        return "abstained: no tool call; confidence is for the abstention, not a tool choice"
    if r.tool_called != declared:
        return f"called {r.tool_called} instead of declared {declared}"
    if r.confidence is not None and r.confidence < threshold:
        return f"declared tool chosen but confidence {r.confidence:.3f} is below {threshold:.2f}"
    return ""


def _row(r: CaseResult, threshold: float) -> dict[str, str]:
    return {
        "case_id": r.case.case_id,
        "label": r.case.label,
        "ecosystem": r.case.ecosystem,
        "package": r.case.package,
        "declared_api": r.case.declared_api,
        "purpose": r.case.purpose,
        "tool_called": r.tool_called or "",
        "confidence": "" if r.confidence is None else f"{r.confidence:.6f}",
        "threshold": f"{threshold:.2f}",
        "l2_verdict": r.verdict,
        "correct": "yes" if r.correct else "no",
        "repeat_consistent": "yes" if r.repeat_consistent else "no",
        "tool_call_raw": r.tool_call_raw,
        "note": note_for(r, threshold),
    }


def _summary_row(results: list[CaseResult], threshold: float) -> dict[str, str]:
    summary = gate(results)
    matched = round(summary["match_allow_rate"] * summary["n_match"])
    mismatched = round(summary["mismatch_allow_rate"] * summary["n_mismatch"])
    outcome = (
        "Gate passed."
        if summary["passed"]
        else ("Gate failed. The semantic layer is not integrated; v1 ships deterministic-only.")
    )
    return {
        "case_id": "GATE",
        "label": "summary",
        "ecosystem": "",
        "package": "",
        "declared_api": "",
        "purpose": "",
        "tool_called": "",
        "confidence": "",
        "threshold": f"{threshold:.2f}",
        "l2_verdict": "PASS" if summary["passed"] else "FAIL",
        "correct": "",
        "repeat_consistent": "all yes" if all(r.repeat_consistent for r in results) else "some no",
        "tool_call_raw": "",
        "note": (
            f"match-allow {summary['match_allow_rate']:.2f} ({matched}/{summary['n_match']}) "
            f"required >= {GATE_MATCH_ALLOW_MIN:.2f}; "
            f"mismatch-allow {summary['mismatch_allow_rate']:.2f} "
            f"({mismatched}/{summary['n_mismatch']}) "
            f"required <= {GATE_MISMATCH_ALLOW_MAX:.2f}. {outcome}"
        ),
    }


def write_csv(results: list[CaseResult], threshold: float, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for r in results:
            writer.writerow(_row(r, threshold))
        writer.writerow(_summary_row(results, threshold))


def load_engine(model: Path) -> Any:
    try:
        import needle_rs  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SpikeError("needle-rs is not installed: pip install 'slopseal[needle]'") from exc
    return needle_rs.V3Engine.load(str(model))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="slopseal-needle-spike")
    parser.add_argument("--model", type=Path, required=True, help="path to needle3.cact")
    parser.add_argument("--labels", type=Path, default=Path("docs/needle_spike_labels.json"))
    parser.add_argument("--out", type=Path, default=Path("docs/needle_spike.csv"))
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args(argv)

    try:
        verify_model(args.model)
        cases, descriptions = load_labels(args.labels)
        engine = load_engine(args.model)
    except SpikeError as exc:
        print(f"spike: {exc}", file=sys.stderr)
        return 2

    results = [run_case(engine, case, descriptions, args.threshold) for case in cases]
    write_csv(results, args.threshold, args.out)
    summary = gate(results)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
