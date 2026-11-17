#!/usr/bin/env python3
"""Measured run of the Contract Check against the labelled evaluation set (docs/CONTRACT_EVAL.md).

Reads docs/contract_labels.json. For each package it pins the labelled version, takes the artifact
the registry names for it, checks that the registry's published digest equals the label, and runs
the live contract twice: uncached (an empty cache) and cached (the second call). Every probe is
answered with check_contract. The metric definitions of CONTRACT_EVAL.md are applied as written.

It uses the live registries and the network. It writes the full result as JSON and prints the
summary. Standard library and the slopseal package only.

Usage: python scripts/contract_eval.py [--out results.json]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import statistics
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from slopseal.contract.types import ContractComplete, ContractDigestMismatch, ContractUnknown
from slopseal.core.types import Ecosystem
from slopseal.quarantine.api_surface import ApiSurface, check_contract
from slopseal.registry.live import LiveSource

REPO = Path(__file__).resolve().parents[1]
LABELS = REPO / "docs" / "contract_labels.json"
ECOSYSTEMS = {"pypi": Ecosystem.PYPI, "npm": Ecosystem.NPM}


def _probe_outcome(result: Any, probe: str) -> tuple[str, str | None]:
    """A(p): PRESENT or ABSENT for a complete contract, or UNKNOWN with its reason."""
    if isinstance(result, ContractDigestMismatch):
        return "UNKNOWN", "contract_digest"
    if isinstance(result, ContractUnknown):
        surface = check_contract(result, probe)
        if surface.outcome is ApiSurface.PRESENT:
            return "PRESENT", result.reason.value  # listed by a complete entry point (two entries)
        return "UNKNOWN", result.reason.value
    outcome = check_contract(result, probe).outcome
    return ("PRESENT" if outcome is ApiSurface.PRESENT else "ABSENT"), None


def _label_digest_matches(label: dict[str, Any], eco: Ecosystem, hexdigest: str | None) -> bool:
    """The label's pinned digest equals the registry's published digest (hex for PyPI sha256;
    the base64 part of the SRI string for npm)."""
    if hexdigest is None:
        return False
    artifact = label["artifact"]
    if eco is Ecosystem.PYPI:
        return artifact.get("digest") == hexdigest
    encoded = base64.b64encode(bytes.fromhex(hexdigest)).decode("ascii")
    return artifact.get("integrity", "").endswith("-" + encoded)


def _run_package(label: dict[str, Any], live: LiveSource) -> dict[str, Any]:
    eco = ECOSYSTEMS[label["ecosystem"]]
    name, version = label["name"], label["version"]
    record: dict[str, Any] = {
        "id": label["id"],
        "ecosystem": label["ecosystem"],
        "name": name,
        "version": version,
        "hard_case": label.get("hard_case"),
        "expected_status": label["expected_status"],
        "expected_reason": label.get("expected_reason"),
    }
    try:
        plan = live._artifact_plan(eco, name, version)  # noqa: SLF001
        if isinstance(plan, ContractUnknown):
            record.update(
                artifact_filename=None,
                filename_matches_label=False,
                published_digest=None,
                digest_matches_label=False,
                label_filename=None,
            )
        else:
            url, _kind, published = plan
            filename = url.rsplit("/", 1)[-1]
            label_filename = (
                label["artifact"].get("filename") or label["artifact"]["url"].rsplit("/", 1)[-1]
            )
            digest = getattr(published, "hexdigest", None)
            record.update(
                artifact_filename=filename,
                label_filename=label_filename,
                filename_matches_label=filename == label_filename,
                published_digest=digest,
                digest_matches_label=_label_digest_matches(label, eco, digest),
            )
        t0 = time.perf_counter()
        first = live.contract(eco, name, version)
        t1 = time.perf_counter()
        second = live.contract(eco, name, version)
        t2 = time.perf_counter()
    except Exception as exc:  # fail closed and keep going: an error is recorded, not hidden
        record["error"] = f"{type(exc).__name__}: {exc}"
        return record
    record["uncached_ms"] = round(1000 * (t1 - t0), 1)
    record["cached_ms"] = round(1000 * (t2 - t1), 2)
    record["package_status"] = (
        "complete"
        if isinstance(first, ContractComplete)
        else ("digest_mismatch" if isinstance(first, ContractDigestMismatch) else "unknown")
    )
    record["package_reason"] = (
        None
        if isinstance(first, ContractComplete)
        else (
            "contract_digest" if isinstance(first, ContractDigestMismatch) else first.reason.value
        )
    )
    record["package_detail"] = (
        None if isinstance(first, ContractComplete) else (getattr(first, "detail", None))
    )
    record["cached_is_complete"] = isinstance(second, ContractComplete)
    record["exports_count"] = len(first.exports) if isinstance(first, ContractComplete) else None
    probes = []
    for probe, label_value in [(p, "PRESENT") for p in label["present"]] + [
        (p, "ABSENT") for p in label["absent"]
    ]:
        answer, reason = _probe_outcome(first, probe)
        probes.append({"probe": probe, "label": label_value, "answer": answer, "reason": reason})
    record["probes"] = probes
    return record


def _metrics(probes: list[dict[str, Any]]) -> dict[str, Any]:
    decided = [p for p in probes if p["answer"] in ("PRESENT", "ABSENT")]
    agree_decided = sum(1 for p in decided if p["answer"] == p["label"])
    agree_all = sum(1 for p in probes if p["answer"] == p["label"])
    false_absent = [p for p in probes if p["label"] == "PRESENT" and p["answer"] == "ABSENT"]
    wrong_present = [p for p in probes if p["label"] == "ABSENT" and p["answer"] == "PRESENT"]
    return {
        "probes": len(probes),
        "decided_probes": len(decided),
        "decided_accuracy": (agree_decided / len(decided)) if decided else None,
        "strict_agreement": (agree_all / len(probes)) if probes else None,
        "false_absent": [(p["probe"], p["label"], p["answer"]) for p in false_absent],
        "wrong_present": [(p["probe"], p["label"], p["answer"]) for p in wrong_present],
    }


def _summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    packages = [r for r in records if "error" not in r]
    all_probes = [p for r in packages for p in r["probes"]]
    decided_packages = [r for r in packages if r["package_status"] == "complete"]
    summary: dict[str, Any] = {
        "packages": len(records),
        "errors": [(r["id"], r["error"]) for r in records if "error" in r],
        "decided_packages": len(decided_packages),
        "coverage_packages": (len(decided_packages) / len(records)) if records else None,
        "probe_coverage": None,
        "total": _metrics(all_probes),
        "by_ecosystem": {},
        "by_hard_case": {},
    }
    summary["probe_coverage"] = sum(
        1 for p in all_probes if p["answer"] in ("PRESENT", "ABSENT")
    ) / len(all_probes)
    for key, field in (("by_ecosystem", "ecosystem"), ("by_hard_case", "hard_case")):
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in packages:
            groups[str(record.get(field))].append(record)
        for group, members in sorted(groups.items()):
            group_probes = [p for r in members for p in r["probes"]]
            summary[key][group] = {
                "packages": len(members),
                "decided_packages": sum(1 for r in members if r["package_status"] == "complete"),
                **_metrics(group_probes),
            }
    expected_unknown = [r for r in packages if r["expected_status"] == "unknown"]
    summary["expected_unknown"] = {
        "packages": len(expected_unknown),
        "agree": [
            r["id"]
            for r in expected_unknown
            if r["package_status"] == "unknown" and r["package_reason"] == r["expected_reason"]
        ],
        "deviation_complete": [
            r["id"] for r in expected_unknown if r["package_status"] == "complete"
        ],
        "deviation_other": [
            (r["id"], r["package_status"], r["package_reason"], r["expected_reason"])
            for r in expected_unknown
            if r["package_status"] != "complete" and r["package_reason"] != r["expected_reason"]
        ],
    }
    expected_complete = [r for r in packages if r["expected_status"] == "complete"]
    summary["expected_complete_not_complete"] = [
        (r["id"], r["package_status"], r["package_reason"])
        for r in expected_complete
        if r["package_status"] != "complete"
    ]
    summary["record_mismatches"] = [
        (r["id"], r["package_detail"])
        for r in packages
        if r["package_reason"] == "parse_error" and "RECORD" in (r["package_detail"] or "")
    ]
    summary["digest_mismatches"] = [
        r["id"] for r in packages if r["package_status"] == "digest_mismatch"
    ]
    summary["label_checks"] = [
        (
            r["id"],
            "filename" if not r["filename_matches_label"] else "",
            "digest" if not r["digest_matches_label"] else "",
        )
        for r in packages
        if not (r["filename_matches_label"] and r["digest_matches_label"])
    ]
    cold = [r["uncached_ms"] for r in packages]
    warm = [r["cached_ms"] for r in packages if r["package_status"] == "complete"]
    summary["latency"] = {
        "uncached_ms_median": statistics.median(cold) if cold else None,
        "uncached_ms_max": max(cold) if cold else None,
        "cached_ms_median_complete": statistics.median(warm) if warm else None,
        "cached_ms_max_complete": max(warm) if warm else None,
    }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None, help="write the full JSON result here")
    parser.add_argument("--labels", default=str(LABELS), help="a labels file (tests only)")
    args = parser.parse_args(argv)
    labels_path = Path(args.labels)
    labels = json.loads(labels_path.read_text(encoding="utf-8"))["packages"]
    digest = hashlib.sha256(labels_path.read_bytes()).hexdigest()
    records: list[dict[str, Any]] = []
    for label in labels:
        with tempfile.TemporaryDirectory() as state:
            live = LiveSource(cache_root=Path(state))
            records.append(_run_package(label, live))
        print(f"done {label['id']}", file=sys.stderr)
    summary = _summarise(records)
    result = {"labels_sha256": digest, "summary": summary, "packages": records}
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=1, sort_keys=True, default=str))
    print(f"labels_sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
