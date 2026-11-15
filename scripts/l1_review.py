"""L1 threshold review: run the deterministic checks over the labeled fixture corpus.

Reads docs/l1_review_labels.json (committed before any run) and reports, per package, the
verdict and the check that produced it. It then prints the confusion counts that the review
write-up uses. The script never edits the policy or the labels.

The rate limit is off for this run. It is a per-minute cap on attempts, not an L1 check, and
23 packages would otherwise hit it.

Usage: python scripts/l1_review.py   (uses the offline snapshot, prints JSON lines + summary)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LABELS = REPO / "docs" / "l1_review_labels.json"

os.environ["SLOPSEAL_OFFLINE_SNAPSHOT"] = "1"
os.environ.setdefault(
    "SLOPSEAL_POLICY_PATH", str(REPO / ".kiro" / "steering" / "dependency-trust.md")
)

from slopseal.core.types import Ecosystem  # noqa: E402
from slopseal.runtime import build_context  # noqa: E402
from slopseal.verdict import InstallRequest, Outcome, verify_install  # noqa: E402

ECOSYSTEM = {"pypi": Ecosystem.PYPI, "npm": Ecosystem.NPM}
EXPECTED = {
    "slopsquat": Outcome.BLOCK,
    "typosquat": Outcome.BLOCK,
    "legit-new": Outcome.ALLOW,
    "legit-old": Outcome.ALLOW,
}


def main() -> int:
    labels = json.loads(LABELS.read_text(encoding="utf-8"))["labels"]
    with tempfile.TemporaryDirectory() as state:
        os.environ["SLOPSEAL_STATE_DIR"] = state
        context = build_context(Path(state), rate_limited=False)
        rows = []
        for eco_name, names in labels.items():
            for name, label in names.items():
                decision = verify_install(
                    InstallRequest(ecosystem=ECOSYSTEM[eco_name], package=name), context
                )
                check = decision.violation.check if decision.violation else None
                rows.append(
                    {
                        "ecosystem": eco_name,
                        "package": name,
                        "label": label,
                        "version": decision.version,
                        "outcome": decision.outcome.value,
                        "check": check,
                        "expected": EXPECTED[label].value,
                        "correct": decision.outcome is EXPECTED[label],
                    }
                )
                print(json.dumps(rows[-1], sort_keys=True))

    attacks = [r for r in rows if r["label"] in ("slopsquat", "typosquat")]
    legit = [r for r in rows if r["label"] in ("legit-new", "legit-old")]
    attacks_blocked = sum(r["outcome"] == "BLOCK" for r in attacks)
    legit_flagged = sum(r["outcome"] != "ALLOW" for r in legit)
    print(f"summary: attacks {attacks_blocked}/{len(attacks)} BLOCK")
    print(f"summary: legit {legit_flagged}/{len(legit)} flagged (BLOCK or QUARANTINE)")
    print(f"summary: total packages {len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
