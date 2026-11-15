# SlopSeal Demo Script

Source: `PRD.md`, Demo Scripts section.

**Phase 3 status.** The runnable demo is the deterministic (fallback) path, and it is what
`scripts/demo.sh` executes. It runs against the signed offline snapshot in a throwaway state
directory, asserts the exit code and key fields at every beat, and fails loudly if any beat
regresses. The primary path adds the Needle purpose check (L2). L2 is gated at M1 and is not
built yet, so the primary script's purpose beat does not run in this release.

Run it:

```bash
pip install -e ".[dev]"
bash scripts/demo.sh
```

**Fixture requirement:** `csv-parser-pro` must be absent from the offline registry snapshot.
The real registry may contain it, so the demo depends on the snapshot, not live data.

---

## Beats (deterministic path)

| Beat | Command | Expected |
|------|---------|----------|
| 1. Slopsquat-style name | `slopseal check csv-parser-pro --version 0.1.0` | exit 1; DependencyViolation with check `existence` and remedy `Did you mean csv-parser?` |
| 2. API mismatch | `slopseal check csv-parser --version 1.2.0 --expected-api csv.reader --purpose "parse CSV"` | exit 75; payload with `mismatch_type: api_absent`, `found_apis` (`parse`, `parse_file`), `retry_budget_remaining: 1`, no confidence field; `csv` suggested |
| 3. Retry | the same command with `--expected-api parse --quarantine-id <id>` | exit 0; ALLOW |
| 4. Audit intact | `slopseal audit verify` | exit 0 |
| 5. Tampering | flip one verdict in a copy of the log, then verify | exit 1 |
| 6. Weakened policy | `slopseal policy check <weakened copy>` | exit 1; floor violated |

## Primary path (adds L2, after M1)

Same beats 1, 2, and 4 to 6. Beat 3 adds purpose-level scoring with Needle 3 before ALLOW.
Voiceover at about 1:15: "The deterministic check confirms the API exists; purpose-level
verification is what Needle adds, and that's what we're testing this week."

## Known limitation (for the write-up)

The deterministic trigger checks that the declared API exists, not that it fits the purpose.
A retry that declares a real exported API passes even if the package is wrong for the task.
P2 (silent semantic mismatch) is covered fully only if L2 ships.
