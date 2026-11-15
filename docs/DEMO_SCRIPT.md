# SlopSeal Demo Script (3 minutes)

Source: `PRD.md`, Demo Scripts section. Both scripts are Day 1 deliverables. Record in offline fixture mode: `SLOPSEAL_OFFLINE_SNAPSHOT=1`.

**Fixture requirement:** `csv-parser-pro` must be absent from the offline registry snapshot. The real registry may contain it, so the demo depends on the snapshot, not live data.

---

## Primary (Needle gate passed)

| Time | Beat |
|------|------|
| 0:00–0:25 | Kiro agent runs `pip install csv-parser-pro`. SlopSeal blocks at the existence check. Typed error: `DependencyViolation {check: 'existence', remedy: 'Did you mean csv-parser?'}` |
| 0:25–0:55 | Agent runs `csv-parser` with intent `{purpose: 'parse CSV', expected_api: 'csv.reader'}`. The deterministic check finds that `csv.reader` is not among the exported symbols (`parse`, `parse_file`). Exit 75 with `mismatch_type: api_absent`, `found_apis`, `suggested_alternatives`, and `retry_budget_remaining: 1`. |
| 0:55–1:25 | Agent retries with refined intent, declaring the expected API as `parse` and the package as `csv-parser`. The API check passes. L2 scores the purpose and clears the threshold. ALLOW. Seal written to the audit log with a signed receipt. |
| 1:15 (narration over the retry) | Voiceover: "The deterministic check confirms the API exists; purpose-level verification is what Needle adds, and that's what we're testing this week." |
| 1:25–2:15 | Developer tries to weaken the fail-closed rule in `.kiro/steering/dependency-trust.md`. The on-steering-change hook runs the property suite with hundreds of synthetic cases. The weakened rule fails a property. The pre-commit guard rejects the edit. |
| 2:15–2:45 | Audit log, signed seals, policy diff (CLI output), and the `.kiro/` tree on screen. |
| 2:45–3:00 | Final slide: "The seal is not built with Kiro. The seal IS Kiro." |

## Fallback (deterministic only)

Same as primary, with these changes:

- 0:55–1:25: The retry passes the deterministic API check. The verdict is ALLOW with no L2 step. The write-up states that purpose is not verified in this mode (see the known limitation).
- The audit and seal beats show the same content.

---

## Known limitation (for the write-up)

The deterministic trigger checks that the declared API exists, not that it fits the purpose. A retry that declares a real exported API passes even if the package is wrong for the task. P2 (silent semantic mismatch) is covered fully only if L2 ships.
