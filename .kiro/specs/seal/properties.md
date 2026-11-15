# SlopSeal: Property-Based Testing Contract

**Source:** `PRD.md` (Fail-Closed Invariant, Quarantine, Acceptance Criteria) and `requirements.md`.
**Runner:** Hypothesis (Python). The PBT suite runs in `src/tests/properties/` and is triggered by `on-steering-change.json` and the pre-commit guard.
**Minimum cases:** 500 per run (R-PBT-1).

---

## 1. Fail-closed invariant

**P-FC-1 (unknown policy blocks).** For any package name, version, and intent, if the policy file is missing, unreadable, or malformed, the verdict is BLOCK with exit 78. Verdict is never ALLOW or QUARANTINE.

**P-FC-2 (unknown registry blocks).** For any package, if the registry snapshot is unreachable, times out, or returns a partial record, the verdict is BLOCK with exit 1. Verdict is never ALLOW.

**P-FC-3 (unknown exports block).** For any intent declaring an `expected_api`, if the package's exported symbols are unknown or partial, the verdict is BLOCK. It is never QUARANTINE (R-Q-2).

**P-FC-4 (no quarantine without intent check).** Exit 75 is produced only when the deterministic API check (`api_absent`) or the L2 check (`l2_low_confidence`) fires. Any other reason for exit 75 is a failure.

**P-FC-5 (L2 is advisory).** For any L2 output, including confidence 0.0 and 1.0, the system never returns exit 1 because of L2 alone (R-3.7).

**P-FC-6 (hard blocks dominate).** For any input where a HARD_BLOCK check fires, the verdict is HARD_BLOCK, regardless of the intent, the L2 output, or the WARN checks.

**P-FC-7 (monotonic policy strictness).** For a policy P and a stricter policy P' (any allow entry removed, any threshold lowered to a stricter value), no input that P blocks may become ALLOW under P'. The generator constructs P' by applying one strictness-increasing edit to P.

**P-FC-8 (weakening is detected).** For any policy edit that removes a fail-closed clause (for example, changes the unknown-state rule from BLOCK to ALLOW), the property suite fails. This is the test that the pre-commit guard depends on.

## 2. Typosquat and near-name rules

**P-TY-1 (typosquat is an intersection).** For any package, HARD_BLOCK with check `typosquat` requires both distance ≤ 2 to a top-N package and age < 30 days. A package with distance ≤ 2 and age ≥ 30 days never receives this HARD_BLOCK. A package with age < 30 days and distance > 2 never receives it.

**P-TY-2 (near-name is WARN only).** For any package, the near-name check (2.11) produces WARN or no result. It never produces HARD_BLOCK, regardless of age.

**P-TY-3 (near-name coverage).** For any top-N name and any single-character substitution by a keyboard-adjacent key, the near-name check (R-2.11) fires.

**P-TY-4 (keyboard clause is subsumed by Levenshtein).** Mathematically, a keyboard-adjacent substitution is a single edit, so its Levenshtein distance is 1. Therefore the keyboard clause of R-2.11 (keyboard distance ≤ 1) is always implied by the Levenshtein clause (distance ≤ 3). The clause is retained in R-2.11 as explicit documentation of the keyboard-adjacency threat. It changes no verdict under the current rule. Any future change that adds coverage through the keyboard clause must use a different metric, such as a weighted keyboard distance, and must add a property that distinguishes it from Levenshtein. The test `test_r_2_11_keyboard_clause_is_subsumed_by_levenshtein` enforces this statement.

## 3. Quarantine state machine

**P-SM-1 (termination).** For any sequence of up to 2 install attempts with the same `quarantine_id`, the state machine reaches a terminal exit code (0, 1, 75 with retry budget 0, or 78) within the configured bound.

**P-SM-2 (retry budget).** For any quarantine, `retry_budget_remaining` starts at 1. A second retry request returns the escalation artifact and exit 75 with budget 0, never a third check.

**P-SM-3 (retry re-checks).** For any retry, the API-surface check runs again on the refined intent. The retry never reuses the first result.

**P-SM-4 (payload shape).** For any QUARANTINE, the payload contains exactly the fields in R-Q-3, and `confidence` is absent.

**P-SM-5 (no confidence leak).** For any QUARANTINE payload, no numeric confidence value appears in the payload. L2 confidence is written to the audit log only.

## 4. Audit and seals

**P-AU-1 (one line per verdict).** For any sequence of verdicts, the JSONL log has exactly one line per verdict, in order.

**P-AU-2 (seal verifies).** For any verdict seal, the signature verifies against the signing key and the sealed fields. Changing any sealed field makes verification fail.

**P-AU-3 (replay reproduces; post-hackathon roadmap, not in v1).** For any historical install record, replaying with the recorded snapshot and policy hash produces the same verdict and exit code.

## 5. Snapshot integrity

**P-SN-1 (tamper detection).** For any single-byte change to the snapshot file, checksum verification fails and the verdict is BLOCK.

**P-SN-2 (determinism).** For any package and snapshot, two runs produce byte-identical verdicts and payloads.

---

## Generator strategy

| Generator | Produces | Used by |
|-----------|----------|---------|
| `gen_package_name` | Unicode confusables, near-miss plurals, compound hallucinations, Levenshtein distances 0–4 from a top-N name | P-TY-*, P-FC-6 |
| `gen_keyboard_substitution` | One-character substitution by a keyboard-adjacent QWERTY key | P-TY-3 |
| `gen_intent` | Valid intents, and malformed intents (missing fields, wrong types, empty strings, oversized values) | P-FC-*, P-SM-* |
| `gen_registry_state` | Available, unreachable, timed out, partial record | P-FC-2, P-FC-3 |
| `gen_policy` | Valid policies, partial policies (missing sections), malformed policies, and one strictness-increasing edit | P-FC-1, P-FC-7, P-FC-8 |
| `gen_l2_output` | Confidence values from 0.0 to 1.0, including boundary values | P-FC-5 |
| `gen_quarantine_sequence` | Sequences of up to 3 attempts with the same `quarantine_id` | P-SM-* |
| `gen_snapshot_bytes` | Valid snapshot, and single-byte mutations at random offsets | P-SN-1 |

**Case count:** Each property runs at least 500 generated cases per run (R-PBT-1). The suite's run configuration sets `max_examples` to 500 or more.

---

## Pass criteria

- Every property above passes on the current policy.
- Each property is exercised by at least one generator from the table.
- Any failure blocks the commit (pre-commit guard) and is reported by `on-steering-change.json`.
- Zero fail-closed violations are tolerated.

## Mapping to requirements

| Property | Requirements |
|----------|--------------|
| P-FC-1 | R-1.4, R-V-1 |
| P-FC-2 | R-P-1 |
| P-FC-3 | R-Q-2 |
| P-FC-4 | R-Q-1, R-Q-4 |
| P-FC-5 | R-3.7 |
| P-FC-6 | R-V-2 |
| P-FC-7, P-FC-8 | R-PBT-2 |
| P-TY-1 | R-2.2, R-2.2a |
| P-TY-2, P-TY-3 | R-2.11 |
| P-SM-1, P-SM-2, P-SM-3 | R-Q-5, R-Q-6, R-Q-7 |
| P-SM-4, P-SM-5 | R-Q-3 |
| P-AU-1, P-AU-2, P-AU-3 | R-5.7.1, R-5.7.2, R-5.7.3 |
| P-SN-1, P-SN-2 | R-P-2 |
