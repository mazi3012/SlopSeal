# SlopSeal Build Plan (Day-Level)

This plan is operational. It can change without a PRD version bump. The phases, exit criteria, and milestones (M1–M4) are defined in `PRD.md`, Schedule section. If a day's work changes a milestone date, update the PRD first.

Day 1 is Nov 15, 2026.

| Day | Date | Phase | Work | Done when |
|-----|------|-------|------|-----------|
| 1 | Nov 15 | 0 | Specs drafted (requirements, properties), demo script in `docs/DEMO_SCRIPT.md`, first commit | First commit pushed. Devpost page checked. |
| 2 | Nov 16 | 0 | `design.md` | Design reviewed against PRD |
| 3 | Nov 17 | 0 | `properties.md` final, spec review against PRD | Phase 0 exit criterion met |
| 4 | Nov 18 | 1 | Fixture corpus: 20 packages (5 of each class). Top-N snapshot dated Nov 18. | Corpus file committed |
| 5 | Nov 19 | 1 | Signed snapshot format, snapshot v0 | Snapshot verifies; tampered copy fails |
| 6 | Nov 20 | 1 | L1 checks 2.1–2.4 | Unit tests pass on corpus |
| 7 | Nov 21 | 1 | L1 checks 2.5–2.11, PBT generators | Unit tests pass on corpus |
| 8 | Nov 22 | 1 | PBT suite, ≥500 cases. Sub-agent feasibility (Open Decision 1). | Phase 1 exit criterion met |
| 9 | Nov 23 | 2 | `dependency-trust.md`, pre-commit guard | Guard rejects a failing policy edit |
| 10 | Nov 24 | 2 | Both hooks. Decide Open Decisions 3 and 6. | Phase 2 exit criterion met |
| 11 | Nov 25 | 3 | Deterministic quarantine: state machine, exit 75 payload, retry, escalation. No L2 work. | Quarantine tests pass |
| 12 | Nov 26 | 3 | Needle spike on the labeled set only. Commit `docs/needle_spike.csv`. | **M1** |
| 13 | Nov 27 | 4 | JSONL log, signed seals, end-to-end deterministic demo, tag `v0.1.0-deterministic` | **M2** |
| 14 | Nov 28 | 5 | PATH shim, `verify_install`, replay, policy diff CLI | Shim and API run; replay reproduces a verdict |
| 15 | Nov 29 | 5 | L2 integration if M1 passed, else hardening. Expand corpus toward 100. | Phase 5 exit criterion met |
| 16 | Nov 30 | 6 | Corpus frozen, count recorded. Hardening only. | **M3** |
| 17 | Dec 1 | 6 | Demo recording (3 minutes, offline snapshot). README. | Video hosted on YouTube or Vimeo |
| 18 | Dec 2 | 6 | Kiro write-up, Devpost draft, candidate tag `v1.0.0-kiroween`. Bug fixes only. | Draft submission complete |
| 19 | Dec 3 | 7 | Submit before 2:00 PM PT. Final tag `v1.0.0-kiroween`. | **M4** |
| — | Dec 4 | — | Emergency buffer | Used only if M4 failed |

## Rules for this file

- Each day has one phase.
- A missed "Done when" moves the day's work to the next day. If that pushes a milestone, the PRD changes first.
- Fallback rules are in `PRD.md`, Schedule section, under "Fallback checkpoint (M2)".
