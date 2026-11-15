# SlopSeal Build Plan (Day-Level)

This plan is operational. It can change without a PRD version bump. The phases, exit criteria, and milestones (M1–M4) are defined in `PRD.md`, Schedule section. If a day's work changes a milestone date, update the PRD first.

Day 1 is Nov 15, 2026.

The **Completed** column gives the UTC merge date of the pull request that finished the work. Every PR (#1 to #7) merged on Nov 15, 2026, which was ahead of the day-level dates in the **Date** column. The Date column is the original plan and is kept for reference.

| Day | Date | Phase | Work | Done when | Completed |
|-----|------|-------|------|-----------|-----------|
| 1 | Nov 15 | 0 | Specs drafted (requirements, properties), demo script in `docs/DEMO_SCRIPT.md`, first commit | First commit pushed. Devpost page checked. | Nov 15, 2026 (PR #1). The Devpost rules page returned HTTP 403, so the form is checked again before submission (open). |
| 2 | Nov 16 | 0 | `design.md` | Design reviewed against PRD | Nov 15, 2026 (PR #1) |
| 3 | Nov 17 | 0 | `properties.md` final, spec review against PRD | Phase 0 exit criterion met | Nov 15, 2026 (PR #1) |
| 4 | Nov 18 | 1 | Fixture corpus: 20 packages (5 of each class). Top-N snapshot dated Nov 18. | Corpus file committed | Nov 15, 2026 (PR #2). Corpus has 23 records (5 slopsquat, 5 typosquat, 5 legit-new, 8 legit-old). |
| 5 | Nov 19 | 1 | Signed snapshot format, snapshot v0 | Snapshot verifies; tampered copy fails | Nov 15, 2026 (PR #2). Checksum manifest, not a signature (THREAT_MODEL section 6). |
| 6 | Nov 20 | 1 | L1 checks 2.1–2.4 | Unit tests pass on corpus | Nov 15, 2026 (PR #2) |
| 7 | Nov 21 | 1 | L1 checks 2.5–2.11, PBT generators | Unit tests pass on corpus | Nov 15, 2026 (PR #2) |
| 8 | Nov 22 | 1 | PBT suite, ≥500 cases. Sub-agent feasibility (Open Decision 1). | Phase 1 exit criterion met | Nov 15, 2026 (PR #2). Sub-agent path not used; moved to roadmap (Open Decision 1). |
| 9 | Nov 23 | 2 | `dependency-trust.md`, pre-commit guard | Guard rejects a failing policy edit | Nov 15, 2026 (PR #3) |
| 10 | Nov 24 | 2 | Both hooks. Decide Open Decisions 3 and 6. | Phase 2 exit criterion met | Nov 15, 2026 (PR #3). Decisions 3 and 6 resolved in Phase 3. |
| 11 | Nov 25 | 3 | Deterministic quarantine: state machine, exit 75 payload, retry, escalation. No L2 work. | Quarantine tests pass | Nov 15, 2026 (PR #4) |
| 12 | Nov 26 | 3 | Needle spike on the labeled set only. Commit `docs/needle_spike.csv`. | **M1** | Nov 15, 2026 (PR #5). Gate failed (match-allow 0.40, mismatch-allow 0.00). L2 not in v1. |
| 13 | Nov 27 | 4 | JSONL log, signed seals, end-to-end deterministic demo, tag `v0.1.0-deterministic` | **M2** | Nov 15, 2026 (PR #4). Tag `v0.1.0-deterministic` at the PR #4 merge. |
| 14 | Nov 28 | 5 | PATH shim, `verify_install`, replay, policy diff CLI | Shim and API run; replay reproduces a verdict | Nov 15, 2026 (PR #6). Shim, `verify_install`, and policy diff done. Replay moved to the post-hackathon roadmap (R-5.7.3). |
| 15 | Nov 29 | 5 | L2 integration if M1 passed, else hardening. Expand corpus toward 100. | Phase 5 exit criterion met | Nov 15, 2026 (PR #6). Hardening path (M1 failed). Corpus not expanded; kept at 23 records. |
| 16 | Nov 30 | 6 | Corpus frozen, count recorded. Hardening only. | **M3** | Nov 15, 2026 (PR #6). Count recorded: 23 records. |
| 17 | Dec 1 | 6 | Demo recording (3 minutes, offline snapshot). README. | Video hosted on YouTube or Vimeo | README done (PR #7). Video recording and upload: open, for the human. |
| 18 | Dec 2 | 6 | Kiro write-up, Devpost draft, candidate tag `v1.0.0-kiroween`. Bug fixes only. | Draft submission complete | Write-up and checklist done (PR #7, Nov 15, 2026). Tag `v1.0.0-kiroween` pushed Nov 15, 2026 (030b773). Devpost draft: open, for the human. |
| 19 | Dec 3 | 7 | Submit before 2:00 PM PT. Final tag `v1.0.0-kiroween`. | **M4** | Open, for the human. Deadline Dec 3, 2026, 2:00 PM PT. |
| — | Dec 4 | — | Emergency buffer | Used only if M4 failed | Not used. |

## Rules for this file

- Each day has one phase.
- A missed "Done when" moves the day's work to the next day. If that pushes a milestone, the PRD changes first.
- Fallback rules are in `PRD.md`, Schedule section, under "Fallback checkpoint (M2)".
