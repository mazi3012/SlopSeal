# Changelog

All notable changes to this project are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet. Replay (R-5.7.3) and the other post-hackathon roadmap items are listed in the README.

## [1.0.0] - 2026-11-15

Kiroween 2026 release. Tag: `v1.0.0-kiroween`. Frankenstein category.

### Added

- Phase 5 (PR #6): PATH shim for pip and npm (`slopseal.intercept`), install rate limit of 10 installs per minute (R-4.7), `slopseal policy diff OLD NEW`, and an L1 threshold review over the 23 fixture records (`docs/L1_THRESHOLD_REVIEW.md`).
- Phase 4 (PR #5): Needle 3 spike on a pre-registered label set. The gate failed (match-allow 0.40 against a minimum of 0.80; mismatch-allow 0.00 against a maximum of 0.20). L2 is not in v1. The runtime choice is recorded in `docs/adr/0003-needle-runtime.md`.
- Phase 3 (PR #4): `verify_install` pipeline; quarantine state machine with one retry, a 900-second window, and an escalation artifact; hash-chained audit log with HMAC-SHA256 seals per line; `slopseal` CLI with exit codes 0, 1, 75, and 78. Tag `v0.1.0-deterministic` at this merge.
- Phase 2 (PR #3): trust policy in `.kiro/steering/dependency-trust.md`, policy loader and floors, the policy guard (`scripts/policy_checks.sh`, pre-commit and Kiro hook), and the two Kiro hooks.
- Phase 1 (PR #2): L1 checks 2.1–2.11 with Hypothesis property tests; offline fixture snapshot with a SHA-256 checksum manifest.
- Phase 0 (PR #1): specs (EARS requirements, design, properties), steering, project docs, CI workflows, and packaging.
- Kiroween submission materials (PR #7): Kiro write-up (`docs/WRITEUP.md`), README, demo runbook (`docs/DEMO_SCRIPT.md`), and submission checklist.
- End-to-end demo (`scripts/demo.sh`, seven beats), run in CI on Python 3.11 and 3.12.

### Not in v1

- Replay (R-5.7.3). Moved to the post-hackathon roadmap at feature freeze.
- The semantic layer (L2). Its gate failed.
- Live registry access. Live mode blocks every check.
- Package managers other than pip and npm, the registry proxy, SARIF output, the local dashboard, the MCP server, and Windows support.

### Fixed

- The first audit event on an empty log was dropped. The genesis entry and the first event are written in one locked write (Phase 3).
- The escalation artifact was not written when a quarantine window expired (Phase 3).
- The CI property job matched zero tests. It now runs the whole suite (Phase 3).
- CI failed when the optional `needle_rs` import was missing. A mypy override in `pyproject.toml` fixes it (Phase 4).
