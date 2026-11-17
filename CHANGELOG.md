# Changelog

All notable changes to this project are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Contract Check (seal-v2 Phase 2): in live mode an intent with `--expected-api` checks the package's exports. The artifact is downloaded only for that check, verified against the registry digest, and read statically in a worker subprocess with CPU, memory, file-size, and wall-time limits. PyPI wheels (R-C-2) and npm tarballs (R-C-3) are extracted. An export list that cannot be read completely is UNKNOWN with a typed reason, and UNKNOWN blocks. The contract cache (R-C-6) stores complete contracts under the state directory. Measured on 51 labelled packages: 10 decided, 53 of 54 decided probes agree, no false ABSENT. See `docs/CONTRACT_EVAL.md`, Run 1.
- Verdict-aware install hook (R-G-1 to R-G-10, P-G-1): `slopseal.hooks.on_install` runs the verdict pipeline for each pinned pip or npm package in an agent's shell command. ALLOW exits 0 and the command runs. BLOCK and QUARANTINE exit 2 with the check, the reason, and a fix or next step. Unpinned versions, URLs, other package managers, environment assignments before an install, and any error exit 2. The v2 spec is in `.kiro/specs/seal-v2/`.
- Resolve-then-pin in live mode (R-1.7): an unpinned `pip install x` or `npm install x` is pinned to the verified latest version. The original and rewritten commands are audited. `--no-resolve` or `SLOPSEAL_NO_RESOLVE=1` keeps the refusal.
- `slopseal audit html`: a single self-contained HTML receipt of the audit log. Each verdict shows its badge, checks, warnings, policy hash, and seal status. Light and dark mode. Stdlib only, no scripts or external requests, and all log text is escaped (R-5.7.1, R-5.7.2).
- Live registry adapter (`slopseal.registry.live`): PyPI JSON API, npm registry, and OSV over `urllib`, with timeouts, a size cap, and explicit unknowns (R-P-3). `slopseal check --live` selects it.

### Fixed

- Live mode did not pass the state directory to the contract cache, so complete contracts were never cached (R-C-6). The state directory is now the cache root.
- Rate limit counted an allowed install twice when the install hook and the PATH shim both verified it. One install now counts once, whichever layers run (R-G-11, R-4.7, P-G-2). The limit of 10 per minute is unchanged.

### Changed

- Live mode: a missing maintainer account age is a WARN, not a BLOCK (R-2.10). Existence, typosquat, slopsquat, CVE/OSV, malware, and install-script checks stay fail-closed. Offline behavior is unchanged. Audit verdicts include `warning_details`.
- Offline is the default. Only `SLOPSEAL_OFFLINE_SNAPSHOT=0` selects live mode. Before, an unset variable selected a live source that blocked every check.
- `npx`, `npm exec`, and `npm x` are verified like installs. Their package must be pinned (R-1.6).
- Install hook blocks agent install commands with exit 2 (R-1.1). The documented Kiro block replaces an unsupported ask.

Replay (R-5.7.3) and the other post-hackathon roadmap items are listed in the README.

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
