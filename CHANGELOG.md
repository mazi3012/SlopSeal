# Changelog

All notable changes to this project are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Phase 3: `verify_install` pipeline, quarantine state machine (one retry, escalation artifact, expiry), JSONL audit log with a hash chain and HMAC-SHA256 seals, and the `slopseal` CLI with exit codes 0, 1, 75, and 78.
- Offline fixture snapshot with a static SHA-256 checksum manifest (Open Decision 6, resolved). The fixtures are hand-written for the demo and tests. They are not a registry index.
- Registry adapter with explicit unknown values; live mode is a fail-closed stub.
- End-to-end demo script (`scripts/demo.sh`), run in CI.

### Changed
- Needle 3 spike (M1 gate) run against a pre-registered labelled set. The gate failed (match-allow 0.40, mismatch-allow 0.00). L2 is not in v1. Evidence: `docs/needle_spike.csv`.

### Fixed
- The first audit event on an empty log was dropped. Genesis and the first event are now written in one locked write.
- The CI property job matched zero tests. It now runs the whole suite.

### Added
- Product requirements document (`PRD.md`).
- Specs: requirements (EARS), design, and property contract in `.kiro/specs/seal/`.
- Steering for agents: product, tech, and structure in `.kiro/steering/`.
- Project docs: build plan, demo script, threat model, failure taxonomy, architecture, ADR index.
- Project scaffolding: `pyproject.toml`, package skeleton, tooling config, CI workflows, PR template.
- Reserved `slopseal` console script. The stub exits 1 with "not implemented" until Phase 1.
- Optional extras: `slopseal[needle]` (empty until the M1 gate passes) and `slopseal[dev]`.
- `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`.
