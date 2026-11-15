# Changelog

All notable changes to this project are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Product requirements document (`PRD.md`).
- Specs: requirements (EARS), design, and property contract in `.kiro/specs/seal/`.
- Steering for agents: product, tech, and structure in `.kiro/steering/`.
- Project docs: build plan, demo script, threat model, failure taxonomy, architecture, ADR index.
- Project scaffolding: `pyproject.toml`, package skeleton, tooling config, CI workflows, PR template.
- Reserved `slopseal` console script. The stub exits 1 with "not implemented" until Phase 1.
- Optional extras: `slopseal[needle]` (empty until the M1 gate passes) and `slopseal[dev]`.
- `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`.
