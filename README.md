# SlopSeal

**Every install gets a seal. Every seal is a verdict. Every verdict is a receipt.**

SlopSeal is a dependency trust firewall for AI coding agents. Before a package is installed, it returns a signed verdict. Its rulebook is a Kiro steering file, and that rulebook is property-tested so the agent it governs cannot quietly weaken it.

Built for Kiroween 2026 (Frankenstein category). License: MIT.

> **Status:** Pre-alpha. The deterministic core, the policy guard, the quarantine state machine, the audit log, and the CLI are built and tested. The semantic layer (L2) was tested against the Needle 3 model and failed its pre-registered gate, so it is not in v1. Live registry access is not built, so live mode blocks every check. Nothing here is ready for production use.

## The problem

AI coding agents run `pip install` and `npm install` from LLM suggestions.

- **Slopsquatting.** The model invents a plausible package name. An attacker registers it with malware.
- **Semantic mismatch.** The package is real and safe but does not do what the agent needed. No CVE scanner flags it.
- **Policy erosion.** Dependency rules live in wikis. When one is weakened, nothing records it.

## How it works

For each install, `verify_install(package, version, intent?)` runs in order:

1. **Policy and snapshot checks.** A missing or malformed policy exits 78. A bad snapshot signature blocks.
2. **Deterministic checks (L1).** Registry existence, typosquat, slopsquat signatures, package age, install scripts, OSV advisories and malware feed, allow and deny lists, license, maintainer, near-name similarity.
3. **Intent check.** If the agent declares the API it expects, SlopSeal compares it to the package's real exports. A mismatch is a QUARANTINE with one bounded retry, then escalation to a human.
4. **Semantic check (L2, optional).** An on-device model (Needle 3) can add a purpose-level check. It is advisory and can only move ALLOW to QUARANTINE. It ships only if it passes a numeric gate (see `PRD.md`).
5. **Seal.** The decision is written to an append-only audit log and signed.

| Exit code | Meaning |
|-----------|---------|
| 0 | ALLOW |
| 1 | BLOCK |
| 75 | QUARANTINE: retry with a refined intent, or escalate |
| 78 | Policy missing or malformed |

SlopSeal never uses the calling agent's LLM.

## How Kiro constitutes the policy

`.kiro/` is part of the product, not documentation.

| Kiro feature | What it is here |
|--------------|-----------------|
| Steering | `dependency-trust.md` holds the trust policy that the code loads at run time |
| Specs | `.kiro/specs/seal/` holds requirements (EARS), design, and the property contract |
| Hooks | `on-install.json` triggers the check on installs. `on-steering-change.json` runs the property suite on policy edits |
| Properties | Hypothesis tests assert that unknown state always blocks. A pre-commit guard rejects a policy edit that fails them |

## Repository map

| Path | Purpose |
|------|---------|
| `PRD.md` | Product requirements, scope, milestones |
| `.kiro/specs/seal/` | Requirements, design, properties |
| `.kiro/steering/` | Agent-facing product, tech, and structure rules; the trust policy |
| `src/slopseal/` | Implementation |
| `src/tests/` | Unit, property, and integration tests |
| `docs/` | Plan, demo script, threat model, failure taxonomy, architecture, ADRs |
| `AGENTS.md` | Rules for coding agents |

## Quick start

```bash
pip install -e ".[dev]"
bash scripts/demo.sh                                   # end-to-end demo, offline snapshot
SLOPSEAL_OFFLINE_SNAPSHOT=1 slopseal check csv-parser --version 1.2.0 --expected-api csv.reader
slopseal audit verify
slopseal policy check
```

| Exit code | Meaning |
|-----------|---------|
| 0 | ALLOW |
| 1 | BLOCK (DependencyViolation JSON on stderr) |
| 75 | QUARANTINE (payload JSON on stdout). CI fails on 75 unless the job opts in to a pause |
| 78 | Policy, key, or state directory is unusable. No verdict is issued |

## Development

Requires Python 3.11 or newer.

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy src/slopseal
pytest
```

Contributors and agents: read `CONTRIBUTING.md` and `AGENTS.md` first.

## Roadmap

In v1: pip and npm checks, PATH shim, `verify_install`, quarantine, audit log with signed seals, replay, policy diff, offline snapshot. After v1: registry proxy, SARIF output, local dashboard, MCP server, Windows support.

## Limitations

- The deterministic intent check confirms a declared API exists in the package's exports. It does not confirm the package fits the purpose. Only the optional L2 layer addresses purpose, and it is gated.
- SlopSeal does not scan package source for vulnerabilities and does not police runtime behavior after install.

## Security

Report vulnerabilities as described in `SECURITY.md`.

## License

MIT. See `LICENSE`.
