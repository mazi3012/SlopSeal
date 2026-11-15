---
inclusion: always
---

# SlopSeal: Product Context

SlopSeal is a dependency trust firewall for AI coding agents. Before a package is installed, SlopSeal returns a signed verdict: ALLOW, BLOCK, or QUARANTINE.

**Full context:** `PRD.md` (product), `.kiro/specs/seal/requirements.md` (behavior), `.kiro/specs/seal/design.md` (structure), `.kiro/specs/seal/properties.md` (invariants). Read the relevant file before changing behavior. Do not restate them here.

## What it prevents

- **P1 Slopsquatting:** an LLM hallucinates a package name and an attacker has registered it.
- **P2 Semantic mismatch:** a real, safe package that does not do what the agent needs.
- **P3 Policy erosion:** a dependency rule weakened with no trace.

## Non-negotiables

1. **Fail closed.** Unknown policy, unknown registry state, a bad snapshot, or an unexpected exception means BLOCK. Nothing returns ALLOW by default.
2. **Policy is data.** Thresholds and lists live in `.kiro/steering/dependency-trust.md`. They are never literals in code.
3. **Never use the calling agent's LLM.** L2, if enabled, runs separately and is advisory only. It can raise QUARANTINE and cannot block.
4. **Deterministic.** Same inputs, same bytes out. Time is injected.
5. **The fail-closed property tests are the safety net.** Do not weaken, skip, or delete one to make a change pass.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | ALLOW |
| 1 | BLOCK |
| 75 | QUARANTINE |
| 78 | Policy error |

## Scope

In v1: pip and npm checks, PATH shim, `verify_install`, quarantine, JSONL audit with signed seals, policy diff (CLI), offline snapshot, property suite. Not in v1: registry proxy, SARIF, dashboard, MCP server, Windows, replay (post-hackathon roadmap). Do not add them without a PRD change.

## Current phase

See `docs/PLAN.md` for the day-level plan and `PRD.md` Schedule for milestones (M1 Nov 26, M2 Nov 27, M3 Nov 30, M4 Dec 3).
