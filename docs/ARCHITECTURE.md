# SlopSeal Architecture Guide

This file is an index. The design lives in `.kiro/specs/seal/design.md` so there is one source of truth.

## Where to look

| Question | Read |
|----------|------|
| What is the product and what is in scope? | `PRD.md` |
| What must the system do? | `.kiro/specs/seal/requirements.md` |
| What must always hold? | `.kiro/specs/seal/properties.md` |
| How is it built? Module map, types, pipeline | `.kiro/specs/seal/design.md` sections 1–6 |
| What does the policy file look like? | `design.md` section 7 |
| How is the snapshot built and verified? | `design.md` section 8 |
| How does quarantine work? | `design.md` section 9 |
| What does the audit log contain? | `design.md` section 10 |
| How are installs intercepted? | `design.md` section 11 |
| What are the risks and limits? | `docs/THREAT_MODEL.md`, `docs/FAILURE_TAXONOMY.md` |
| What is the plan and where are we? | `docs/PLAN.md` |
| Why was a choice made? | `docs/adr/` |
| How do I work here? | `CONTRIBUTING.md`, `AGENTS.md`, `.kiro/steering/` |

## Shape in one paragraph

One function, `verify_install`, turns a package, a policy, and a snapshot (or live registry) into a `Decision`. Callers (PATH shim, CLI, Kiro hook) only map that decision to an exit code. Checks are pure functions behind small Protocols, so offline mode, tests, and replay swap the I/O without touching logic. Anything unknown or unexpected becomes BLOCK in one wrapper.

## Keeping this current

When a section of `design.md` is renumbered, update the pointers above. Do not copy design content into this file.
