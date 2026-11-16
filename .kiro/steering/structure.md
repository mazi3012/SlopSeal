---
inclusion: always
---

# SlopSeal: Repository Structure and Rules

## Layout

```
.kiro/
  specs/seal/        requirements.md, design.md, properties.md   (behavior contract)
  steering/          product.md, tech.md, structure.md, dependency-trust.md, llm-backend.md, demo-fixtures.md
  hooks/             on-install.json, on-steering-change.json
src/
  slopseal/
    cli.py           command-line entry point
    verdict.py       pipeline orchestration, Decision, failclosed wrapper
    intercept/       path_shim.py, api.py
    mcp/             server.py (stdio MCP server, slopseal-mcp; R-1.8)
    core/            one file per L1 check (existence.py, typosquat.py, ...)
    semantic/        L2 interface and Needle adapter (gated at M1)
    quarantine/      state_machine.py, payload.py, escalation.py, api_surface.py
    audit/           log.py, seal.py
    policy/          loader.py, diff.py
    fixtures/        checksummed snapshot files
  tests/
    unit/            one file per module or check
    properties/      strategies.py and test_*.py named after property ids
    integration/     CLI and shim as subprocesses, demo path
scripts/             build_snapshot.py, run_pbt.sh, record_demo.sh, install_shims.sh
docs/                ARCHITECTURE.md, THREAT_MODEL.md, FAILURE_TAXONOMY.md, DEMO_SCRIPT.md, PLAN.md, adr/
PRD.md  README.md  AGENTS.md  CONTRIBUTING.md  SECURITY.md  CHANGELOG.md
```

## Where things go

| If you are adding... | Put it in | Also update |
|----------------------|-----------|-------------|
| A new L1 check | `core/<name>.py` | `requirements.md`, `properties.md` if it affects an invariant, unit test |
| A threshold or list | `dependency-trust.md` policy block, read via `policy/` | `design.md` section 7 schema |
| A new exit code or output field | `verdict.py` and `design.md` section 13 | `requirements.md`, PRD |
| A new external service call | A Protocol in `design.md` section 4, then an implementation | `docs/THREAT_MODEL.md` data-sent table |
| A new dependency | `pyproject.toml` | `docs/adr/` entry |

## Import direction

Layers, lowest first: `types` → `fixtures`, `policy` → `core` → `quarantine`, `semantic`, `audit` → `verdict` → `cli`, `intercept`.

A module may import only from layers below it. `core` and `semantic` never import each other. A circular import is a design error: fix the layering, not the import.

## Spec-first rule

Behavior changes start in `.kiro/specs/seal/`. Order of work:

1. Edit `requirements.md` (and `properties.md` if an invariant changes).
2. Edit `design.md` if structure changes.
3. Write or update tests that name the requirement id.
4. Change the code.

If a request conflicts with a requirement or property, stop and flag it. Do not change code to match a request that violates the spec.

## Files agents must not change without an explicit request

- `.kiro/specs/seal/properties.md` (the invariant contract)
- `.kiro/steering/dependency-trust.md` (the live policy; edits are gated by the property suite)
- `src/slopseal/fixtures/` (checksummed; regenerate with `scripts/build_snapshot.py`, never hand-edit)
- `LICENSE`
- Anything under `.git/`

## Traceability

- Every commit message cites a requirement id.
- Every test names the requirement or property it covers.
- Every module docstring lists the requirement ids it implements.
