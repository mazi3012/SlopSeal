# SlopSeal v2: Property-Based Testing Contract

**Relation to v1:** `.kiro/specs/seal/properties.md` is unchanged and still applies. This file adds properties.
**Runner:** Hypothesis, at least 500 cases per property (R-PBT-1). Tests live in `src/tests/properties/` and are named after the property id.

---

## 1. Gate (Phase 1)

**P-G-1 (the hook exits 0 or 2, and only ALLOW reaches 0).** For any hook payload text, any outcome assignment for the packages that `verify_install` is asked about (each package independently ALLOW, BLOCK, or QUARANTINE), and any result from building the context (success, or one of the handled errors):

1. The exit code is 0 or 2.
2. Stdout is empty.
3. If the command text contains no install, the exit code is 0 and no verdict was requested (R-G-7).
4. If the command text contains an install, the exit code is 0 only if (a) every install in it is verifiable, (b) at least one verdict was requested, and (c) every verdict returned ALLOW.
5. If any verdict returned BLOCK or QUARANTINE, the exit code is 2.
6. If building the context failed and the command contains a verifiable install, the exit code is 2.

Properties 3 and 4 are the part that says "only ALLOW maps to 0". The wording "for any path" in the task covers a command with no install, which has no verdict. That path keeps its v1 exit 0 (R-G-7), because blocking every `ls` would make the hook unusable. The property states it explicitly so the exception cannot grow.

**P-G-1 oracle.** The generator builds each command from pieces whose class is known by construction (no install, verifiable install, unverifiable install), joined by `&&`, `;`, `|`, a newline, or wrapped in `sudo`, `nohup`, `env VAR=val` (which makes the install unverifiable), or `bash -c`. The expected class is computed from the pieces, not from the code under test. A second strategy feeds arbitrary text and arbitrary JSON shapes as the payload and checks only properties 1 and 2, with a verifier that always returns ALLOW. That is the worst case for the exit code.

### Generators

| Generator | Produces | Used by |
|-----------|----------|---------|
| `gen_hook_command` | Commands built from classified pieces, joiners, and wrappers | P-G-1 (3, 4, 5, 6) |
| `gen_hook_payload` | Valid Kiro payloads, JSON with missing or mistyped `tool_input`, arbitrary text | P-G-1 (1, 2) |
| `gen_outcome_map` | An outcome (ALLOW, BLOCK, QUARANTINE) per package name | P-G-1 (4, 5) |
| `gen_build_result` | Context build success, or one of the handled errors | P-G-1 (6) |

## Mapping to requirements

| Property | Requirements |
|----------|--------------|
| P-G-1 | R-G-1, R-G-2, R-G-3, R-G-4, R-G-5, R-G-6, R-G-7, R-G-8 |

## Pass criteria

- P-G-1 passes with 500 or more cases.
- No v1 property is changed, skipped, or given fewer examples.
