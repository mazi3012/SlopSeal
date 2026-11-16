# SlopSeal v2: Property-Based Testing Contract

**Relation to v1:** `.kiro/specs/seal/properties.md` is unchanged and still applies. This file adds properties.
**Runner:** Hypothesis, at least 500 cases per property (R-PBT-1). Tests live in `src/tests/properties/` and are named after the property id.

---

## 1. Gate (Phase 1)

**P-G-1 (the hook exits 0 or 2, only ALLOW reaches 0, and setup failures block).** For any hook payload text, any outcome assignment for the packages that `verify_install` is asked about (each package independently ALLOW, BLOCK, or QUARANTINE), and any setup failure from the set below:

- `none`: no failure.
- `build_policy`, `build_seal_key`, `build_snapshot`, `build_os`: building the context raises a policy, seal key, snapshot, or OS error.
- `import_missing`: the gate module cannot be imported (a missing or broken module).
- `decision_error`: the decision raises an exception.
- `stdin_unreadable`: reading stdin raises.
- `stdin_stalled`: stdin does not close within the stdin timeout.
- `deadline`: the decision does not finish within the deadline.

The property requires:

1. The exit code is 0 or 2.
2. Stdout is empty.
3. Any install verified is one the command names. Nothing is verified after a setup failure.
4. The exit code is 0 only if (a) there is no failure, (b) every install in the command is verifiable, (c) at least one verdict was requested, and (d) every verdict returned ALLOW.
5. If any verdict returned BLOCK or QUARANTINE, the exit code is 2.
6. `stdin_unreadable`, `stdin_stalled`, and `deadline` exit 2 for every payload. The hook cannot know what the command is, or the decision did not finish, so these block whether or not the command has an install (R-G-6).
7. `build_*`, `import_missing`, and `decision_error` exit 2 when the command contains an install. A command with no install never builds the context or loads the gate (R-G-7), so the failure is not on its path and it exits 0.

Property 4 is the part that says "only ALLOW maps to 0". The rule for a command with no install stays as in v1 (R-G-7). Blocking every `ls` because the policy file is broken would make the hook unusable. Property 7 is the scope of "setup error": a setup failure blocks the installs it affects, and the hook blocks on any failure it cannot get past. A setup failure on a non-install command is not a verdict, so it does not change that command's exit code. Owner decision: if you want every setup failure to block every command, the gate must be imported before the command scan, and that changes R-G-7 for the broken-install case.

**P-G-1 oracle.** The generator builds each command from pieces whose class is known by construction (no install, verifiable install, unverifiable install), joined by `&&`, `;`, `|`, a newline, or wrapped in `sudo`, `nohup`, `env VAR=val` (which makes the install unverifiable), or `bash -c`. The expected class is computed from the pieces, not from the code under test. The failure is drawn from the set above and injected at the point where it occurs in the real hook: the context build, the gate import, the gate call, stdin, the stdin stall timer, and the deadline. A second strategy feeds arbitrary text and arbitrary JSON shapes as the payload, and it applies the same failure set, and checks properties 1, 2, 5, and 6, with a verifier that always returns ALLOW. That is the worst case for the exit code.

### Generators

| Generator | Produces | Used by |
|-----------|----------|---------|
| `gen_hook_command` | Commands built from classified pieces, joiners, and wrappers | P-G-1 (3, 4, 5, 7) |
| `gen_hook_payload` | Valid Kiro payloads, JSON with missing or mistyped `tool_input`, arbitrary text | P-G-1 (1, 2, 6) |
| `gen_outcome_map` | An outcome (ALLOW, BLOCK, QUARANTINE) per package name | P-G-1 (4, 5) |
| `gen_setup_failure` | One failure from the set above, injected at its point in the hook | P-G-1 (1, 3, 4, 6, 7) |

## 2. Rate limit across layers (Phase 1)

**P-G-2 (one install, one count).** For any sequence of installs, where each install is one of: a hook call then a shim call for the same package and version (both layers), a hook call alone, or a shim call alone, and where time moves forward by any amount, the number of counted attempts equals the number of counted installs predicted by this model:

- Every hook call counts once (R-G-11).
- A hook call that ALLOWs adds one credit for its install key.
- A shim call counts once when no credit exists for its key, and consumes one credit (without counting) when a credit younger than the 60-second window exists.

A pair of hook and shim calls for one install therefore counts once. The oracle is the model above, a plain counter, not the limiter's code. The sequence stays at or under the limit, so every call is ALLOW and the blocked path is tested by R-4.7.

### Generators

| Generator | Produces | Used by |
|-----------|----------|---------|
| `gen_install_events` | Sequences of up to 10 events: hook or shim call for a key from a small pool (allowed packages and one blocked package), or a time step of 0 to 90 seconds | P-G-2 |

## Mapping to requirements

| Property | Requirements |
|----------|--------------|
| P-G-1 | R-G-1, R-G-2, R-G-3, R-G-4, R-G-5, R-G-6, R-G-7, R-G-8 |
| P-G-2 | R-G-11, R-4.7 |

## Pass criteria

- P-G-1 passes with 500 or more cases.
- No v1 property is changed, skipped, or given fewer examples.
