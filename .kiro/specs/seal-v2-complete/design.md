# SlopSeal v2-complete: Design

Requirements: `requirements.md`. Decision record: ADR 0006. Observation: `reports/SlopSeal_V2_COMPLETE_OBSERVATION.md`. Trust-zone and gateway design that this builds on: `reports/SlopSeal_D2_SECURITY_STATE_ARCHITECTURE.md` and ADR 0004 (draft PR #32).

## 1. Shape of the system

```
 User adds ONE entry:  mcpServers.slopseal  (local command = Tier 0, remote url = Tier 1)
        |
        v
 ZONE A: agent environment (untrusted)
 +--------------------------------------------------------------------------------+
 |  agent shell --PreToolUse--> managed hook --> launcher --(plugged)--> hook module |
 |       |                                          |                                |
 |       | MCP: verify_install, slopseal_settings   +--(unplugged)--> exit 0, delete  |
 |       v                                                                           |
 |  slopseal-mcp (Tier 0, local)  or  MCP client of the service (Tier 1)             |
 +----------|---------------------------------------------------------------------+
            | Tier 1 only: verdict API + gateway, one service credential per session
            v
 ZONE B: SlopSeal service (trusted)           ZONE C: registries
   verifier, policy pin, key, audit, settings  <-- gateway fetches, verifies digest
   rate limit, quarantine, grants, probes
 Platform step (human, once): agent sandbox egress allows only the service host.
```

Tier 0 is the left half only. Tier 1 adds zone B and the platform step. The same code serves both. The Tier 0 server is the Tier 1 service with a local transport and local state.

## 2. Auto-plug and lifecycle

### 2.1 What the server does at start (R-AP-2)

1. Work out the managed hook text for this server version and this interpreter.
2. If no hook file exists, write it (mode `x`, as today).
3. If a managed hook exists and differs, write a temporary file in the same directory and rename it over the old one. Rename is atomic, so a concurrent shell command sees the old or the new file, never half of one.
4. If the file exists and is not managed, leave it and write one stderr line.
5. Start serving. Errors never stop the server (R-1.9).

The managed marker is `slopseal-managed:<server version>` inside the command string. The hook JSON has no comment field and its schema may not allow extra keys, so the marker lives in the command and in the `name` prefix `SlopSeal:`. Issue #56's two copies collapse into one rule: the running server owns the managed file.

### 2.2 The launcher (R-AP-3 to R-AP-6)

Constraints: stdlib only, no SlopSeal imports, under about 60 lines, and its own unit tests. The interpreter that has SlopSeal is passed as `$1`, as today. The launcher itself runs under the system `python3`, because `$1` may no longer exist after the entry is deleted. If there is no `python3`, the launcher cannot decide, so it behaves as indeterminate and the old fail-closed wrapper applies.

```
state = plugged_state()            # plugged | unplugged | indeterminate
if state == unplugged:
    remove managed hook file (only if it carries the marker); print one stderr line; exit 0
rc = run("$1 -m slopseal.hooks.on_install", stdin passed through)
if rc in (0, 2): exit rc
print install hint; exit 2          # plugged or indeterminate, and SlopSeal cannot run
```

`plugged_state` reads every `.kiro/settings/mcp.json` from the working directory up to the filesystem root, and `~/.kiro/settings/mcp.json`. It returns:

- `plugged` if any readable file has an enabled `slopseal` entry.
- `unplugged` if at least one file was read and none has an enabled entry.
- `indeterminate` if no file could be read, or a file is present but not valid JSON.

Why "any enabled entry wins": Kiro lets the workspace file override the user file. A repository the user clones could ship a disabled `slopseal` entry and switch the guard off. The launcher takes the stricter reading. The cost is that a user who disables the entry in the workspace but not in the user file keeps the hook. That is a safe failure.

Why config presence and not a heartbeat: a crash and a deletion look the same to a heartbeat. Only the config tells them apart (ADR 0006).

Where the launcher text lives is decided in task V2C-1.3 by test: inline with `-c` in the hook command, or as a sibling file `slopseal-launch.py` that the server also manages. Inline keeps one file. A sibling file is easier to read and test. The tie-breaker is whether Kiro's hook runner passes a long command intact.

### 2.3 Removal and re-adding

| Action | Result |
|---|---|
| Delete or disable the entry | The next shell command reaches the launcher, state is unplugged, the managed hook deletes itself, exit 0. Nothing of SlopSeal runs again. |
| Add the entry back and connect | The server starts, finds no hook, writes it. Plugged again. |
| Delete the entry while the shell is mid-install | The running command is unaffected. The next command is unprotected. |
| `.slopseal/` after removal | Kept (audit evidence). `slopseal purge` (human command) removes it. |
| Platform egress rule (Tier 1) | Stays. The user removes it where it was set. The uninstall text says so. |

### 2.4 Pinned launch (R-AP-1)

The shipped entry:

```json
{
  "mcpServers": {
    "slopseal": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/mazi3012/SlopSeal.git@v2.0.0", "slopseal-mcp"],
      "autoApprove": ["verify_install"]
    }
  }
}
```

No `env` block is needed: live mode is the default (R-LV-1), the policy falls back to the bundled default, and the state directory defaults to `.slopseal`. This also removes F-12 (workspace-relative paths in the shipped config). Tag and commit pinning is part of the release step. The repository gets a release checklist line, "gate pin", as issue #50 asks.

## 3. Modes and defaults (R-LV)

- Live is the default. A lookup failure is BLOCK with a typed reason, so a network problem stops installs and does not allow them.
- Offline needs `SLOPSEAL_OFFLINE_SNAPSHOT=1`. A snapshot with `"fixture": true` refuses to start unless that variable is set, and then warns.
- `as_of` comes from the build script. The loader refuses a future `as_of`. The fixture files are checksummed and `AGENTS.md` forbids hand edits, so regenerating them is an owner-approved task.
- Privacy line for the README: live mode sends the package name and version to PyPI, npm, and OSV.

## 4. Settings

### 4.1 Surfaces

| Surface | What it is | Initiated by |
|---|---|---|
| `slopseal_settings` tool | `status`, `get`, `preset`, `set` | The agent (with user approval, per Kiro's tool approval) |
| `slopseal-setup` prompt | Starts guided setup | The user, from the `#` menu |
| Elicitation form | Preset choice and a few knobs | The server, during a `slopseal_settings` call, only if the client declared `elicitation` |
| First-run offer | One sentence in the first result | Automatic |
| Host command `slopseal settings` | Human channel for any change, including loosening | The user, in a terminal (IDE, CLI) |

### 4.2 Knobs (proposed values; owner approves them in D-V2C-7)

Every value is checked by `enforce_floors` after the overlay is applied. Direction says which way is stricter.

| Knob | Policy key | Balanced | Strict | Stricter direction |
|---|---|---|---|---|
| Typosquat distance | `typosquat_max_distance` | 2 | 3 | higher |
| Typosquat age window (days) | `typosquat_max_age_days` | 30 | 60 | higher |
| New package age (days) | `new_package_max_age_days` | 7 | 14 | higher |
| Maintainer account age (days) | `min_account_age_days` | 90 | 180 | higher |
| Missing maintainer data | `levels.maintainer` | warn | block | warn to block |
| Undeclared license | `levels.license_undeclared` | warn | block | warn to block |
| Installs per minute | `max_installs_per_minute` | 10 | 5 | lower |
| Retry budget | `retry_budget` | 1 | 0 | lower |
| Deny list | `lists.deny` | empty | empty | add names |
| Allow list | `lists.allow` | empty | empty | adding is a loosening (human only) |
| Mode | live or offline | live | live | offline is a loosening (human only) |

Balanced equals today's shipped policy, so choosing it changes nothing. Not exposed as knobs: install-script level, license level, malware and critical-CVE handling, and the compiled-wheel allowlist. They stay fixed (decision D6 of the Phase 6 plan).

### 4.3 First-run flow

```
connect --> first verify_install result
              |-- settings record exists? yes --> normal result
              |-- no --> result starts with the status line + one setup sentence
                         |-- user picks "setup" --> elicitation form (if supported) or chat-guided
                         |        --> preset + optional knobs --> record written (setup: done)
                         |-- user ignores --> nothing else happens; Balanced applies
                         |-- user says "skip" --> record written (setup: skipped)
```

Rules: the offer is never shown more than once per connection. After `skipped` it appears only when the user starts setup. The hook's own message mentions setup once, in the first block message after a reset, and never again. No step needs an answer for the guard to work.

### 4.4 Channels and the tighten-only rule (R-SET-6)

```
change request (field, new value, channel)
   compare to the current effective value  -> tighten | neutral | loosen
   channel == agent and loosen -> refuse, name the human route, audit "refused"
   apply overlay -> enforce_floors -> any violation -> refuse whole change, audit "refused"
   write settings.json (sealed) -> audit "applied" with old, new, channel
```

The human channel for loosening is: an elicitation answer that shows the old and new value and needs a confirm, or `slopseal settings set ...` in a terminal, or a reviewed edit of the policy file (which the pre-commit guard and the property suite check).

Limits, stated plainly: in Tier 0 the agent can edit `.slopseal/settings.json` and the workspace policy file directly (F-11, F-16). The tighten-only rule then guards the tool, not the file. The seal on `settings.json` only detects an edit by someone without the key, and the key is readable too. Tier 1 moves the record into the service, where the rule is real.

### 4.5 Why no "off" in settings

An off switch in a tool the agent can call is a one-step bypass. The off switch is the entry, which is read-only to the agent on Web (observation O-3).

## 5. Tier 1: boundary

Reuse, do not rebuild: the trust zones, session tokens, grants, and anchor rules in D2; the gateway and digest check in ADR 0004 and PR #32; the Ed25519 verifier in `sign/verify.py`; the preflight rules in `preflight/`.

New work in this spec:

1. **Remote MCP transport.** The service speaks MCP over HTTP. The `slopseal` entry holds `url` and a credential. The local server and the service share the verdict code.
2. **Index protocol (R-NB-4).** The pip simple API and the npm registry JSON with tarball URLs rewritten to the gateway. This is R-GW-6, the missing piece that lets plain `pip install` and `npm install` use the gateway.
3. **Live upstream adapter** for artifact URL and published digest.
4. **State out of the workspace** (R-NB-2). The service owns the key, policy pin, audit, rate limit, settings, and quarantine store.
5. **Approvals** (R-NB-6). Replace unauthenticated `slopseal escalate` with a signed approval.
6. **Probe harness** (issue #39, R-NB-5, R-NB-8): direct-registry-fails, gateway-answers, config-write-denied, hook-file protection, escape routes.
7. **Platform step.** One documented action: restrict the sandbox network to the service host. The settings flow shows the exact steps and then runs the probes.

The service must be hosted by someone. Options and the recommendation are in section 9 (D-V2C-1).

## 6. Threat delta (agent as adversary)

| Attack | Tier 0 | Tier 1 |
|---|---|---|
| Install in a form the hook misses | Open until gate A1. Stated in the status. | Closed. The package source is the gateway, so command text does not matter. |
| Direct `curl` to a registry | Open | Closed by the platform egress rule, and proven by a probe |
| Delete the MCP entry to switch the guard off | Web: blocked, config is read-only. IDE and CLI: workspace config may be writable, so prefer the user config. | Deleting the entry also deletes the credential. Installs fail, because egress stays closed. |
| Ship a cloned repo with a disabled `slopseal` entry | Ignored: any enabled entry wins (section 2.2) | Same |
| Call `slopseal_settings` to loosen policy | Refused on the agent channel. Direct file edit still works. | Refused. State is in the service. |
| Edit the managed hook file | Possible (hook dir is writable). Detected only on the next server start. | Irrelevant to the boundary, since the gateway does not depend on the hook |
| Read or rewrite key, audit, rate-limit state | Possible (F-16) | Impossible from zone A |
| Fake "unplugged" by corrupting a config file | The launcher treats unreadable or invalid JSON as indeterminate, which behaves as plugged | Same |
| Prompt-injected metadata in a package record | Treated as data (existing rule) | Same |

## 7. Status line (R-ST-1)

Fixed wording, one per case. The preflight supplies the case. No other text may claim more.

| Case | Line |
|---|---|
| Tier 0 | `SlopSeal status: GUARD (advisory). Checks pinned installs in recognised forms. Not a boundary.` |
| Tier 1, probes missing or failing | `SlopSeal status: NOT ENFORCED. Direct registry access is not blocked. Setup: slopseal-setup.` |
| Tier 1, some checks fail | `SlopSeal status: PARTIALLY ENFORCED. Open: <check ids>.` |
| Tier 1, all probes pass | `SlopSeal status: ENFORCED. Probes passed at <UTC time>.` |

## 8. Compatibility by surface

| Capability | Kiro Web | Kiro IDE | Kiro CLI |
|---|---|---|---|
| One-entry install | Yes (tested config path) | Yes `[DOC]` | Yes `[DOC]` |
| Auto-written hook | Yes (works today) | Yes `[DOC]`, untested | Untested |
| Entry is read-only to the agent | Yes, tested | Not known for the workspace file | Not known |
| Unplug on delete | Yes | Yes | Yes |
| Elicitation form | Unconfirmed | Unconfirmed | Documented for local V3 2.34+ |
| Prompt `slopseal-setup` | Expected `[DOC]` | Expected `[DOC]` | Expected `[DOC]` |
| Tier 1 egress rule | Platform setting (allow-list mode) | User sandbox settings | User sandbox settings |
| Host command | No (no host terminal) | Yes | Yes |

On Web the loosening channel is the elicitation form or a reviewed edit of the policy file. If neither exists, Web users cannot loosen from the session. That is acceptable: Balanced is the shipped policy, and tightening always works.

## 9. Open decisions

| ID | Decision | Recommendation |
|---|---|---|
| D-V2C-1 | Who hosts the Tier 1 service | Self-hosted container, owned by the user or team. A shared service would receive every package name. |
| D-V2C-2 | Live as the default mode | Yes, with the fixture guard (R-LV-2) |
| D-V2C-3 | Loosening only through the human channel | Yes |
| D-V2C-4 | Phase naming | V2C-0 to V2C-5, listed in `tasks.md` |
| D-V2C-5 | Release tag and pin policy | Tag `v2.0.0`, pin by tag, record the commit in the release notes |
| D-V2C-6 | Hook self-removes on unplug | Yes. A no-op hook would keep running a process on every command |
| D-V2C-7 | Strict preset values (section 4.2) | Approve or edit the table |
| D-V2C-8 | Launcher inline or sibling file | Decide by test in V2C-1.3 |
| D1, D2, D3 | Inherited from the Phase 6 plan: egress, state location, approvals | As recommended there |

## 10. Failure modes

| Failure | Behavior |
|---|---|
| Launcher cannot read any config | Indeterminate, acts as plugged |
| Config file is invalid JSON | Indeterminate for that file. If no other file is readable, acts as plugged |
| SlopSeal missing but entry present | Exit 2 with the install hint |
| Settings overlay fails the floors | Ignored whole, status line says so, Balanced stays |
| `settings.json` unreadable or fails its seal | Balanced applies, status line says so, audit event written |
| Service unreachable (Tier 1) | Every install is refused, status names the cause |
| Elicitation declined or dismissed | Treated as skip. Nothing changes. |
