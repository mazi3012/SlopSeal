# SlopSeal v2-complete: Observation Report

Date: 2026-11-18. Base: `main` at 9825bbb. Status: input to `.kiro/specs/seal-v2-complete/`. No code changed.

Goal being observed: a user adds one `slopseal` entry to a Kiro MCP config and the firewall plugs in by itself. A first-run settings flow is offered and can be skipped. Deleting the entry removes the firewall. The result is a real firewall on Kiro Web, as far as the platform allows.

Evidence labels: `[CODE]` read in this repository. `[TESTED]` run in this Kiro Web session (read-only, no secrets read). `[DOC]` Kiro documentation. `[PRIOR]` an earlier SlopSeal report. `[INFERRED]` my reasoning, not verified.

## 1. What exists today

| Part | State | Evidence |
|---|---|---|
| MCP server `slopseal-mcp` | Handles `initialize`, `tools/list`, `tools/call`. One tool, `verify_install`. Declares only the `tools` capability. No prompts, no resources, no elicitation. | `[CODE]` `mcp/server.py` lines 289 to 304 |
| Hook bootstrap (R-1.9) | On server start, writes `.kiro/hooks/block-agent-installs.json` if it does not exist. Never overwrites. Command runs `sys.executable -m slopseal.hooks.on_install`. | `[CODE]` `bootstrap_install_hook` |
| Hook trigger | `PreToolUse`, matcher `execute_bash`. It runs on every shell command, not only installs. | `[CODE]` hook JSON |
| Policy and floors | Policy file, then bundled default. Floors in code (`policy/invariants.py`). | `[CODE]` |
| Modes | Offline fixture snapshot is the default. Live PyPI, npm, and OSV exist (`SLOPSEAL_OFFLINE_SNAPSHOT=0`). | `[CODE]` `runtime.py` |
| Receipts | Ed25519 receipt verifier merged (PR #54). | `[CODE]` `sign/verify.py` |
| Status | `preflight` reports ENFORCED, PARTIALLY ENFORCED, or NOT ENFORCED. Probes are not built, so it always says NOT ENFORCED (issue #39). | `[CODE]` |
| Gateway | MVP in draft PR #32. One route, no pip or npm index protocol, no live upstream, conflicts with `main`. | `[PRIOR]` ADR 0004 on that branch |
| Needle (L2) | `[semantic] enabled = false`. Nothing in the verdict pipeline imports it. Spike failed its gate. | `[CODE]` `[PRIOR]` |
| Hardening (Phase 6 gate A) | Eleven strict-xfail markers remain, F-01 to F-06 and F-08 to F-12. `R-G-13` and `R-G-14` are not in the requirements yet. | `[CODE]` |

## 2. What this Kiro Web session shows

| Fact | Result | Label |
|---|---|---|
| Network mode | `OPEN_INTERNET`. | `[TESTED]` `get_sandbox_info` |
| MCP config location | `/projects/.kiro/settings/mcp.json`. It lists `slopseal` and `tool-server`. | `[TESTED]` |
| MCP config writable from the agent shell | No. `/projects/.kiro/settings` and `/projects/sandbox/.kiro/settings` are separate read-only mounts. Readable. | `[TESTED]` `/proc/mounts`, `os.access` |
| Hook directory writable from the agent shell | Yes. `/projects/sandbox/.kiro/hooks` is `W_OK`. | `[TESTED]` `os.access`, no write attempted |
| SlopSeal state | `/projects/sandbox/.slopseal/` holds `secret.key`, `audit.jsonl`, `ratelimit.json`, and is root-owned and readable by the agent shell. | `[TESTED]` listing only |
| Agent privileges | Root with `CAP_NET_ADMIN`, so a local firewall rule can be removed by the agent. | `[PRIOR]` D1 report |

## 3. Findings

### O-1. Auto-plug mostly exists, with four gaps

R-1.9 already plugs the hook in from the MCP server start. The gaps:

- A stale hook is never refreshed, because the bootstrap never overwrites. Two hook copies with different launch commands exist today (issue #56).
- The default mode reads the bundled fixture snapshot, which is a test fixture with typosquat examples. It blocks real packages as "not covered" (issue #55). Its `as_of` is in the future relative to real time (issue #57).
- `mcp.json` launches from an unpinned `git+https` source (issue #50).
- The hook has no connection to the MCP entry after it is written.

### O-2. Deleting the MCP entry can block every shell command (HIGH) `[TESTED]`

The wrapper in `install_hook_command` exits 2 for any module exit code other than 0 or 2. The hook runs on every `execute_bash`. I ran the wrapper's logic from a directory where `import slopseal` fails:

```
ModuleNotFoundError: No module named 'slopseal'
module exit code: 1
wrapper result: exit 2 (every command blocked)
```

So if the entry is deleted and the environment that provided SlopSeal goes away, a stale hook blocks all commands, not only installs. The requested behavior ("delete the MCP and the firewall is gone") is the opposite of the current one. The hook also works without the MCP process, because it only needs the module, so deleting the entry alone does not remove it either.

### O-3. The unplug signal can be read on Web `[TESTED]`

The MCP config is readable and read-only to the agent shell. A launcher can check whether a `slopseal` entry exists and is not disabled. Because the agent cannot write that file, "delete the entry" is a human act on Web, which fits the tamper model. `[DOC]` The IDE and CLI keep the same file at `.kiro/settings/mcp.json` (workspace) and `~/.kiro/settings/mcp.json` (user), and the workspace entry wins on a name clash. Those two paths are `[DOC]`, not tested here.

### O-4. A settings page cannot open on connect or save `[DOC]`

- Kiro has no documented event for "MCP entry saved" or "server connected" that a server can hook.
- MCP prompts are user-initiated, from the `#` menu.
- Elicitation (an inline form) happens only during a tool call. Kiro documents it for the CLI, local V3 sessions, version 2.34 and later. Web and IDE support is unconfirmed. URL-mode elicitation is a requested feature (Kiro issue #4785), not supported.
- The SlopSeal server does not declare or request elicitation today.

So "the settings page must come on first connect" cannot be promised. What can be built: the first tool result and the first hook message offer setup. A form is used where the client supports elicitation. Chat-guided setup is the fallback. Every path is skippable and has safe defaults.

### O-5. A real firewall needs the network layer, which MCP cannot set `[PRIOR]` `[TESTED]`

Nothing in an MCP entry changes the sandbox network. The platform setting (network mode) is outside the session. With direct registry access open, any HTTP client bypasses command-text checks (K-1). A real firewall therefore needs the gateway, a platform egress allow-list, and key and state out of the agent's reach. The allow-list step cannot be automated from MCP.

The two goals pull against each other. "Deleting the entry removes the firewall" is right for the verification layer. If the egress allow-list is a platform setting, deleting the entry cannot revert it, and it should not, or the agent could revert it. The plan keeps both: the layer is removable by deleting the entry, and the network rule is removed by the human who set it.

### O-6. A settings tool is an attack surface

An agent can call any MCP tool the user does not block. A `settings` tool that can loosen policy would let a prompt-injected agent weaken the firewall. In Tier 0 the agent can also edit workspace files directly (F-11), so tool-level limits are advisory there. Rule: the agent channel may only tighten. Loosening needs a human channel. The tool must not be auto-approved.

### O-7. Key and state are agent-readable in the local mode `[TESTED]`

Moving them out of reach needs a separate trust zone. On Web the only zone the agent cannot reach is a remote service (D2 section 3.2). A remote MCP server (HTTP transport) fits the "one MCP entry" goal: the entry holds a URL and a credential instead of a local command.

### O-8. Hardening debt gates every claim

Eleven findings still have a strict-xfail test (F-01 to F-06, F-08 to F-12). F-13, F-14, and F-16 are also open and have no test. F-01 (hook misses common install forms) is CRITICAL. Until gate A is done, the Tier 0 claim stays "stops accidental installs in recognised forms".

### O-9. Needle has no role

L2 is advisory-only (ALLOW to QUARANTINE, never BLOCK), disabled, and failed its pre-registered gate. It stays out of the plan.

### O-10. Live mode exists but is not the default

The live adapter exists with fail-closed behavior on any lookup error. Making it the default changes what leaves the machine: package names and versions go to PyPI, npm, and OSV. Those registries are contacted by the install anyway. This is an owner decision.

## 4. What cannot be promised

| Wish | Limit | Reason |
|---|---|---|
| Settings page opens on connect and save | Not possible | No Kiro event or UI hook (O-4) |
| Full firewall from the MCP entry alone | Not possible | Network rule is a platform setting (O-5) |
| Firewall gone on delete, and agent cannot turn it off | Both hold only because the config is read-only to the agent on Web (O-3) | Tested on Web only |
| Tier 0 stops a deliberate adversary | No | F-01, F-16, K-1 |

## 5. Claims allowed per tier

| Tier | Needs | May say |
|---|---|---|
| Guard (Tier 0) | One MCP entry | "Verifies pinned installs and blocks the recognised install forms. Fails closed on forms it cannot read. Not a boundary." |
| Boundary (Tier 1) | Remote service entry, platform egress allow-list, probes pass | "Packages reach the agent only through the SlopSeal gateway, and the keys are outside the agent's reach." Only when preflight returns ENFORCED. |

## 6. Questions to settle by probe on a real surface

1. Does Web re-read `mcp.json` between commands, and is the entry removed from the file when the user deletes the server in the UI? (`[INFERRED]`: yes.)
2. Does the Web client send the `elicitation` capability in `initialize`? Same question for the IDE and CLI.
3. Does an MCP server declared with a `url` (HTTP transport) work on Web, and can the entry carry a credential header?
4. Where does a Power-installed server's entry live, and is it in the same file?
5. Which allow-list modes does the Web settings page offer, and does `COMMON_DEPENDENCIES` include PyPI and npm? (`[INFERRED]`: it probably does.)
