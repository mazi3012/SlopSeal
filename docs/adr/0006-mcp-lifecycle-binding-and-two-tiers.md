# 0006. MCP entry is the only install point, the hook is bound to it, and enforcement has two tiers

Status: Proposed (owner review pending)
Date: 2026-11-18

## Context

The goal is one way to install: a `slopseal` entry in a Kiro MCP config. The firewall plugs in on its own, and removing the entry removes it. `reports/SlopSeal_V2_COMPLETE_OBSERVATION.md` found:

- The MCP server already writes the hook (R-1.9), but the hook is not tied to the entry. The hook runs on every shell command and exits 2 when SlopSeal cannot be imported, so a removed install can block all commands (O-2, tested).
- Kiro has no event for "entry saved" or "server connected". Elicitation works only during a tool call, and is documented for the CLI only (O-4).
- A real boundary needs a network rule and out-of-reach key and state. An MCP entry cannot set a network rule (O-5, O-7).
- On Kiro Web the MCP config is readable and read-only to the agent shell (O-3, tested).

## Decision

1. **One install artifact.** The `slopseal` MCP entry. The managed hook is derived state: the server writes and refreshes it, and nothing else asks the user to create a file.
2. **Lifecycle binding.** The hook starts a small launcher that does not import SlopSeal. The launcher reads the MCP configs. If no enabled `slopseal` entry exists, it removes the hook file and exits 0. If an entry exists and SlopSeal cannot run, it exits 2. If the configs cannot be read at all, it treats the entry as present (fail closed).
3. **Two tiers.**
   - Tier 0, Guard: local stdio server, advisory. Works anywhere.
   - Tier 1, Boundary: the same entry points at a remote service (HTTP transport) that holds key and state and serves artifacts. It also needs a platform egress allow-list that the user sets once. The status line says ENFORCED only when the probes pass.
4. **Settings by two channels.** The agent channel may only tighten. Loosening needs a human channel: an elicitation form where supported, a host command, or an edit under review. There is no "off" switch in the tool. Removing the entry is the off switch.
5. **First run is an offer, not a page.** The first tool result and the first hook message carry a status line and one setup instruction. Setup is skippable and defaults are safe.

## Alternatives considered

- **Power-only install.** A Power cannot install a hook (K-9), so the verification layer would not auto-plug.
- **A separate installer command.** Breaks the "one way" goal.
- **Heartbeat lease for liveness.** A crash and a deletion look the same, so it either fails open on a crash or never unplugs. Config presence is the only signal that separates them.
- **Hook never self-removes.** Keeps the all-commands-blocked failure after the entry is deleted.
- **Settings tool that can loosen.** A prompt-injected agent could weaken the policy.

## Consequences

- Removal works cleanly on Web because the agent cannot write the config. On IDE and CLI the workspace config may be agent-writable. The launcher then trusts a file the agent could edit. Guard tier is advisory, and the status says so. User-level config stays the recommended location there.
- The hook gains a second code path to test. The launcher must stay small, stdlib-only, and import nothing from SlopSeal.
- A network rule set in the platform survives deletion of the entry. That is intended, and the uninstall instructions say so.
- Tier 1 needs a service that someone hosts. Who hosts it is an open decision (D-V2C-1).
- The client may not send the `elicitation` capability. Chat-guided setup is then the only path, and loosening needs the host command.
