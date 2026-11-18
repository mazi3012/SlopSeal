# SlopSeal v2-complete: Requirements

Scope: the work that takes SlopSeal from "a guard that needs setup" to "one MCP entry, auto-plugged, with a removable first-run setup, and a real boundary where the platform allows". Observation: `reports/SlopSeal_V2_COMPLETE_OBSERVATION.md`. Decision record: `docs/adr/0006-mcp-lifecycle-binding-and-two-tiers.md`. Tasks: `tasks.md`.

Goal statement (the v2-complete exit): on a fresh Kiro workspace, a user adds one `slopseal` entry to an MCP config and saves. From then on, the verification layer is active without another step, a skippable setup is offered once, and deleting the entry removes the layer. With the Tier 1 service and the platform egress rule in place, direct registry access from the agent fails and the status reports ENFORCED from probes.

Terms:

- **Entry:** the `slopseal` object under `mcpServers` in a Kiro MCP config.
- **Managed hook:** the file `.kiro/hooks/block-agent-installs.json` when it carries the SlopSeal marker (R-AP-2).
- **Launcher:** the first command of the managed hook. It does not import SlopSeal.
- **Plugged:** an enabled entry exists (R-AP-4). **Unplugged:** none exists. **Indeterminate:** no MCP config could be read.
- **Tighten:** a change that makes the effective policy stricter. **Loosen:** the opposite. A change in neither direction is neutral.
- **Agent channel:** an MCP tool call made by the agent. **Human channel:** an elicitation answer, a host command run by the user, or a reviewed edit of the policy file.
- **Tier 0 (Guard):** local stdio server. **Tier 1 (Boundary):** remote service plus platform egress allow-list.

Existing requirements (R-1.9, R-G-*, R-Q-*, R-C-*, R-PF-*) stay as written. This file adds to them and edits none of them, except where it names a change.

## Auto-plug and lifecycle (R-AP)

**R-AP-1 (one install point).** The system shall reach Tier 0 enforcement with one entry and no other user-created file or command. The documented entry shall pin a release tag, and the launch shall not use an unpinned source (issue #50).

**R-AP-2 (managed hook).** When the server starts and the entry is plugged, the system shall write the managed hook if it does not exist. A hook is managed when its command carries the marker `slopseal-managed` followed by a version. If the file exists, is managed, and its command differs from the one this server version would write, the system shall replace it atomically (temporary file in the same directory, then rename). If the file exists and is not managed, the system shall leave it unchanged and report one line on stderr. A write failure shall not stop the server and shall be reported on stderr only (extends R-1.9, closes issue #56).

**R-AP-3 (launcher independence).** The managed hook command shall start the launcher before anything from SlopSeal is imported. The launcher shall use only the interpreter's standard library and shall decide plugged, unplugged, or indeterminate before it runs the hook module.

**R-AP-4 (plugged).** The launcher shall treat the state as plugged when an entry named `slopseal`, without `"disabled": true`, exists in any readable file of these: `.kiro/settings/mcp.json` in the working directory or any parent directory (on Kiro Web this reaches `/projects/.kiro/settings/mcp.json`), and `~/.kiro/settings/mcp.json`. It shall treat the state as unplugged only when at least one file was read and no file holds an enabled entry. It shall not let a disabled entry in one file cancel an enabled entry in another, even though Kiro lets the workspace file win, because a cloned repository could ship a disabled entry. If no file can be read, the state is indeterminate and the launcher shall behave as plugged.

**R-AP-5 (unplugged).** When the state is unplugged, the launcher shall exit 0 with at most one line on stderr, shall remove the managed hook file if it is managed, and shall run nothing else from SlopSeal. It shall never remove an unmanaged file.

**R-AP-6 (plugged but broken).** When the state is plugged or indeterminate and the hook module cannot run or exits with a code other than 0 or 2, the launcher shall exit 2 and print the install hint (the v1 fail-closed behavior).

**R-AP-7 (no config writes).** The server and the launcher shall never write to an MCP config, a Kiro settings directory, or a user settings file.

**R-AP-8 (residue).** Removing the entry shall leave `.slopseal/` in place, because it holds audit evidence. The documentation shall say so and name the host command that purges it.

**R-AP-9 (first status).** The first `verify_install` result after a connection, and the first managed hook message after the settings are created or reset, shall begin with one status line (R-ST-1).

## Modes and defaults (R-LV)

**R-LV-1 (live by default).** When `SLOPSEAL_OFFLINE_SNAPSHOT` is unset, the system shall select live mode. Offline mode shall need an explicit `SLOPSEAL_OFFLINE_SNAPSHOT=1`. The CHANGELOG and README shall state what live mode sends: package name and version to PyPI, npm, and OSV, and nothing else. (Owner decision D-V2C-2. This replaces the v1.0 default.)

**R-LV-2 (fixture guard).** If the snapshot is marked `"fixture": true` and offline mode was not chosen explicitly, the system shall refuse to start offline and shall name the variable in the message (issue #55). An explicit offline choice with a fixture snapshot shall print a warning that it is not a registry index.

**R-LV-3 (snapshot date).** `as_of` in a snapshot shall be written by `scripts/build_snapshot.py` from the build time. The loader shall reject a snapshot whose `as_of` is later than the wall clock (issue #57). Regenerating the checksummed fixtures needs the owner's approval.

**R-LV-4 (live failure).** Any live lookup that fails, times out, or returns an unreadable answer shall give BLOCK with the typed reason (existing fail-closed rule, restated).

## Settings (R-SET)

**R-SET-1 (tool).** The server shall expose a tool `slopseal_settings` with the actions `status`, `get`, `preset`, and `set`. The tool shall not run, install, or fetch anything.

**R-SET-2 (prompt).** The server shall expose the MCP prompt `slopseal-setup`. It starts the guided setup when the user picks it.

**R-SET-3 (first run).** When no settings record exists, the first `verify_install` result shall include the status line and one sentence that names the way to open setup and the way to skip it. If the client declared the `elicitation` capability in `initialize`, `slopseal_settings` may open a form with the presets. Otherwise setup is chat-guided: the agent asks the user and calls the tool with the answers.

**R-SET-4 (skip).** The user can skip setup. Skipping shall write a record with `setup: skipped`, shall apply the Balanced preset, and shall not show the offer again unless the user starts setup. The system shall need no input to work.

**R-SET-5 (presets and knobs).** The system shall offer the presets Strict and Balanced (the default) and the knobs listed in design section 4.2. Every preset and knob value shall pass `enforce_floors` after it is applied.

**R-SET-6 (channels).** On the agent channel the system shall accept only a change that tightens or is neutral, and shall refuse a change that loosens. The refusal shall name the human route. A change to the allow list, to the mode, or to any value below its current setting is a loosening. A loosening shall be accepted only through the human channel.

**R-SET-7 (no off switch).** No action of `slopseal_settings` shall disable verification, remove the managed hook, or lower a floor. Removing the entry is the only off switch (R-AP-5).

**R-SET-8 (audit).** Every accepted or refused change shall be written to the audit log with the old value, the new value, the channel, the result, and the wall-clock time.

**R-SET-9 (approval guidance).** The documented entry shall set `autoApprove` to `["verify_install"]` at most. The setup text shall tell the user not to auto-approve `slopseal_settings`.

**R-SET-10 (storage).** In Tier 0 the settings record shall live under the state directory as `settings.json`, sealed with the audit seal key, and the documentation shall say the agent can edit it directly in that tier. In Tier 1 it shall live in the service.

**R-SET-11 (precedence).** The effective policy shall be the policy file (or the bundled default) with the settings overlay applied. The overlay shall never produce a value outside the floors, and an invalid overlay shall be ignored as a whole with a BLOCK-level warning in the status line.

## Network boundary, Tier 1 (R-NB)

**R-NB-1 (remote entry).** The entry may name a remote service (HTTP transport) with a credential, instead of a local command. The service shall expose the same tools as the local server.

**R-NB-2 (secrets out of reach).** In Tier 1 the seal key, policy pin, audit log, rate-limit state, and quarantine store shall exist only in the service. The workspace shall hold none of them (D2 section 4).

**R-NB-3 (gateway).** The service shall serve an artifact only for an ALLOW verdict on that exact package, version, and digest, and only against a one-use grant bound to the session (D2 section 7.5, AC-32 to AC-34).

**R-NB-4 (index protocol).** The gateway shall answer the pip simple index and the npm registry protocol, so a plain `pip install` and `npm install` reach it with no change to the command (closes R-GW-6).

**R-NB-5 (egress).** The system shall document the one platform step that restricts the agent sandbox to the service host. A probe shall confirm from the agent shell that direct access to PyPI and npm fails and that the service host answers.

**R-NB-6 (approvals).** A quarantine shall be approved only by a signature from a human-held Ed25519 key, verified by the service (R-AR-1 verifier, decision D3).

**R-NB-7 (availability).** When the service cannot be reached, every install shall be refused and the status shall say why. The service shall expose a health check.

**R-NB-8 (status from probes).** The preflight shall report ENFORCED only when its probes return PASS (issue #39). A probe that is not run gives NOT ENFORCED.

## Status and honesty (R-ST)

**R-ST-1 (status line).** Every `verify_install` result shall carry a status line with the tier and the preflight status, in the fixed wording of design section 7.

**R-ST-2 (no overclaim).** No message, README line, or document shall say ENFORCED, firewall, or boundary beyond what the preflight status and the tier allow (observation section 5). A test shall check the shipped messages and docs for the forbidden wording at each tier.

## Hardening prerequisites (R-HD)

**R-HD-1 (guard claim).** Until the Phase 6 gate A items A1 to A3 are merged (hook deny-by-default, hook honors quarantine, floors enforced at runtime), Tier 0 shall say "advisory" in its status line and shall not claim to cover command forms it cannot read.

**R-HD-2 (boundary claim).** Tier 1 shall not report ENFORCED until gate A and the Tier 1 requirements R-NB-2 to R-NB-8 are met.

**R-HD-3 (new requirement ids).** The gate A items add their own ids (R-G-13, R-G-14 and others) in their own spec step before their code, as the Phase 6 plan requires.
