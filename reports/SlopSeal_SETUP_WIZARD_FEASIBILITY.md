# SlopSeal Setup Wizard and MCP Onboarding: Feasibility Investigation

- Date: 2026-11-17
- Status: investigation only. No production code, firewall, network, or sandbox setting was changed. PR #32 was not touched. D1 is **not enforced**. D2 and D3 are not started.
- Builds on: `reports/SlopSeal_ONE_STEP_INSTALL_FEASIBILITY.md` (draft PR #33).

Evidence labels used below: **[doc]** an official documentation page I read; **[issue]** a bug or feature report in a vendor's public tracker (status may have changed); **[blog]** a third-party article; **[local]** measured in this sandbox; **[unverified]** not confirmed, do not rely on it.

## 0. The central question

> Can we realistically build a SlopSeal experience where the user adds MCP, clicks Save, and then completes all required security configuration through one guided setup wizard?

**Answer: partly. The guided wizard is realistic. The literal sequence "Save, then the wizard opens by itself" is not, and the network protection cannot be completed from inside the MCP connection.**

Three facts decide this:

1. **An MCP server cannot see "Save", and no client documents a way for it to open a wizard on its own.** The server learns only that a process started and that `initialize` arrived. The specification's only mechanism to send a user to a page is URL-mode elicitation, and that must be nested in another request and needs the user's consent before the client opens anything [doc: MCP elicitation spec].
2. **Network protection is set outside the MCP connection.** MCP gives the agent a channel to ask SlopSeal questions. It does not configure the host network, a container network, or a platform allow-list. In Claude Code, local MCP servers even run *outside* the shell sandbox [doc: Claude Code sandboxing], so a probe run from the MCP server measures the wrong network.
3. **The privileged step has to be done by the human on the host,** through a host-side installer that the agent cannot drive. That step can be guided, in plain language, but it cannot be hidden from the user or run by the MCP server.

What is realistic is this journey:

```
Add SlopSeal MCP  ->  Save  ->  first SlopSeal tool call (or /slopseal-setup)
   -> MCP replies: "NOT ENFORCED. Run: slopseal setup" (advisory mode, clearly labelled)
   -> user runs `slopseal setup` in a host terminal (one command)
   -> guided wizard (CLI, with a local web view) -> admin approval step -> verify
   -> status: ENFORCED / PARTIALLY ENFORCED / NOT ENFORCED, shown in the dashboard and in every MCP result
```

That is one guided setup with one extra command, not an automatic pop-up. Where a client supports URL elicitation, the first tool call can offer to open the local wizard page, always with the user's consent.

## 1. A. MCP installation and Save behaviour

### 1.1 What an MCP server can and cannot detect

| Question | Answer | Evidence |
|---|---|---|
| Can the server detect that config was saved? | **No.** The specification defines no configuration lifecycle event. The server sees only a new process (stdio) or a new connection, then `initialize`. | [doc] MCP spec lifecycle; SlopSeal's server handles only `initialize`, `ping`, `tools/list`, `tools/call` ([local] `mcp/server.py`) |
| Does saving a config cause a restart? | Kiro: "Servers reconnect automatically" after the config file is saved. Others: not documented in what I read. | [doc] kiro.dev/docs/mcp |
| What can the server learn at start? | The client's declared name, version, protocol version, and capabilities (including whether `elicitation` with `form` and/or `url` is declared). `clientInfo` is self-reported and can be spoofed, so it is a hint, never a security input. | [doc] MCP spec |
| Can the server push a setup UI by itself? | **No.** Elicitation requests are "nested inside other MCP server features" (for example a tool call), and clients must obtain consent before opening a URL. | [doc] MCP elicitation spec |
| Can the server detect first run? | **Yes**, by its own state: no setup state file exists, or no status has ever been issued. That is a signal on first tool call or first start, not a "Save" event. | [local] design inference |

### 1.2 What a server can use to start onboarding

| Mechanism | What it does | Limits |
|---|---|---|
| **Tool-result message** | Every `verify_install` result can carry the current status and the next step. The user and agent both see it. | Not a UI. It appears only after a tool call. |
| **MCP prompt** (`/slopseal-setup`) | Appears as a command in clients that list server prompts (Claude Code shows MCP prompts as slash commands; Cursor supports prompts; Kiro supports server prompts) | Needs the user to type it. Claude Code issues report that dynamic list updates are not honoured, so the prompt must exist from the first `initialize` |
| **URL-mode elicitation** | Asks the client to open a URL, after showing the full URL and getting consent | Needs the client to declare `elicitation.url`. Claude Code declares it for stdio servers (v2.1.287 or later). Cursor lists elicitation as supported. Codex, VS Code, and Kiro: not confirmed for URL mode |
| **MCP Apps extension** | A tool can return an interactive view in the host's UI | Cursor documents support. Others: not confirmed. Limited to what the host renders, and it cannot run privileged steps |
| **Notification (`list_changed`, `message`)** | Could signal state changes | Claude Code issues report `tools/list_changed` and `prompts/list_changed` are not honoured. Do not depend on them |
| **Install links** | Cursor and Kiro have one-click install links (`cursor://`, `kiro://`) that show a confirmation dialog before anything is written | These install the server only. They do not open a wizard |

### 1.3 Client support

| Client | Add MCP | Elicitation (form / URL) | Prompts | Config lifecycle events | Notes |
|---|---|---|---|---|---|
| **Claude Code** | `claude mcp add`, `.mcp.json`, plugins | Declares `form` and `url` for stdio, sse, http and ws servers in the user's config (v2.1.287 or later). Plain `form` only for claude.ai connectors. URL: asks the user whether to open the link. Non-interactive runs cancel input requests | Yes, as slash commands | None documented. `/mcp` shows status. | **Local MCP servers run outside the shell sandbox.** Elicitation hooks can auto-respond |
| **Cursor** | `mcp.json`, Customize page, `cursor://` install links with a confirm dialog | "Supported" in Cursor's table. Mode support not stated | Yes | None documented | MCP Apps extension supported |
| **Codex CLI / IDE** | `codex mcp add`, `config.toml` shared by CLI and IDE | **Unreliable.** A tracker issue reports the client advertises elicitation and then auto-declines requests. Later issues describe partial behaviour. Current state unconfirmed | Not confirmed | None documented | Treat elicitation as unavailable until retested |
| **VS Code (Copilot agent mode)** | Extensions panel, `mcp.json`, install links | Form elicitation reported since 1.102 [blog]. URL mode: not confirmed | Not confirmed | None documented | Admin policy "MCP servers in Copilot" controls access |
| **Kiro IDE / CLI** | `mcp.json`; `kiro://` install links with confirmation | Docs say Kiro can "respond to server elicitation requests". A tracker issue (Jan 2026) asks for URL mode and protocol 2025-11-25. Current URL support unconfirmed | Yes ("server-provided prompts and resources") | **Save of the config file reconnects servers automatically** [doc] | Hook behaviour untested |
| **Kiro Web / Mobile** | Config file; Web supports stdio and remote servers | Unconfirmed | Web: yes. Mobile: no | Same as IDE for config | OAuth only through Powers. A browser on the user's own machine may not exist next to a cloud sandbox |
| **Cloud agents** (Copilot cloud, Cursor cloud, Codex Cloud) | Admin or repo settings | Not applicable, because there is no local desktop to open a page on | n/a | n/a | Wizard cannot run inside them |

### 1.4 If automatic opening is impossible, the best alternative

A **host-side CLI wizard** (`slopseal setup`) that also serves a **local dashboard**, with the MCP server acting as a signpost. Reasons:

- The privileged work needs a host process, not an MCP server. A CLI run by the user in a normal terminal is the only place that can request administrator approval honestly.
- The CLI works the same way for every client, so the experience does not depend on elicitation support.
- The MCP server stays small. It only reports status and points at the wizard.

The page URL given to a client through elicitation must not be pre-authenticated (the specification forbids a URL that grants access by itself). So the local page uses a **pairing code printed in the terminal** that the user types into the page. A one-time token inside the URL would break that rule.

## 2. B. Setup wizard architecture

### 2.1 Detection

| Need | Method | Reliability |
|---|---|---|
| Operating system | `platform`, `uname`, WSL markers | High |
| AI agent | Presence of config directories and binaries on the host (`~/.claude`, `~/.codex`, `~/.cursor`, `~/.kiro`, `code`), plus `clientInfo.name` from the MCP `initialize` as a hint | Disk signals: medium-high. `clientInfo`: low (spoofable) |
| Docker and sandboxes | `docker info`, socket type, `/.dockerenv`, cgroups, `bwrap` and `socat` for Claude Code's Linux sandbox | High for local; **[local] this sandbox has the Docker CLI but `/var/run/docker.sock` is `/dev/null`**, so Docker is intentionally disabled here |
| Administrator rights | `id -u`, `sudo -n true` (non-interactive), membership of `docker` | High. Never try to escalate silently |
| Existing SlopSeal install | Version, state directory, gateway health endpoint | High |
| Existing network restrictions | **Probe, do not read config.** Config shows intent, not effect | High for tested paths |
| Managed policy present | Read-only checks of the known managed locations for each agent | Medium. Platform-specific, and absent on cloud |

### 2.2 Wizard state machine

```
NEW -> DETECTED -> PLAN_APPROVED -> STEP[i]: APPLY -> VERIFY -> (OK | FAILED) -> ... -> FINAL_PROBE -> STATUS
                                            |                                          |
                                      rollback record                      ENFORCED / PARTIALLY / NOT ENFORCED
```

Rules:

- **Each step is idempotent** and has its own verification. "Applied" and "verified" are different states.
- **Progress is persisted** in a host-owned setup record so an interrupted run can resume at the first unverified step.
- **The record is not the status.** Status is recomputed from live probes and a signed attestation from the gateway. A file that says "done" must never produce ENFORCED by itself.
- **Every change has a rollback entry** (what was created, how to remove it). Cancel and failure both roll back or leave a clearly marked partial state.
- The wizard keeps working if the agent client is not running. It does not need MCP for any privileged step.

### 2.3 Where the state lives (trust boundary)

If the setup record, signing key, policy pin, or status file sits in the agent's workspace, the agent can forge a pass. So state is owned by the host user (or the gateway container) and mounted into the agent environment read-only, or not at all. This is the same issue as audit finding F-16 and decision D2. D2 is not started, so the wizard design assumes it as a prerequisite for any ENFORCED claim.

## 3. C. Network security configuration (Linux Docker first)

### 3.1 Topology

```
+------------------- Host (human administrator) -------------------+
|  slopseal setup (CLI wizard + local dashboard, 127.0.0.1)         |
|     | creates / verifies                                          |
|     v                                                             |
|  [internal network "slopseal-agent" : --internal, no IPv6]        |
|     |                    |                                        |
|  [agent container]   [gateway container]----[egress network]---> registries
|   - non-root          - separate user         (only the gateway
|   - cap_drop ALL      - read-only filesystem    reaches this net)
|   - no docker.sock    - holds key, policy,
|   - no host network     audit log, rate state
|   - pip/npm point at    - upstream host allow-list in code
|     gateway only      - no shared volume with the agent
+-------------------------------------------------------------------+
```

### 3.2 How each requirement is met (Docker)

| Requirement | Mechanism | Evidence and caveat |
|---|---|---|
| Wizard and host installer communicate | They are the same host-side program: the CLI process owns the privileged steps and serves the dashboard. No privileged channel runs through MCP | design |
| Gateway deployment | A container started by the host installer, on both the internal and the egress network | The gateway must first speak the pip and npm protocols (R-GW-6, not built) |
| Agent isolation | Agent container joins only the `--internal` network. Docker documents `--internal` networks and the `none` driver | [doc] docs.docker.com/engine/network. |
| Direct PyPI and npm blocked | The agent network has no route out. Block is at the network layer, not in a tool, so `curl`, `urllib`, `fetch`, direct IPs, ports, and proxy variables all fail the same way | to be probed |
| Gateway reaches registries | Gateway is attached to the egress network. Its **own** code restricts upstream hosts to PyPI and npm hosts (an SSRF guard). Optional host IP rules can add a second layer, but registry CDN IPs change, so IP rules alone are brittle | design. No per-container domain allow-list exists natively in Docker |
| Agent cannot change the restrictions | No `CAP_NET_ADMIN`, not privileged, no `docker.sock`, no host networking, `no-new-privileges`. Network is created by the daemon on the host, outside the container | [unverified] must be tested. Docker also manages its own iptables rules, and custom rules can be bypassed or overwritten [doc] docs.docker.com/engine/network/firewall-iptables |
| IPv6 | Create the network without IPv6 | [doc] IPv6 is opt-in per network |

### 3.3 Known risks to test before any claim

- **Host reachability from an internal network.** Services on the host listening on all interfaces may be reachable at the bridge gateway address. I did not find documentation that says either way, so the probe matrix must include that address and `host.docker.internal`. **[unverified]**
- **DNS.** Docker's embedded DNS answers for container names. The probe must confirm that external names do not resolve, and DNS over HTTPS must fail.
- **Docker rights are root-equivalent.** The consent text must say so in plain words.
- **Escape from the container** is out of scope for this boundary. Rootless Docker or a user namespace reduces the risk.
- **This sandbox cannot test any of this.** Docker is disabled here (`/var/run/docker.sock` is `/dev/null`). A prototype needs a Linux host or a CI runner with Docker, and I recommend that before any development decision about the Docker tier.

### 3.4 Other platforms (what the wizard can and cannot do)

| Platform | What the wizard can do | What stays manual |
|---|---|---|
| Claude Code (Linux, WSL2, macOS) | Write user and project settings, register MCP, run probes from a sandboxed shell command, print a managed-settings snippet | Managed settings need an administrator. The sandbox is off by default, so the wizard must turn it on and then check it. Escape hatches (`excludedCommands`, unsandboxed retry, `!` prompt, built-in WebFetch) need managed policy |
| Codex | Write `config.toml` (network proxy domain rules), register MCP, probe | Managed requirements and disabling escalation; "full sandbox escalation can bypass the command proxy" per the docs |
| Cursor | Write `.cursor/sandbox.json` (`networkPolicy`), `hooks.json`, MCP | Team-admin policy. A per-repo file can be changed by someone who controls the repo |
| Kiro IDE | Register MCP, hook, steering | Whether Kiro hooks and any egress controls enforce anything is untested |
| Kiro Web, Copilot cloud, Cursor cloud, Codex Cloud | Probe and print the checklist | Platform admin UI. No API found |

**Important for every client:** local MCP servers are not inside the agent's shell sandbox in Claude Code [doc]. Probes must therefore run **in the agent's execution context** (a command the agent shell runs, or a helper started by the host inside the same container). A probe run from the MCP server would test the MCP server's network, which is usually open.

## 4. D. User interface

### 4.1 Options compared

| Option | Strengths | Weaknesses |
|---|---|---|
| Hosted web dashboard | Easy to update, central view | A hosted page **cannot** configure a local host or Docker. It would need an agent on the machine anyway. Sending environment data off the machine also conflicts with SlopSeal's "does not phone home" position. Not suitable for setup. Could be an optional fleet status view later |
| Local web interface only | Friendly for non-technical users. Good for status | Needs a host process anyway. Opening it from MCP depends on elicitation support. DNS rebinding and CSRF need care |
| CLI interactive wizard only | Works everywhere, including SSH. Honest place for admin consent. Easiest to make correct | Less welcoming. Weak dashboard |
| **CLI wizard + local web dashboard (combination)** | CLI runs the privileged steps and the verification. A local page shows the stages and the live status. Either one can be used alone | Two surfaces to build and keep consistent |

### 4.2 Recommendation

**CLI wizard that also serves a local dashboard.** The CLI is the controller and the source of truth. The dashboard is a view with a pairing code, bound to `127.0.0.1`, with Host and Origin checks. The MCP server signposts to both.

### 4.3 Wizard stages and what the user sees

| Stage | User sees | What happens | Verified how | If it fails |
|---|---|---|---|---|
| 1. Welcome | What SlopSeal does, in two sentences. "Setup changes your network settings. You approve each change." | Nothing is changed | n/a | n/a |
| 2. Detect environment | A checklist: OS, agent(s) found, Docker, admin rights, existing install | Read-only detection | Each item shows what was found and how | Unknown items are shown as unknown, never as "ok" |
| 3. Connect AI agent | "Add SlopSeal to Claude Code" with the exact change listed | Registers MCP and hook for the chosen client (with consent) | Client reports the server connected | MCP stays advisory and the status says so |
| 4. Configure security | A plain-language plan: "SlopSeal will create a private network for your agent. Your agent will be able to reach only the SlopSeal package service." Administrator approval shown as one "Approve" step with what it will do | Host installer creates the network, the gateway container, and the agent settings | Each step is checked after it is applied | Rolled back or marked partial. Status is not raised |
| 5. Verify network restrictions | A live list of probes with pass or fail | Probe matrix run from the agent's execution context | See section 5 | Any direct-access success makes the result NOT ENFORCED |
| 6. Activate protection | "Protection is ON for the tested paths" only if ENFORCED. Otherwise the exact state and the missing step | Status published to the gateway and dashboard | Attestation | Never shown as "Protected" unless ENFORCED |
| 7. Dashboard | Current status, last probe time, gateway health, recent verdicts, a "Re-verify" button | Continuous | Status expires and is re-probed | Auto-downgrade, with a visible notice |

The wizard never needs the user to read a firewall rule. The words "Docker", "network", and "gateway" appear in plain terms only where a decision needs them, with an optional "show details".

## 5. E. Security status

### 5.1 Definitions

| Status | Meaning | Required evidence |
|---|---|---|
| **ENFORCED** | The package source is the boundary for the tested paths, and the agent cannot change it | (a) enforcement point is outside the agent's control (host-level network, managed policy, or platform setting); (b) all probes pass from the agent's execution context; (c) gateway healthy and reachable; (d) the status attestation is fresh and signed by a component the agent cannot write; (e) known escape hatches for that platform are disabled |
| **PARTIALLY ENFORCED** | Some layers are verified, but the boundary is incomplete or relies on something the agent could change | Examples: probes pass but the policy is user-scope; hook and MCP active but no network layer; escape hatch still enabled; one probe class could not run |
| **NOT ENFORCED** | No verified boundary | Any direct-access probe succeeds; the gateway is down; probes could not run; status is stale; unknown state |

### 5.2 Rules

1. **Unknown means NOT ENFORCED.** A probe that cannot run is a failure, not a skip.
2. **A successful direct-access probe is NOT ENFORCED**, not "partial".
3. **MCP connectivity is never evidence of isolation.** A connected server with no verified network layer reports NOT ENFORCED.
4. **The label always states its scope:** "ENFORCED for 12 of 12 tested paths, boundary: host network." A successful probe is evidence for the tested paths, not a proof that no bypass exists.
5. **Status expires.** Re-probe on every session start and on a timer. A stale status is NOT ENFORCED.
6. **Downgrades are loud.** Any change to a lower status is shown in the dashboard and in the next MCP result. It is never silent.
7. **The agent cannot raise the status.** Only the host component and gateway write it.
8. **Every MCP result carries the current status line**, so an agent or user cannot read an ALLOW without seeing it.

### 5.3 Probe matrix (run from the agent's execution context)

| Group | Probe | Pass |
|---|---|---|
| Direct HTTP | `curl`, Python `urllib`, Node `fetch` to `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` | All fail |
| Direct IP | The same hosts by IPv4 and IPv6 address, on ports 80, 443, 8443 | All fail |
| DNS | External name resolution; DNS over HTTPS and TLS | Fail |
| Proxy variables | Set and unset `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` | No change in result |
| Host reach | Bridge gateway address, `host.docker.internal`, link-local metadata address | Fail |
| Other protocols | UDP, QUIC, raw TCP | Fail |
| Gateway | ALLOW fixture package served with matching digest; BLOCK and QUARANTINE fixtures return no bytes | Pass |
| Escape hatches (agent platforms) | Excluded commands, unsandboxed retry, escalation, built-in fetch tools | Disabled or restricted |
| Self-tamper | The agent environment tries to change its own network settings | Fails |

## 6. F. Error handling

Rule for all rows: **never raise the status on a failure, never hide a failure, and state the next step in plain words.**

| Situation | What happens | Status shown | Next step shown |
|---|---|---|---|
| User lacks administrator privileges | The wizard completes every non-privileged step, writes a ready-to-send **admin request** (plain-language checklist and a generated command for the administrator), and stops | NOT ENFORCED (or PARTIALLY if an agent-scope layer is verified) | "Ask your administrator to approve the attached request. Re-run `slopseal setup` afterwards." |
| Docker unavailable | Wizard offers another tier if the detected agent has a managed layer, otherwise stops | NOT ENFORCED | "Docker is not available. Choose another setup, or install Docker." |
| Platform has no network control (cloud sandboxes) | Wizard switches to probe-only mode and prints the platform's admin checklist | NOT ENFORCED until a platform setting is applied and the probe passes | Checklist for the platform owner |
| Gateway fails to start | Wizard shows the log summary, rolls back the agent network change, and does not attach the agent to a network without a gateway | NOT ENFORCED | "Gateway did not start. Fix and retry. No settings were left half-applied." |
| Network verification fails | Wizard names the failed probe, leaves the boundary visible, and does not activate | NOT ENFORCED | Exact probe and a suggested fix |
| MCP connects but protection is unavailable | Every MCP result carries "NOT ENFORCED: <reason>". `verify_install` verdicts stay available as advice | NOT ENFORCED | "Run `slopseal setup`" |
| User cancels midway | Persist progress and the rollback record. Offer "roll back now" or "resume later". If nothing is verified, status stays NOT ENFORCED | NOT ENFORCED | "Resume with `slopseal setup`" |
| Probe cannot run (no `curl`, no shell access) | Counts as failure | NOT ENFORCED | Install the tool or use another probe route |
| Status attestation is stale | Auto-downgrade | NOT ENFORCED | Re-verify |
| Installer interrupted or crashes | Next run reads the setup record and the live state, then continues at the first unverified step | Unchanged until verified | Resume prompt |

## 7. Deliverables

### 7.1 Proposed architecture

```
 Host (human)                                  Agent environment (untrusted)
 +-----------------------------+               +--------------------------------+
 | slopseal setup (CLI)        |  creates      | AI agent + shell               |
 |  - detect                   |-------------> |  - network: internal only      |
 |  - plan / consent           |               |  - pip/npm -> gateway          |
 |  - apply / verify / rollback|               |  - SlopSeal MCP (advisory +    |
 |  - local dashboard 127.0.0.1|               |    status line)                |
 +--------------+--------------+               +---------------+----------------+
                | owns / attests                               | requests
                v                                              v
 +-----------------------------+               +--------------------------------+
 | Gateway (separate user /    | <-------------| package managers, MCP tool     |
 | container)                  |   only route  +--------------------------------+
 |  verify_install, digest     |
 |  key, policy pin, audit,    |----> PyPI / npm (allow-listed upstream only)
 |  rate state, status         |
 +-----------------------------+
```

### 7.2 One-step installation feasibility

| Variant | Feasible? | Notes |
|---|---|---|
| **One command that registers MCP and configures everything** (`slopseal setup`) | Yes on a local Linux host with Docker, and on developer machines running Claude Code, Codex or Cursor with an administrator step | Closest to genuine one-step |
| **MCP first, wizard second** (your proposed flow) | Yes, with one extra command, and MCP is advisory until setup is verified | The MCP server shows "NOT ENFORCED" with the next step |
| **Wizard opens automatically after Save** | Not supported by any client documented here | The specification requires consent before a URL opens, and no config event exists |
| **Cloud sandboxes** | No. Needs the platform owner | Probe-only |

### 7.3 Security and permission requirements

1. The wizard runs on the host as the human user. It never runs through the agent's shell or the MCP server.
2. Each privileged action is explained, shown, and confirmed. No silent `sudo`, and no stored credentials.
3. Docker rights are described as root-equivalent in the consent text.
4. The dashboard binds to `127.0.0.1`, checks `Host` and `Origin`, rejects DNS rebinding, and requires a pairing code typed by the user. No credentials in URLs.
5. Setup record, key, policy pin, and attestation are owned by the host or gateway and not writable by the agent.
6. The MCP server never performs a configuration change and never asks the agent to run a privileged command.
7. The installer is signed and pinned if distributed with a command-line pipe. Prefer a signed package and a visible plan.
8. All changes are recorded for rollback.

### 7.4 Potential security weaknesses

1. **A false ENFORCED** is the worst failure. It comes from probing the wrong network (MCP server instead of the agent shell), from a forgeable status file, or from a stale result. The rules in section 5.2 address these.
2. **The agent edits its own client settings** (user-scope sandbox, `mcp.json`). Only managed scope or a host-level boundary resists that.
3. **Escape hatches** in each agent product bypass the shell sandbox by design.
4. **Elicitation phishing.** A malicious MCP server could ask the user to open a hostile URL. The client shows the domain, but users click through. SlopSeal's page must use a known local address and a pairing code, and the wizard should say what it expects the URL to look like.
5. **Local web UI attacks:** DNS rebinding, CSRF, port scanning, other local users. Mitigated by the controls in 7.3.4, still a real attack surface.
6. **Gateway is a high-value target and a single point of failure.**
7. **Prompt injection through status text.** Status strings come from SlopSeal, but the agent may relay or obey them. The status line must be fixed wording with metadata only as data.
8. **Setup creates a false sense of safety** for installs that bypass the package managers (downloads by `curl`, `git clone` of code). The network boundary covers those only if the egress policy blocks them as well.
9. **Docker-specific unknowns** in section 3.3.
10. **Client behaviour changes** (the Claude Code and Codex issue reports show features moving). The probe is rerun on every start for that reason.

### 7.5 Estimated complexity and phases

Rough single-developer estimates, not including security review. Each phase needs a spec entry, an ADR where it changes a trust boundary, and your approval before it starts.

| Phase | Work | Estimate | Depends on |
|---|---|---|---|
| W0 | ADR 0005 (status model, probe contract, wizard threat model) | 1 week | Your decisions |
| W1 | Status model and probe library (stdlib), fixed wording for status | 2 weeks | W0 |
| W2 | Gateway production (live adapters, pip and npm protocol, separate-user runtime, upstream allow-list, attestation) | 4–6 weeks | PR #32, ADR 0004 |
| W3 | Docker reference topology and probe on a Linux host with Docker (prototype and bypass tests, including host reach) | 2–3 weeks | W1, W2, a Docker-capable test host |
| W4 | CLI wizard (detect, plan, consent, state machine, resume, rollback) | 3–4 weeks | W1 |
| W5 | Local dashboard (pairing code, Host/Origin checks, live status) | 2–3 weeks | W4 |
| W6 | MCP integration (status line in every result, `/slopseal-setup` prompt, URL elicitation where declared) | 1–2 weeks | W1, W5 |
| W7 | Agent profiles: Claude Code, Codex, Cursor (user-scope config, managed snippet, probe, escape-hatch checks) | 3–5 weeks | W4 |
| W8 | Cloud and Web probe-only mode and admin checklists | 1–2 weeks | W1 |
| W9 | Red-team bypass suite and signed releases | ongoing | all |

Total to a first useful Docker tier: roughly 14–20 weeks for one developer. A Claude Code and Codex tier adds the profile work.

## 8. What I could not verify

- Whether Codex now handles elicitation correctly. The reports I found are older and mixed.
- Whether VS Code supports URL-mode elicitation. I found only third-party reports of form mode.
- Whether Kiro supports URL-mode elicitation today, and whether Kiro hooks and egress controls enforce anything on Web.
- Whether a Docker `--internal` network lets the container reach services bound on the host's bridge address.
- Whether the agent products' managed settings stop an agent that edits its own user-level files in every case.
- Everything about Docker behaviour in practice. Docker is disabled in this sandbox.

## 9. Sources

- MCP elicitation specification (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation
- Claude Code MCP (elicitation modes, prompts): https://code.claude.com/docs/en/mcp
- Claude Code sandboxing (network namespace, proxy, local MCP servers run outside the sandbox): https://code.claude.com/docs/en/sandboxing
- Cursor MCP support table: https://cursor.com/docs/mcp ; Cursor sandbox.json: https://cursor.com/docs/reference/sandbox
- Codex elicitation issue: https://github.com/openai/codex/issues/6992
- Kiro MCP: https://kiro.dev/docs/mcp/ ; Kiro URL-mode issue: https://github.com/kirodotdev/Kiro/issues/4785
- VS Code elicitation report: https://den.dev/blog/vscode-mcp-elicitations-stop-guessing/
- Docker networking and iptables: https://docs.docker.com/engine/network/ , https://docs.docker.com/engine/network/firewall-iptables
- Earlier SlopSeal reports: `reports/SlopSeal_ONE_STEP_INSTALL_FEASIBILITY.md` (PR #33), `reports/SlopSeal_D1_EGRESS_EXPERIMENT.md` (PR #32)

Content was summarised, not quoted, for licensing reasons.

## 10. Recommendation

**Build a host-side guided setup with a local dashboard, and use MCP only as a status signpost and an optional on-ramp.**

1. **Entry points, in order of reliability:** `slopseal setup` in a host terminal (always works); the `/slopseal-setup` prompt and the status line in every MCP result (works where prompts exist); URL elicitation to the local dashboard (only where the client declares `url` mode, always with consent).
2. **First target:** Linux Docker, then Claude Code and Codex with managed-policy snippets. Do not target cloud sandboxes beyond probe-only guidance.
3. **Status is computed, never stored as a claim.** ENFORCED needs a host-level or managed boundary, passing probes from the agent's execution context, a fresh signed attestation, and disabled escape hatches. Anything unknown is NOT ENFORCED.
4. **Before any development decision:** run a Docker prototype on a Linux host to confirm section 3.3 (host reach, DNS, self-tamper), and test Kiro hooks and Web behaviour in a separate sandbox.
5. **Prerequisites:** gateway production work (R-GW-6), D2 (state and key outside the agent's reach), and D3 (human-held approval key). The wizard cannot honestly report ENFORCED without D2.
6. **Promise to users:** "Add SlopSeal, run one command, approve the changes, and see whether you are protected." Not "Save and it is done".

I have not started implementation and will wait for your approval.
