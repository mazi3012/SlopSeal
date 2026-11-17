# SlopSeal One-Step Installation: Technical Feasibility

- Date: 2026-11-17
- Status: investigation only. No production code, firewall, or sandbox setting was changed. PR #32 was not touched.
- Question: can SlopSeal be installed in one step, configuring the MCP tool, the package gateway, and network restrictions, without weakening its guarantees?

## 0. Summary

- **A one-step installer is feasible for local Linux containers and for agents with a managed policy layer (Claude Code, Codex, Cursor, Copilot local sandboxing).** In each of these, the installer can write the configuration, register the MCP tool, and run a probe. Some steps still need an administrator.
- **The installer cannot make network enforcement real by itself when it runs inside the agent's own sandbox.** The agent shell runs as root with `CAP_NET_ADMIN` in our sandbox, so any rule it adds can be removed by the same agent. Enforcement has to be applied by something the agent cannot change: a platform setting, a managed policy the agent cannot override, or a container/VM whose network the agent cannot reconfigure.
- **MCP does not provide network isolation.** An MCP server is a request channel: it lets the agent ask SlopSeal for a verdict. The agent's shell still has whatever network the platform gives it. Registering an MCP server does not restrict egress.
- **Cloud coding-agent sandboxes** (GitHub Copilot cloud agent, Kiro Web, Codex Cloud) expose egress controls only through the vendor's admin UI. I found no documented API that an installer could call to set them. Those cases need a manual admin step, and the installer can only verify the result.
- **Recommended architecture:** a two-part installer. A *host setup* step (run by an administrator or the platform owner) applies the network boundary. An *agent setup* step (run inside the sandbox) registers MCP, hooks, and the gateway client, then runs a probe matrix. The installer refuses to report success unless the probe shows the boundary holds.

## 1. Platform capabilities

### 1.1 Current sandbox (this environment, for reference)

Measured in this session, read-only:

| Item | Observed |
|---|---|
| Platform network mode | `OPEN_INTERNET` (from `get_sandbox_info`) |
| Process user | `uid=0(root)` |
| Effective capabilities | `CapEff=000001ffffffffff`, which includes `CAP_NET_ADMIN` |
| Firewall tooling | `iptables` present, `nft` absent |
| OUTPUT chain | Default ACCEPT, plus one platform REJECT for `169.254.169.254` |
| Registry reachability | `pypi.org` 200, `registry.npmjs.org` 200 |
| Proxy variable | `TRANSPARENT_PROXY_ENABLED=true` is set, but registries are still reachable directly, so this does not enforce registry egress |

Conclusion for this sandbox: an installer run here could add `iptables` rules, but the agent could remove them. It cannot produce enforcement.

### 1.2 Per-platform capability summary

Verified from the official pages linked in section 6. Items marked *unknown* were not confirmed.

| Platform | Programmatic network restriction? | Configuration surface | Enforced by OS or platform? | Admin-only layer? | Known escape hatches |
|---|---|---|---|---|---|
| **Claude Code** (Bash tool) | Yes | `settings.json`, `sandbox.network.allowedDomains`, `strictAllowlist`; managed settings | Yes on Linux and WSL2: commands run in a separate network namespace, and all traffic goes through a proxy outside the sandbox | Yes: managed settings can set `allowManagedDomainsOnly`, and only managed entries are honoured | `sandbox.excludedCommands` runs matching commands with no proxy; unsandboxed retry; the `!` shell prompt; built-in tools (WebFetch, Read) are not covered by `allowedDomains` |
| **Codex CLI / IDE** | Yes | `config.toml`: `sandbox_workspace_write.network_access`, `features.network_proxy` with domain rules; admin requirements | Yes: Linux uses `bwrap` and seccomp. Network is off by default in workspace-write | Yes: managed requirements and managed command allowlists | "Where policy permits full sandbox escalation ... that execution can bypass the command proxy" (the official doc), so escalation must be disabled in managed policy |
| **Cursor** | Yes | `sandbox.json` `networkPolicy` (`default: deny`, allow, deny), per-user and per-repo | Sandbox mode is OS-enforced; the policy file is applied by the agent runtime | Yes: team-admin policy layers above repo files and cannot be weakened by them; admin dashboard can enforce allowlists | Commands that need full network go to the approval classifier; the repo's own `sandbox.json` cannot override a team-admin policy |
| **GitHub Copilot in VS Code / CLI** (local sandboxing, GA Oct 2026) | Yes | Sandbox settings; enterprise managed settings; managed permissions for network domains (Business and Enterprise) | Yes for shell commands and children, per GitHub's documentation | Yes: managed settings "still apply ... before sign in", and `--no-sandbox` cannot disable a sandbox that managed settings require | Outbound network is *enabled by default* in VS Code unless configured. Sandboxing covers shell commands, not every built-in tool |
| **Generic Linux Docker** | Yes, strongly | `docker network create --internal`; a dual-homed gateway container; DOCKER-USER iptables chain | Yes, if the agent container has no route out and no `CAP_NET_ADMIN`, and cannot reach the Docker socket | Yes: the host operator controls the daemon | Agent with the Docker socket or `CAP_NET_ADMIN` can add routes. Docker's own iptables rules can bypass host firewall rules if left unmanaged |
| **Kiro Web** | Partly | Platform "internet access" levels (Connections only, Common dependencies, Open internet) and a custom allow-list | Platform-enforced. Whether the allow-list is strict and whether hooks run on Web are *unknown* | Yes: the platform owner sets it | No programmatic API found for the installer to call. Kiro's `permissions.yaml` does not apply on Web (per Kiro documentation) |
| **GitHub Copilot cloud agent** | Yes, per repo or org | "Internet access" firewall tab; a recommended allow-list is on by default | Yes, platform-enforced | Repo or org admin | The recommended allow-list includes package registries by default and must be edited manually |
| **Cursor cloud agents** | Yes | Admin dashboard egress settings | Platform-enforced | Team admin | Configured in the dashboard, not by an installer |
| **Codex Cloud** | Partly | Environment internet settings; "agent internet access" and domain allow-list (Legacy) | Platform-enforced | Workspace admin | Dependencies can be installed during a setup phase that has network access |

## 2. Automatic installation

### 2.1 Can one installer configure MCP, the gateway, and network restrictions?

| Component | Automatable from the installer? | Notes |
|---|---|---|
| MCP server registration | Yes, for Claude Code, Codex, Cursor, Copilot (each has a user or project config file) | Writes config only. Does not restrict network |
| Hook registration (command-text hook) | Yes, where the agent supports PreToolUse hooks | Advisory. Kiro's hook behaviour on Web is unconfirmed |
| Gateway process | Yes, as a local process or a container | It is a separate trust domain only if run as another user or container (section 4) |
| Agent-level network allow-list (Claude Code, Codex, Cursor, Copilot local) | Yes for the *user* scope. The *managed* scope needs an administrator | A user-scope setting can be edited by the user, so it is advisory for the user's own agent |
| Host-level isolation (`--internal` network, gateway dual-homing) | Yes, if the installer runs with Docker rights on the host | Requires the operator's approval because Docker rights are root-equivalent |
| Platform sandbox network mode (Kiro Web, Copilot cloud, Codex Cloud, Cursor cloud) | **No.** No documented API found | Admin UI only |
| Shared-host firewall rules | Possible, but requires root and is removable by root | Not an enforcement boundary against an agent with root |

### 2.2 Can the installer detect the environment?

Yes, for the local cases, using observable signals: the presence of the agent's config directory, the agent's binary, `docker info`, `/proc/self/status` (`CapEff`), `uid`, the presence of `bwrap` and `socat` (needed by Claude Code's sandbox on Linux), and whether the process is inside a container (`/.dockerenv`, cgroup). Cloud platforms cannot be reliably detected from inside the sandbox, so the installer should ask the user to declare the platform and then verify.

### 2.3 Can it identify whether administrator approval is required?

Partly. The installer can detect whether it can write each *managed* location:

- Claude Code managed settings (file or MDM): writable only by root or an MDM tool.
- Codex managed requirements: admin-provisioned.
- Cursor team policy: admin dashboard only.
- Docker: needs membership in the `docker` group or root.
- Platform sandbox: not detectable from inside the sandbox.

The installer should print which steps need an administrator, and it must not try to escalate privileges to do them.

### 2.4 Can it verify that restrictions are actually enforced?

Only partly. Active probes from inside the sandbox can show that the boundary *holds for the probed paths*. They cannot show that it holds against an adversarial agent that tries other paths. The probe matrix is in section 4.4. A probe pass is evidence, not proof. A proof needs the enforcement point to be outside the agent: a platform attestation, or a container host whose network the agent cannot configure.

## 3. Environment comparison for each target

| Environment | One-step install possible? | What the installer can do | Admin step required | Enforcement the installer can verify | Complexity |
|---|---|---|---|---|---|
| **Claude Code** (Linux or WSL2) | Mostly | Install `bubblewrap` and `socat` (with consent), write project and user settings, register the MCP tool, run probes | Managed settings for `allowManagedDomainsOnly`, and to disable `allowUnsandboxedCommands` and the `!` escape | Probe: direct access fails for Bash; the gateway succeeds. Built-in WebFetch is a separate path that must be disabled or policy-restricted | Medium |
| **Claude Code** (macOS) | Partly | Same config. Seatbelt blocks non-proxy connections by default | Same as above | Probe, same limits | Medium |
| **Codex CLI / IDE** | Mostly | Write `config.toml`, enable `network_proxy` with domain rules, register MCP, probe | `requirements.toml` (managed) to force sandbox, forbid escalation, and fix the network policy | Probe for Bash-equivalent commands. Escalation path must be tested separately | Medium |
| **Cursor** (desktop) | Mostly | Write `.cursor/sandbox.json` and `.cursor/hooks.json` (hooks with `failClosed`), register MCP | Team-admin policy and dashboard allow-list | Probe. Repo file alone is overridable by an in-repo change, so it is advisory for untrusted repos | Medium |
| **VS Code + Copilot** (local sandboxing) | Partly | Write local sandbox settings and MCP registration | Enterprise managed settings (Business or Enterprise plan) | Probe for shell commands; managed settings are the only tamper-resistant layer | Medium-high |
| **Generic Linux Docker** | Yes, with Docker rights | Create an `--internal` network, the gateway container (dual-homed, separate user), agent container on the internal network only, and the probe | Docker rights on the host (root-equivalent) | Strongest local option. Probe plus a host-side check that the agent container has no default route to the internet | Medium-high |
| **Kiro Web** | No, not automatable | Register MCP and the hook if supported; probe | Platform owner sets the internet access level and the allow-list | Probe only. Whether hooks run on Web is unconfirmed | High (manual) |
| **Copilot cloud agent** | No, not automatable | Probe and print the required allow-list | Repo or org admin edits the firewall allow-list | Probe only | High (manual) |
| **Cursor cloud agents** | No, not automatable | Probe and print the required settings | Team admin | Probe only | High (manual) |
| **Codex Cloud** | No, not automatable | Print setup steps; probe | Workspace admin | Probe only | High (manual) |

## 4. Security architecture

### 4.1 Preventing direct PyPI and npm access

Enforcement belongs at the network layer, not in tools. A deny-by-default egress policy with one allowed destination (the gateway's address and port) is the only approach that does not depend on which HTTP client the agent uses.

Requirements for that policy:

- Allow only the gateway's IP and port. Deny everything else, including IPv6, DNS to public resolvers, and other ports.
- Resolve registry names only through the gateway, or deny DNS to the agent altogether.
- Do not rely on an environment variable such as `HTTP_PROXY`. A process can unset it.

### 4.2 Bypass channels that must be closed

| Channel | Why it bypasses a tool-level control | Closed by |
|---|---|---|
| `curl`, `wget`, `python urllib`, `node fetch`, `git` over HTTPS | Any HTTP client can reach the registry | Network namespace or `--internal` network with only the gateway reachable |
| Direct IP to a registry CDN | Hostname allow-lists are bypassed by IP | Network-layer allow-list by IP *and* destination, plus no DNS path to the registry |
| Alternate ports (for example 8443) | Port-based allow-lists are bypassed | Deny all ports except the gateway's |
| IPv6 | Many policies cover only IPv4 | Disable IPv6 in the agent network, or allow only the gateway's IPv6 address |
| Environment proxy variables | A process can set its own proxy, or unset the one provided | Enforce at the network layer, not via env |
| DNS-over-HTTPS or DNS-over-TLS | Name lookups bypass DNS allow-lists | Deny outbound 443 and 853 except to the gateway |
| UDP and HTTP/3 (QUIC) | Not covered by TCP proxies | Deny UDP except to the gateway (if any) |
| Raw TCP tools (`ssh`, `nc`) | Tools that ignore proxy variables | Network-layer deny |
| Unsandboxed commands (Claude `excludedCommands`, unsandboxed retry; Codex escalation; Cursor approval) | These run outside the agent's sandbox | Disable them in managed policy. Test them separately |
| Built-in agent tools (for example WebFetch) | They bypass the shell sandbox | Disable them in managed policy, or allow only the gateway |
| The agent editing its own config (`~/.claude/settings.json`, `.cursor/sandbox.json`, `config.toml`) | Relaxes the user-scope policy | Managed scope on the platform; the probe catches it on next run |
| Installing a second MCP server that does network I/O | An extra process with the same network | Same network layer. MCP itself is not a boundary |
| The gateway as an open proxy (SSRF) | If the gateway forwards any URL, it becomes the bypass | Gateway forwards only to an allow-list of registry hosts |

### 4.3 Protecting the gateway from the untrusted agent

- Run the gateway as a separate user or in a separate container, with no shared writable volume with the agent.
- Put the signing key, the policy pin, the audit log, and the rate-limit state in the gateway's own storage. The agent must have no read access to them. (This is F-16 and D2, still open.)
- The gateway's own egress is limited to the registry hosts it needs. It must not be able to reach arbitrary hosts.
- Audit writes happen only in the gateway, so an agent cannot rewrite its own history.
- Count rate limits per session token issued by the gateway, so restarting the agent process does not reset them.

### 4.4 Probe matrix (verification)

A verifier run inside the sandbox must check each row, and it must report "not enforced" if any direct-access row succeeds:

| Probe | Expected result |
|---|---|
| `curl` to `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` | Fails |
| Same via Python `urllib` and Node `fetch` | Fails |
| Direct IP of each registry, IPv4 and IPv6 | Fails |
| Ports 80, 443, 8443 to the registry | Fails |
| DNS-over-HTTPS to a public resolver | Fails |
| Gateway address, artifact route | Succeeds for ALLOW, and returns no bytes for BLOCK |
| Changing `HTTP_PROXY`, `HTTPS_PROXY` | No change in result |

### 4.5 Failing closed

- If the installer cannot establish the boundary, it must not enable the agent workflow. It may still register MCP for advisory use, but it must print "NOT ENFORCED" and set a status that the MCP tool reports on each call.
- The MCP tool and hook should be able to read that status and refuse to report ALLOW for installs unless the boundary is verified.
- A probe that cannot run (no `curl`, no sandbox) counts as a failure, not a pass.

### 4.6 Security of the installer itself

- A `curl | sh` installer is a supply-chain risk. Prefer a signed release (for example Sigstore or minisign), a pinned version, and a checksum, and show the plan before any change.
- The installer must not run `sudo` or change managed settings without an explicit, separate confirmation.
- It must be idempotent, produce a dry-run report, and keep a rollback record of every file it changed.

## 5. Installation experience

A command such as `curl -fsSL <official-installer> | sh` is feasible for a local developer machine or a container. The installer would:

1. Detect the platform and the capabilities listed in section 2.
2. Print a plan: what it will write, what needs root, and what needs an administrator.
3. Require confirmation for each privileged step.
4. Install or configure the gateway, the MCP registration, and the agent settings.
5. Run the probe matrix (section 4.4) and print the result.
6. Exit non-zero if the boundary is not verified.

Limits:

- For Kiro Web, Copilot cloud, Cursor cloud, and Codex Cloud, the installer cannot change the platform setting. It can only print the required steps and verify the result.
- A `curl | sh` install is not a substitute for an admin decision. The installer must say so.

## 6. Sources

Verified in this investigation:

- Claude Code sandboxing: https://code.claude.com/docs/en/sandboxing (network namespace, proxy, `allowedDomains`, `strictAllowlist`, `allowManagedDomainsOnly`, `excludedCommands`, built-in tools not covered)
- Claude Code admin setup: https://code.claude.com/docs/en/admin-setup (managed settings delivered by admin console, MDM, or file)
- Codex approvals and security: https://learn.chatgpt.com/docs/agent-approvals-security (network off by default, `network_proxy`, managed command allowlist, escalation bypass)
- Cursor sandbox.json: https://cursor.com/docs/reference/sandbox (`networkPolicy` default deny, team-admin layer cannot be weakened by repo files)
- Docker networking: https://docs.docker.com/engine/network/ (`none` driver, `--internal` networks)
- Docker iptables: https://docs.docker.com/engine/network/firewall-iptables (Docker manages iptables rules)

Found in search results only (not opened in full): Copilot cloud agent firewall (https://docs.github.com/copilot/customizing-copilot/customizing-or-disabling-the-firewall-for-copilot-coding-agent), Copilot local sandboxing (https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/using-local-sandboxing), VS Code agent security (https://github.com/microsoft/vscode-docs/blob/main/docs/agents/run/security.md), Cursor security hardening (https://cursor.com/docs/enterprise/security-hardening).

Content was summarised, not quoted, for licensing reasons.

## 7. Estimated implementation complexity

| Work item | Estimate | Depends on |
|---|---|---|
| Installer core (detect, plan, dry run, confirm, rollback, signed release) | 3–4 weeks | None |
| Gateway production: live PyPI and npm adapters, pip and npm protocol, session tokens, upstream allow-list | 4–6 weeks | ADR 0004 |
| Linux Docker reference (internal network, dual-homed gateway, probe) | 2–3 weeks | Gateway production |
| Claude Code profile (user config, MCP, probe, managed snippet) | 1–2 weeks | Installer core |
| Codex profile (config, `network_proxy`, requirements snippet, probe) | 1–2 weeks | Installer core |
| Cursor profile (`sandbox.json`, `hooks.json`, MCP, probe) | 1–2 weeks | Installer core |
| VS Code and Copilot profile | 3+ weeks, with uncertainty about APIs | Installer core |
| Cloud platform guides and probe-only mode | 1–2 weeks, mostly documentation | Probe |
| Bypass test suite and red-team regression tests | Ongoing | Probe |

These are rough engineering estimates for one developer. They do not include security review.

## 8. Recommended development phases

Each phase needs its own spec entry, ADR where it changes a trust boundary, and approval from you before it starts.

| Phase | Goal | Exit criteria |
|---|---|---|
| **P0** Decisions and threat model | ADR 0005: enforcement tiers, what the installer may and may not do, the probe contract | You approve the tiers and the "NOT ENFORCED" rule |
| **P1** Gateway production | Live adapters, pip and npm protocol, separate-user runtime, upstream allow-list | Gateway serves pip and npm installs for ALLOW packages and refuses the rest, with tests against recorded registry responses |
| **P2** Linux Docker reference | Agent container on an internal network; gateway dual-homed; probe matrix | Probe matrix passes; a deliberate bypass attempt from the agent container fails; the gateway still reaches the registries |
| **P3** Installer v1 | Detect, plan, confirm, configure Claude Code, Codex, and Cursor, register MCP, run probes, report status | Dry run is correct; probes gate the success status; rollback restores every changed file |
| **P4** Managed-policy snippets | Generated admin snippets for Claude managed settings, Codex requirements, Cursor team policy | An administrator can apply each snippet, and the probe confirms the result |
| **P5** Cloud and Web guides | Probe-only mode and step-by-step admin checklists for Kiro Web, Copilot cloud, Cursor cloud, Codex Cloud | Probe reports correctly on each platform |
| **P6** Assurance | Red-team bypass suite, signed releases, attestation where the platform provides it | Each known bypass has a regression test |

## 9. Security risks and limitations

1. **The installer can be bypassed by the same agent if it runs inside that agent's sandbox with root.** Mitigation: host-level setup by an administrator, managed scope, or a container the agent cannot reconfigure.
2. **Probes show behaviour, not guarantees.** A passing probe does not prove the agent cannot find another path. Mitigation: probes plus a platform attestation where possible.
3. **Escape hatches in the agent products** (excluded commands, unsandboxed retry, escalation, built-in tools) bypass the shell sandbox by design. Mitigation: managed policy that disables them; probes for each.
4. **Managed scope needs an administrator.** Without it, the user can change the policy. The installer must say so and report "advisory".
5. **Cloud platforms cannot be configured by an installer.** Mitigation: documented admin checklists and probe-only verification.
6. **Kiro-specific unknowns:** whether hooks run on Web; whether the Web allow-list is strict; whether it has an API. I did not confirm these, and they need a test in Kiro before any claim.
7. **The gateway is a single point of failure and a high-value target.** Mitigation: separate runtime, minimal egress, audit, availability target.
8. **Supply chain of the installer and gateway.** Mitigation: signed releases, pinned dependencies (ADR 0002 keeps the core stdlib-only).
9. **Docker rights are root-equivalent.** The installer must not assume it can use them.
10. **Platform behaviour changes.** Agent products change their sandbox and config keys often. Mitigation: pin supported versions and run probes on every install and on each agent upgrade.
11. **Approval fatigue.** If users routinely accept host allow-list prompts, the boundary erodes. Mitigation: deny-by-default with no in-session prompt for registry hosts.

## 10. Recommended architecture

**A two-part installer with an explicit enforcement tier.**

```
Host setup (administrator or platform owner)           Agent setup (inside the sandbox)
  - creates internal network / gateway container         - registers MCP (advisory verdicts)
  - runs gateway as a separate user                      - writes agent-scope settings
  - writes managed settings (admin approval)             - registers hooks where supported
  - applies platform allow-list where possible           - runs probe matrix (section 4.4)
            |                                                          |
            +--------------------------+-------------------------------+
                                       v
                 Status: ENFORCED (tier 2 or 3, probe passed)
                       or NOT ENFORCED (probe failed, or no admin step)
```

Tiers:

- **Tier 3, enforced by the platform or a host the agent cannot reconfigure.** Local Docker with an internal network, or a platform allow-list set by an admin. The only tier that supports "D1 is enforced".
- **Tier 2, enforced by the agent product's managed policy.** Claude Code managed settings, Codex requirements, Cursor team policy, Copilot enterprise managed settings. Enforced for the agent's shell, subject to its escape hatches being disabled.
- **Tier 1, advisory.** User-scope settings, MCP, hooks. Useful for UX and for catching honest mistakes. Not a boundary.
- **Tier 0, not enforced.** The installer prints the result and the MCP tool reports it.

Rules:

1. The installer reports the highest tier it has verified with probes. It never reports a higher tier than it verified.
2. The installer never claims D1 is enforced unless the tier is 3, or tier 2 with the escape hatches disabled and a probe pass.
3. Every privileged step is shown in advance and needs its own confirmation.
4. The gateway is the only package source in every tier. Only its address is allowed through the agent's network.

**Recommended first implementation target:** Tier 3 on Linux Docker, because it is the only environment in this investigation where the installer controls the network boundary without relying on an administrator's UI. Then Tier 2 for Claude Code and Codex, which have the strongest documented OS-level sandboxes with managed policy.

## 11. What requires whom

| Requirement | Who | Automatable? |
|---|---|---|
| Install gateway and SlopSeal package | Developer | Yes |
| Register MCP and hooks | Developer | Yes, where the agent has a config file |
| Agent-scope network allow-list | Developer | Yes, advisory |
| Managed policy (Claude, Codex, Cursor, Copilot) | Administrator | Snippets only |
| Docker internal network and gateway container | Host operator | Yes, with Docker rights |
| Platform internet access level (Kiro Web, Copilot cloud, Cursor cloud, Codex Cloud) | Platform or team admin | No (no API found) |
| Verification probes | Developer | Yes |

## 12. Open questions for you

1. Which platform is the first target? I recommend Linux Docker (Tier 3).
2. Do you have an administrator for the managed-policy layer, or is the target developer machines only?
3. Can we test Kiro hook behaviour and Kiro Web allow-list enforcement in a separate sandbox? That is needed before any Kiro claim.
4. Accept the probe-based "enforced" definition in rule 2 above, or require a platform attestation for the strongest claim?

I have not started implementation. I'm waiting for your approval.
