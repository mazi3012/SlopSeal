# SlopSeal v1 Scope: Kiro-Native Investigation (IDE, CLI, Web)

- Date: 2026-11-17
- Status: read-only investigation. No production code, firewall, network, sandbox, hook, or Kiro setting was changed. PR #32 was not touched. D1 is **not enforced**. D2 and D3 are not started.
- Scope: Kiro IDE, Kiro CLI, Kiro Web.

## 0. Read this first: what was tested and what was not

I am running inside **Kiro Web**. That is the only Kiro surface I can test.

| Surface | What I could do | What the results below are |
|---|---|---|
| **Kiro Web** | Run read-only tests in this live session | **Tested** where marked `[TESTED]`. Documentation and code declarations are marked separately |
| **Kiro IDE** | Nothing. I have no IDE session | **Documentation only** (`[DOC]`). Nothing tested |
| **Kiro CLI** | Nothing. I have no CLI session | **Documentation only** (`[DOC]`). Nothing tested |

The IDE and CLI behave differently from Web in several documented ways (a local sandbox that Web does not have, a different MCP execution model, user-level hook files). Do not read Web results as IDE or CLI results. Section 8 gives a read-only test protocol for the IDE and CLI to run in throwaway installs.

Labels: `[TESTED]` measured in this Kiro Web session. `[OBSERVED]` seen on disk in this session (configuration, files). `[DOC]` an official kiro.dev page. `[CODE]` a type declaration in the installed Kiro agent bundle (shows a setting exists, not how it behaves). `[UNTESTED]` not verified.

No secret was read. I checked file permissions of the SlopSeal key file and did not read its contents. Environment variable values were hidden except booleans.

## 1. Test matrix

| # | Question | Kiro Web | Kiro IDE | Kiro CLI |
|---|---|---|---|---|
| 1.1 | Does PreToolUse run? | **Yes** `[TESTED]` | Yes `[DOC]` `[UNTESTED]` | Yes (V3) `[DOC]` `[UNTESTED]` |
| 1.2 | Does exit 2 block the operation? | **Yes** `[TESTED]` | Yes `[DOC]` `[UNTESTED]` | Yes `[DOC]` `[UNTESTED]` |
| 1.3 | Does the agent see stderr on a block? | **Yes, verbatim** `[TESTED]` | Yes `[DOC]` | Yes `[DOC]` |
| 1.4 | Does the developer see stderr on a block? | **Unknown.** I can only see the agent side `[UNTESTED]` | Unconfirmed `[DOC]` (output panel logs mentioned) | Unconfirmed `[DOC]` (hook card mentioned) |
| 1.5 | Is stderr from an allowed (exit 0) command visible? | **Not tested.** Needs an allowed install, which I may not run `[UNTESTED]` | Not confirmed `[DOC]` | Not confirmed `[DOC]` |
| 1.6 | Other non-zero exit and timeout behaviour | Not documented for Web `[DOC]` | **Two pages disagree** (warn and allow, or block) `[DOC]` | Warn and allow `[DOC]`. Timeout outcome not documented |
| 1.7 | Where do hook files live? | Workspace `.kiro/hooks`, or Agent Config > Hooks `[DOC]`. A hook file was present here `[OBSERVED]` | Workspace `.kiro/hooks` `[DOC]` | Workspace and `~/.kiro/hooks` `[DOC]` |
| 2.1 | Network restriction control | Per-user setting in Settings > Sandbox, with levels and a custom allow-list `[DOC]`. Current mode here: `OPEN_INTERNET` `[TESTED]` | Local sandbox `networkAccess` (`DEFAULT_BLOCKED`, `COMMON_DEPENDENCIES`, `DEFAULT_ALLOWED`) and `sandbox_network` rules. Sandbox is **off by default** `[DOC]` | Same as IDE, local V3 sessions, CLI 2.31+ `[DOC]` |
| 2.2 | Can the agent edit the allow-list or sandbox setting? | No mechanism found. The settings directory is not writable by my shell `[TESTED]`. Not exercised | No: always-deny rules block agent writes to `~/.kiro/settings`, `.kiro/settings` `[DOC]` `[UNTESTED]` | Same `[DOC]` `[UNTESTED]` |
| 2.3 | Who must control it? | The **user**. No organization admin control for Web `[DOC]` | User, workspace, and admin `managed-settings.json` (admin can add deny or ask rules, not allow) `[DOC]`. Whether admin can force `sandbox.json` is unconfirmed. A `sandboxNetworkMode` governed setting exists in the agent bundle `[CODE]` | Same as IDE `[DOC]` |
| 2.4 | Do alternative HTTP clients reach PyPI and npm? | **Yes, all** `[TESTED]` (section 3) | Not tested. A working sandbox blocks them by design `[DOC]` | Same |
| 3.1 | Where does the MCP server run? | **Outside my command sandbox.** No MCP process is visible in my process list `[TESTED]` | stdio servers run **outside** the sandbox by default. `mcpSandboxing: true` moves them inside `[DOC]` | Same as IDE `[DOC]` |
| 3.2 | Does it share the agent's network restrictions? | **Unknown.** Both have open internet here `[UNTESTED]` | No by default. Yes if `mcpSandboxing` is on `[DOC]` | Same |
| 3.3 | Can the MCP server reach registries when the agent cannot? | **Not testable** without changing the network setting `[UNTESTED]` | Yes by default (documented asymmetry) `[DOC]` `[UNTESTED]` | Same |
| 3.4 | Can the agent bypass MCP and download directly? | **Yes** `[TESTED]` | Only if the sandbox is off or allows it `[DOC]` | Same |
| 4.1 | Can a Power install MCP, hooks and steering together? | MCP: yes. Steering: yes in the legacy format `[OBSERVED]`. **Hooks: not documented, none in any installed Power** `[OBSERVED]` `[DOC]` | Same `[DOC]` | Same `[DOC]` |

## 2. Test 1: Hook execution (Kiro Web, tested)

| Observation | Result | Evidence |
|---|---|---|
| The hook fired before `execute_bash` | Yes | Kiro replied "Tool execute_bash was intercepted by PreToolUse hooks before execution" on the blocked commands in this session. The hook is the workspace file `/projects/sandbox/.kiro/hooks/block-agent-installs.json` `[OBSERVED]` |
| Exit code 2 prevented execution | Yes | Kiro stated "The tool was NOT executed" for every blocked call |
| The agent received stderr | Yes | The full block text appeared in the instruction block, including the JSON problem line |
| The hook fails closed on unparseable text | Yes | Heredocs with unbalanced quotes were blocked with the "cannot be read" reason |
| Hook registered by the MCP bootstrap | Yes | The file is owned by uid 0 and was written at 13:05:49, at session start, before any command of mine `[OBSERVED]`. The R-1.9 bootstrap therefore works on Web |
| The running hook is an older SlopSeal copy | Yes | Its interpreter is a uv cache path with its own installed copy, and the wording is the pre-messaging text. The workspace hook file also still has the old name `[OBSERVED]` |
| The developer sees stderr on a block | **Not testable by me** | I can see only what Kiro gives the agent |
| stderr from an allowed install is visible | **Not tested** | The only way to produce an allowed-install output is to run a real install, which I may not do |
| Behaviour on timeout | **Not tested** | Not documented either |

Documented but untested for IDE and CLI: PreToolUse runs on both, exit 2 blocks and returns stderr to the model. CLI 3.4.0 or later adds JSON decisions (`allow`, `ask`, `deny`, `updatedInput`). One documentation page says a non-zero code other than 2 allows the call with a warning. Another says it blocks in the IDE. This conflict matters because SlopSeal's wrapper relies on exit 2.

## 3. Test 2: Network restriction ownership (Kiro Web, tested)

| Check | Result |
|---|---|
| Platform network mode | `OPEN_INTERNET` `[TESTED]` |
| Shell sandbox | The shell runs under `bwrap` with `--unshare-pid` and bind mounts but **without `--unshare-net`**. The shell shares the container network `[TESTED]` |
| Privileges | The shell is root with the full capability set. `iptables -S` works. I did not change any rule `[TESTED]` |
| Existing firewall | One REJECT for the cloud metadata address. No rule touches registry traffic. The NAT table maps some loopback and link-local ports to platform services `[TESTED]` |
| `TRANSPARENT_PROXY_ENABLED=true` | Present, but registries are reachable directly. It does not enforce registry egress in the current mode `[TESTED]` |
| Kiro trust files | `permissions.yaml`, `mcp.json`, and the settings directory are **not writable** by my shell `[TESTED]` (`os.access`, nothing written). The file itself says it exists to stop the agent editing its own trust boundaries `[OBSERVED]` |
| Network setting visible as a file? | No. The sandbox state directory is empty and read-only. The Web internet level seems to live on the platform side, not in a file `[OBSERVED]` |
| Can the agent change the Web allow-list? | **No mechanism found, not exercised.** The documentation says it is a per-user setting in the Web UI `[DOC]`. Whether the container-level root could affect a platform-level restriction is **unknown** `[UNTESTED]` |
| Can the agent disable sandbox restrictions? | The settings files are write-protected. But the agent shell is root with `CAP_NET_ADMIN` in its container, so it could change container-level firewall rules. I did not try. If Kiro enforces Web egress only inside the container, that is a bypass. If it enforces outside the container, it is not. **Unknown** |

**Alternative HTTP clients reached both registries** (HEAD requests, `[TESTED]`):

| Client | PyPI | npm |
|---|---|---|
| Python `urllib`, environment proxy settings | 200 | 200 |
| Python `urllib`, proxy disabled | 200 | 200 |
| Node `fetch` | 200 | 200 |
| Raw TLS socket to a resolved IPv4 address | 200 | (not run) |
| Raw TLS socket to an IPv6 address | connection error | (not run) |
| `npm view express version` | n/a | returned a version |
| `pip index versions requests` | returned a version | n/a |

The IPv6 failure shows no IPv6 path in this container, not a restriction. All results are what an open network produces.

**Who controls the setting:**

- Web: the user, in Settings > Sandbox (or Kiro Mobile). No organization-admin control is documented for Web `[DOC]`.
- IDE and CLI: user and workspace `sandbox.json`. The agent cannot write them (always-deny). An administrator can deploy `managed-settings.json` with deny and ask rules that users cannot override, but the documentation says admin policies are client-enforced and can be bypassed with local admin access `[DOC]`.
- The enterprise-management reference lists `sandbox_network` as unsupported, while the agent bundle declares governed values for `sandbox`, `mcpSandboxing`, `sandboxFailClosed`, and `sandboxNetworkMode` `[CODE]`. These two statements conflict. Treat admin enforcement of sandbox network mode as **unconfirmed**.

## 4. Test 3: MCP network isolation (Kiro Web, tested)

| Check | Result |
|---|---|
| Where does the SlopSeal MCP server run? | Not in my process namespace: no `slopseal`, `uvx`, or MCP process appears in my process list. My shell has its own PID namespace `[TESTED]` |
| How is it started? | `mcp.json` in the Kiro settings directory starts `uvx --from git+https://github.com/mazi3012/SlopSeal.git slopseal-mcp` with `SLOPSEAL_OFFLINE_SNAPSHOT=0` (live mode) and `waitForReady: true` `[OBSERVED]`. The platform's own `tool-server` is reached at `http://127.0.0.1:8080/mcp` `[OBSERVED]` |
| Does it share my filesystem and user? | **Yes.** It wrote `/projects/sandbox/.slopseal/` as uid 0 at 13:14, matching my two MCP calls (audit file has genesis plus 2 verdicts) `[TESTED]` |
| Is its state protected from the agent shell? | **No.** My shell can read and write `secret.key`, `audit.jsonl`, `ratelimit.json` `[TESTED]` (permission checks only, contents not read) |
| Does it reach registries? | Yes. Its answers came from live PyPI and OSV data `[TESTED]` |
| Does it share the agent's network restrictions? | **Unknown.** Both are unrestricted now. Which of the two Web documentation pages is right (inside or outside the sandbox) cannot be settled without setting an allow-list `[UNTESTED]` |
| Can MCP reach a registry when the agent cannot? | **Not testable** here without changing the network setting `[UNTESTED]` |
| Can the agent bypass MCP and download directly? | **Yes** (section 3) |
| Platform services reachable from the shell | Loopback ports 8080, 8081, 8082 and 1338 accept connections from my shell `[TESTED]` (connect only, no data sent) |

Documented for IDE and CLI: stdio MCP servers run **outside** the command sandbox by default, with the user's access. With `mcpSandboxing: true` they run inside it and follow the same network rules. Remote HTTP and SSE servers are never sandboxed `[DOC]`. If this holds, it gives the useful asymmetry: the shell can be blocked while the MCP server reaches registries. It also means MCP-based probes would test the wrong network, so probes must run through the agent's shell.

## 5. Bypass findings

| ID | Finding | Surface | Evidence | Severity |
|---|---|---|---|---|
| K-1 | **Any HTTP client reaches PyPI and npm directly.** The hook is the only barrier | Web | `[TESTED]` | HIGH (D1 not enforced) |
| K-2 | **SlopSeal's key, audit log and rate-limit state are readable and writable by the agent shell.** This is audit finding F-16, now confirmed live | Web | `[TESTED]` | HIGH |
| K-3 | **The workspace hook file is writable by the agent shell** (`os.access`). An actual write was not attempted. The documentation says writes to `.kiro/hooks` through Kiro's file tools always prompt, but a shell command is a different path and is not tested. The installed hook does not detect a command that deletes or edits it (function-level check) | Web | `[TESTED]` partial | HIGH if confirmed |
| K-4 | **Container root with `CAP_NET_ADMIN`.** If any Web egress rule lives inside the container, the agent can remove it | Web | `[TESTED]` privileges, enforcement location unknown | HIGH if confirmed |
| K-5 | **The hook and the MCP server run different SlopSeal copies and configurations** (hook: uv-cache copy, old text; MCP: git copy, live mode). F-21 confirmed. The hook gate can apply different policy than the MCP tool | Web | `[OBSERVED]` | MEDIUM |
| K-6 | The local command sandbox is off by default on IDE and CLI, so a user who never enables it has no network control | IDE, CLI | `[DOC]` | MEDIUM |
| K-7 | The two documentation pages disagree on non-zero exit behaviour in the IDE | IDE | `[DOC]` | MEDIUM (could make a crash fail open) |
| K-8 | Existing F-01 hook detection gaps still apply on every surface that runs the command-text hook | All | audit | CRITICAL (existing) |
| K-9 | A Power cannot install a hook. SlopSeal relies on the MCP bootstrap to write it, which only works after the MCP server starts | All | `[DOC]` `[OBSERVED]` | LOW-MEDIUM |

**Positive findings:** Kiro Web does protect its own trust files from the agent shell (read-only mounts), and the bootstrap-registered hook fires and blocks reliably. These show the platform's file-level protection is real. What is missing is the same protection for SlopSeal's own state and hook.

## 6. Kiro Power architecture (recommended)

### 6.1 What a Power can and cannot do `[DOC]` `[OBSERVED]`

| Capability | Plugin format (`plugin.json`) | Legacy format (`POWER.md`) |
|---|---|---|
| MCP server registration | Yes (`mcp.json`, managed internally, namespaced) | Yes (`mcp.json`, written to the user MCP config) |
| Steering files | Not listed | Yes. Installed examples have `steering/` `[OBSERVED]` |
| Skills (guided procedures) | Yes (`skills/`) | Not listed |
| Hooks | **Not documented. None in any installed Power** `[OBSERVED]` | Same |
| Post-install code or onboarding | **None documented** | **None documented** |
| Surfaces | IDE, CLI v3, Web (not inside cloud sessions for CLI install) | Same |

The repository's `power-upload/` has `POWER.md`, `mcp.json`, and `plugin.json` together. Which format wins when both exist is **untested**.

### 6.2 Recommended structure

```
slopseal Power
 ├─ plugin.json            (Agent Plugin format, version-pinned)
 ├─ mcp.json               (stdio server, pinned git ref, waitForReady, no workspace-relative paths)
 ├─ skills/
 │    ├─ setup/SKILL.md    (guided setup, activates on "set up SlopSeal")
 │    └─ status/SKILL.md   (report the current enforcement status)
 └─ POWER.md               (documentation and steering text, if the legacy format is also needed)
```

Runtime pieces that the Power cannot install, and how each is provided:

| Piece | Provided by | Notes |
|---|---|---|
| MCP server | The Power | Starts on session start. First tool result carries the status line |
| Install hook | The MCP bootstrap (R-1.9), already working on Web | Must pin one SlopSeal copy for hook and MCP (K-5) |
| Hook protection | Not available in Web today | The file is agent-writable. IDE and CLI: put the hook in a user-level or agent-config location the agent cannot write, where supported |
| Sandbox network policy (IDE, CLI) | A host-side step by the user: `slopseal setup` writes user-level `sandbox.json` and `permissions.yaml` | Agent writes to those paths are denied by Kiro |
| State and key | Outside the workspace and denied for sandbox reads (IDE, CLI), via a `permissions.yaml` `fs_read` deny entry | Web has no equivalent. It needs a remote gateway |
| Configuration sync | Possible route: cloud hooks and Power config applied to local IDE and CLI sessions `[DOC]` | Worth testing as a distribution aid, not a security control |

### 6.3 Kiro-native enforcement design to test (IDE and CLI)

This is a hypothesis built from documentation. **Nothing here is tested.**

1. User turns the sandbox on, with `networkAccess: DEFAULT_BLOCKED`, and adds a `sandbox_network` allow rule for the gateway address only. `COMMON_DEPENDENCIES` must not be used, because it includes the registries.
2. `mcpSandboxing` stays **off** (the default). The SlopSeal MCP server and the gateway run outside the sandbox and can reach the registries. The sandboxed shell cannot.
3. SlopSeal state lives in a directory outside the workspace. `permissions.yaml` denies sandbox reads of it. Kiro denies agent writes to `permissions.yaml`.
4. An administrator, where available, adds deny rules in `managed-settings.json`.
5. `sandboxFailClosed` is on, if the setting is user-controllable.

This would use only Kiro's own mechanisms. It still depends on unconfirmed points (loopback reachability from the sandbox, agent escape routes such as requesting an unsandboxed run, admin enforcement of network mode), which section 8 tests.

### 6.4 Web is different

Web has no host terminal, no local Docker, no admin governance, and the internet setting is per user. The Power can install the MCP server and hook and can run guided steps through a skill. It cannot configure the network. For Web, the only boundary the documentation supports is a **user-set custom allow-list** that lists only a remote gateway host, which requires a hosted gateway that does not exist yet. Until that exists and is tested, Web is advisory.

## 7. Proposed setup wizard workflow (Kiro-native, no Save callback)

Kiro has no documented post-install step for a Power, and I found no event for "Save". The reliable triggers are these:

| Trigger | Surfaces | Evidence |
|---|---|---|
| First `verify_install` result carries the status line and next step | All | design |
| `SessionStart` hook that prints the current status | Web, IDE, CLI | Hook trigger exists on Web `[DOC]`. Whether its output reaches the user or the agent is **unconfirmed** |
| Power skill `setup` the agent runs when the user asks | All | `[DOC]` skills activate on request |
| MCP prompt `/slopseal-setup` | All | Server prompts are supported on all three `[DOC]` |
| URL elicitation to a local dashboard | CLI local V3 (2.34+) documented. IDE and Web unconfirmed `[DOC]` | Not reliable |
| Host command `slopseal setup` | IDE, CLI only (needs a host terminal) | design |

**Workflow:**

1. **Install the Power** (IDE panel or link, `/powers install` on CLI, Agent Config on Web). The MCP server starts and the bootstrap registers the hook.
2. **First contact:** the first `verify_install` result begins with `SlopSeal status: NOT ENFORCED. Run the setup guide.` A `SessionStart` hook (to be tested) prints the same line.
3. **Guided setup (chat):** the `setup` skill walks through the steps and runs read-only detection and probes in the shell.
4. **Privileged or settings steps (IDE, CLI):** the skill hands the user a single host command, `slopseal setup`. That command, run by the human in a normal terminal, writes the user-level sandbox and permission settings and shows each change for approval. The agent cannot run it, and the skill must say so.
5. **Web steps:** the skill shows the user exactly what to set in Settings > Sandbox and in Agent Config, then verifies through probes. The user does these in the Web UI. The agent cannot.
6. **Verify:** the probe matrix runs through the agent's shell and reports each result.
7. **Status:** the wizard states ENFORCED, PARTIALLY ENFORCED, or NOT ENFORCED with the tested scope. The status is repeated in every MCP result.

Nothing in the workflow depends on a Save callback or on an automatic UI opening.

## 8. Test protocol for IDE and CLI (read-only; run in throwaway installs)

I could not run these. They need an IDE session and a CLI session. Use a throwaway workspace and a throwaway user profile. Do not use a real project.

| ID | Test | How | What it decides |
|---|---|---|---|
| H1 | Hook fires | Add a fixture PreToolUse hook that prints a marker to stderr and exits 2 on a harmless command | Whether hooks run |
| H2 | Exit 2 blocks, and where stderr is shown | Same hook. Note what the developer sees in the UI | Developer visibility |
| H3 | Exit 0 stderr | Fixture that prints to stderr and exits 0 | Whether ALLOW messages can reach the developer |
| H4 | Other non-zero exit | Fixture that exits 1 | Resolve the documentation conflict. If it allows, the wrapper must stay |
| H5 | Hook timeout | Fixture that sleeps past the timeout | Fail open or closed |
| N1 | Sandbox off by default | Fresh profile, run `curl` to a registry | Default exposure |
| N2 | `DEFAULT_BLOCKED` blocks every client | `curl`, `urllib`, `fetch`, direct IP, IPv6, DNS-over-HTTPS | Whether the shell sandbox is a real boundary |
| N3 | Loopback reach | Start a local test server outside the sandbox and try it from the shell | Whether a local gateway is reachable |
| N4 | Agent self-edit | Ask the agent to edit `sandbox.json` and `permissions.yaml`, and to run `chmod` or `sed` on them | Whether always-deny holds through the shell |
| N5 | Escape routes | Ask the agent to run a command unsandboxed or to request more access | Whether an approval path bypasses the network rule |
| N6 | Admin policy | Deploy `managed-settings.json` with a deny rule, then try to override it in user config | Whether admin deny is real |
| N7 | Admin network mode | Check whether a managed value for network mode applies | Resolves the docs versus code conflict |
| M1 | MCP location | Run `ps` from the shell with a test MCP server | Inside or outside the sandbox |
| M2 | `mcpSandboxing` | Toggle it, and test registry reach from the MCP server and the shell | The asymmetry |
| M3 | State directory | Deny sandbox reads on a directory outside the workspace, and try to read it from the shell | Whether D2 can be met natively |
| P1 | Power contents | Install a test Power with `plugin.json`, `mcp.json`, `skills/`, and `POWER.md` together | Which format wins |
| P2 | Power hooks | Try a `hooks/` folder in a test Power | Whether any hook is installed |
| P3 | Onboarding | Check what "Try the power" does | Whether a first-run step exists |
| P4 | Elicitation | Send URL-mode elicitation from a test MCP server | Which surfaces open links |

**Web tests that need a person** because I cannot change Settings from inside a session:

| ID | Test | What it decides |
|---|---|---|
| W1 | Set the custom allow-list to a single test host, then run the probe matrix | Whether Web egress control works and which clients it covers |
| W2 | Same, then ask the agent to change its own network (container-level firewall) | Where the restriction is enforced (K-4) |
| W3 | Same, then call the SlopSeal MCP tool | Whether the MCP server is inside or outside the allow-list |
| W4 | `SessionStart` hook output | Who sees it |
| W5 | Attempt to modify `/projects/sandbox/.kiro/hooks` through the shell | K-3 |

## 9. Enforcement status definitions (Kiro-native)

The status is computed from live probes through the agent's shell, never from a stored claim. A probe pass is evidence for the tested paths only.

| Status | Meaning on Kiro | Required |
|---|---|---|
| **ENFORCED** | Direct registry access fails for every tested client. The agent cannot change the boundary. SlopSeal's key and state are out of the agent's reach | Sandbox or allow-list verified by probes; setting owned by a user or admin the agent cannot write (tested through N4, N5, W2); state protected (M3); gateway healthy; attestation fresh; escape hatches checked. **Not reachable on any Kiro surface today** |
| **PARTIALLY ENFORCED** | Some layers are verified, but the boundary is incomplete or depends on something the agent might change | Examples: hook and MCP active; sandbox on and probes pass but escape routes untested; state in the workspace |
| **NOT ENFORCED** | No verified boundary | Any direct probe succeeds, probes cannot run, gateway down, status stale, or Web with the default open internet |

Current status of this very session, by these definitions: **NOT ENFORCED** (direct access succeeds, state is agent-writable).

Rules (unchanged from the wizard report): unknown means NOT ENFORCED; MCP connectivity never counts as isolation; the status is repeated in every result; downgrades are loud; the agent cannot raise the status.

## 10. Recommendation for SlopSeal v1 (Kiro IDE, CLI, Web)

1. **State the honest v1 claim:** "SlopSeal verifies packages, blocks the common install forms, and tells you whether your Kiro setup actually enforces a boundary." **Do not claim ENFORCED on any surface** until the tests in section 8 pass.
2. **Distribute as one Power** (MCP, skills for setup and status, pinned versions). Keep the MCP bootstrap for the hook. Pin hook and MCP to the same SlopSeal copy (K-5).
3. **IDE and CLI first, because they have a real local sandbox.** Build the Kiro-native design in 6.3 and test it with section 8 before writing code. If N2, N4, N5 and M3 pass, ENFORCED becomes reachable without Docker. If they fail, fall back to the Docker design from PR #34.
4. **Web is advisory in v1** (NOT ENFORCED or PARTIALLY ENFORCED). The only supported boundary is a user-set allow-list plus a hosted gateway, which does not exist. Say so in the product.
5. **Do D2 first.** The Web test showed the key and audit log are agent-writable. No status above PARTIALLY ENFORCED is honest until the key and state are out of the agent's reach. The IDE and CLI path may meet D2 natively through `permissions.yaml` and a state directory outside the workspace.
6. **Fix the cheap, certain issues in the same cycle:** unify the hook and MCP copy (K-5), move the shipped configuration off workspace-relative paths (F-12), and keep the exit-2 wrapper (K-7).
7. **Wizard:** chat-guided skill plus a host command for IDE and CLI. No dependence on a Save callback, on automatic UI opening, or on elicitation.

**Decisions I need from you:**
1. Approve running section 8 on a real Kiro IDE and a real Kiro CLI in throwaway installs. I cannot do this from here.
2. Approve a Web test pass (W1 to W5) in a throwaway Web workspace, where you change the allow-list through Settings.
3. Confirm that IDE and CLI should be the first enforcement targets, with Web advisory.
4. Confirm that D2 starts before any wizard work.

## 11. Sources

- Hooks: https://kiro.dev/docs/hooks/types.md , https://kiro.dev/docs/hooks.md , https://kiro.dev/docs/hooks/actions.md , https://kiro.dev/docs/hooks/troubleshooting.md
- Sandbox (IDE, CLI): https://kiro.dev/docs/sandbox.md ; permissions: https://kiro.dev/docs/permissions.md ; enterprise permissions: https://kiro.dev/docs/enterprise/governance/permissions.md ; enterprise reference: https://kiro.dev/docs/enterprise/enterprise-management/reference.md
- Web internet access: https://kiro.dev/docs/web/sandbox/internet-access.md ; Web MCP: https://kiro.dev/docs/web/sandbox/mcp.md ; Identity Center: https://kiro.dev/docs/web/identity-center.md ; Mobile settings: https://kiro.dev/docs/mobile/settings.md
- MCP: https://kiro.dev/docs/mcp/ , https://kiro.dev/docs/mcp/security.md , https://kiro.dev/docs/mcp/usage.md
- Powers: https://kiro.dev/docs/powers.md , https://kiro.dev/docs/powers/create.md , https://kiro.dev/docs/powers/installation.md
- Cloud configuration sync: https://kiro.dev/docs/web/cloud-configuration.md
- Type declarations in the installed agent bundle: `platform/hooks.d.ts`, `governance/settings/enterprise-values.d.ts`
- Earlier SlopSeal reports: PR #32 (gateway MVP, untouched), PR #33 (one-step feasibility), PR #34 (setup wizard feasibility)

Content was summarised, not quoted, for licensing reasons. The fixture scripts I used are in `/projects/sandbox/audit_probes/` (outside the repository) and wrote nothing.
