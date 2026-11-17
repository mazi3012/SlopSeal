# D2: Security-State Ownership Architecture (design, not implemented)

- Date: 2026-11-17
- Status: **design and threat model only.** No code, configuration, firewall, network, sandbox, or Kiro setting was changed. D2 is not implemented. D3 and the setup wizard are not started. PRs #32, #33 and #34 are untouched.
- Scope: Kiro IDE, Kiro CLI (first enforcement targets) and Kiro Web (advisory in v1).
- Closes or prepares: F-16 (agent reads and resets SlopSeal state), F-03 and F-04 (audit integrity), F-11 (policy pin), F-02 Part B (approval trust).

Evidence labels: **[tested]** measured by a probe in this Kiro Web session or in a throwaway test on this machine; **[code]** read from the repository; **[doc]** official documentation; **[design]** proposal, untested.

## 1. The problem, confirmed

| # | Fact | Evidence |
|---|---|---|
| P1 | The agent shell reads SlopSeal's `secret.key`, `audit.jsonl`, and `ratelimit.json` and can write them | [tested] Kiro Web: permission checks on `/projects/sandbox/.slopseal/` show readable and writable (contents not read) |
| P2 | The agent shell runs as root with the full capability set in Kiro Web, including `CAP_NET_ADMIN` | [tested] `CapEff=000001ffffffffff` |
| P3 | The MCP server runs as the same user and shares the filesystem | [tested] it wrote `.slopseal` at 13:14 as uid 0, matching its two verdicts |
| P4 | **A deleted key is silently replaced.** `load_or_create_key` creates a new key when the file is missing, and `build_context` calls it on every verdict. A verdict then returns ALLOW, and the existing log fails verification only when someone runs `verify` | [code] `audit/seal.py` lines 31–45, `runtime.py` line 81. [tested] throwaway probe: after deleting the key, the next verdict was ALLOW, and `verify` then failed at seq 1 "seal does not verify" |
| P5 | Deleting `ratelimit.json` resets the install rate limit | [code] `quarantine/rate_limit.py`: a missing state file means no attempts. [tested] earlier audit probe: `limit 1: True False`, then `True` after deletion |
| P6 | The audit chain has no external anchor, so the newest lines can be removed | audit finding F-04, reproduced |

P4 is a design flaw that exists even before the agent is malicious: losing the key, or a disk fault, silently turns a verifiable log into an unverifiable one while SlopSeal keeps answering. D2 must make missing security state a stop, never a reset.

## 2. Why moving the files is not enough

Moving `.slopseal` to another directory while the agent keeps the same privileges changes nothing. The agent can read any path it can reach, and a path can always be found. Each protection must come from one of these:

1. **A different OS identity** that the agent process cannot become (no `sudo`, no matching credentials, no capability to change its own uid). This works only if the agent is not root.
2. **A different kernel or machine boundary**, such as a separate container with no shared mount, a separate VM, or a host the agent cannot log into.
3. **An external service** that holds the secrets and answers only authenticated questions. The agent never receives the key, the state, or a way to compute keyed values.

Root in the agent's environment defeats option 1 completely: root can read any file, change ownership, ptrace processes it owns, and read another user's memory on the same host. So on Kiro Web, where the agent is root, **no file-based or same-kernel design can protect a secret.** D2 therefore depends on option 2 or 3 for any claim above PARTIALLY ENFORCED.

## 3. Architecture

### 3.1 Components and trust zones

```
 ZONE A: agent environment (untrusted; agent shell, agent process, MCP client)
 +----------------------------------------------------------------------------+
 |  AI agent + shell (root on Web; developer user on IDE/CLI, to be tested)   |
 |   |                                                                        |
 |   +-- slopseal-mcp (MCP server)  --holds NO secret, only a session token--+ |
 +------|---------------------------------------------------------------------+
        | request channel: unix socket (IDE/CLI) or mTLS over the network (remote)
        | -> carries: verify request, status read.  Never: key, state, approval
        v
 ZONE B: SlopSeal service (trusted; separate identity or separate host)
 +----------------------------------------------------------------------------+
 |  slopseal-svc (gateway logic + verifier + audit writer + rate limiter)      |
 |   - seal key            (only here)                                          |
 |   - policy pin          (only here; hash checked on each request)           |
 |   - audit log           (append-only, sealed, anchored, see section 6)      |
 |   - rate-limit state    (only here; keyed by session, see section 5)        |
 |   - quarantine store    (only here)                                          |
 |   - approval verifier   (checks human signatures; see section 4.4)          |
 +------|---------------------------------------------------------------------+
        | outbound, allow-listed upstream hosts only
        v
 ZONE C: package registries (PyPI, npm, OSV, artifact hosts)

 ZONE H: human approver (separate device or terminal). Holds the approval private key.
```

### 3.2 Where the service runs, by surface

| Surface | Agent identity | Service placement | Achievable protection | Status |
|---|---|---|---|---|
| **Kiro IDE/CLI, developer machine** (agent is the developer's user) | Non-root user, to be confirmed by test | Separate OS user `slopseal-svc`, unix socket, key in a directory owned by that user with mode 0700 | Protects key and state from the agent *if* the agent cannot become that user or read its files. Weaker than option 2 against an agent that can run privileged commands | Design; test T-IDE-1 to T-IDE-4 |
| **Kiro IDE/CLI, agent in a container** | Root in the container | Service in a second container with no shared mount, reached over a socket the agent can use but cannot read the secrets through | Strong against a root agent. The socket is an attack surface and must authenticate callers | Design |
| **Kiro Web** (agent is root in a platform container) | Root | Remote service only (option 3). Nothing secret is local | Only option 3 works. No Web-local design can protect secrets | **Advisory in v1** (decision 2) |
| **Remote SaaS** | n/a | Hosted service | Strongest isolation, but a hosted service receives package names, which conflicts with the "does not phone home" position in the threat model | Not recommended for v1 |

### 3.3 Trust boundaries

1. **A → B.** The only trusted path. Authenticated per request. Carries no secret material in either direction.
2. **B → C.** Outbound fetch limited to an allow-list in service code, plus egress rules on the service's host (D1 applies to the agent, not to the service).
3. **H → B.** Approvals only. Signed by a key that never exists in A or B (section 4.4).
4. **Platform → A.** Kiro's own protection of its configuration files (read-only mounts, always-deny rules) is a platform boundary SlopSeal can rely on only as far as tested.

## 4. Key and state storage design

### 4.1 What is secret, and what must be readable by whom

| Item | Secret? | Owner | Agent may read? | Agent may write? |
|---|---|---|---|---|
| Seal key (HMAC, 32 bytes) | Yes | service only | No | No |
| Approval public key | No | service (copy) | Yes (harmless) | No |
| Approval private key | Yes | human (device) | No | No |
| Policy file and its pin (hash) | Integrity-critical, not secret | service | Read the pin only, through the API | No |
| Audit log | Integrity-critical | service | Read through the API (verdict history), not the file | No |
| Rate-limit state | Integrity-critical | service | No | No |
| Quarantine store and artifacts | Integrity-critical | service | Read through the API | No |
| Session tokens | Yes (bearer) | service issues, agent holds | Yes, its own token only | No |
| Snapshot and manifest | Integrity-critical | repository (for reproducibility) | Yes | Repository change only |

### 4.2 Key handling rules

- **Generated only by the service, at first start, inside the service's identity.** Never by the verdict path.
- **Never regenerated automatically.** If the key file is missing and any audit state exists, the service **refuses to issue verdicts** and reports `SEAL_KEY_MISSING` (fail closed). Recovery is an explicit, logged operator action that archives the old log and starts a new chain with a recorded marker.
- **Never in an MCP response, an environment variable, a log line, or a command-line argument.** The service reads it from its own file (or a secret store) at start.
- **Rotation** writes a new key id; old seals carry the key id so verification can use the matching key. Rotation is an operator action and is logged.
- **Storage on the IDE/CLI path:** a directory owned by the service identity, mode 0700, file mode 0600, not inside any workspace, and not readable by the agent identity (test T-IDE-2).

### 4.3 State ownership

- All security state moves into the service. The MCP server becomes a client with no local state. This removes `.slopseal` from the workspace entirely.
- **Rate-limit state** lives in the service and is keyed by the **service-issued session token**, not by process or directory. Restarting the agent, deleting files on the agent side, or using a second MCP process does not reset the count.
- **Quarantine store** is service-owned. The hook and the MCP tool query the service for status instead of reading a file.

### 4.4 Approval trust (F-02 Part B)

- An approval is a signed statement `{quarantine_id, package, version, decision, reason, timestamp, approver}`, signed by the approval private key on a human device.
- The service verifies the signature against the approval public key and accepts an approval only for an existing quarantine.
- The agent cannot sign, cannot read the private key, and cannot submit an approval through the MCP tool. The MCP tool has no approval operation.
- Signature algorithm: Ed25519 is the right choice. The repository's stdlib-only rule (ADR 0002) means adding a crypto library needs its own ADR. Until then, approvals are unavailable and quarantines stay open. This is the fail-closed choice.

## 5. Audit integrity design

### 5.1 Requirements

1. An agent with root on the agent side cannot change, delete, reorder, or truncate a recorded verdict without detection.
2. A verifier can check the whole history from the service's sealed records alone.
3. Loss of the newest records is detectable.
4. A failed write never produces an ALLOW (the existing rule, kept).

### 5.2 Design

- **Records** are written only by the service. Each record carries `seq`, `prev_hash`, all content fields, `key_id`, and an HMAC over the **full canonical record** (fixes F-03). `line_hash` is replaced by the HMAC so a rewrite needs the key.
- **Head anchoring (fixes F-04).** After each append the service publishes `{seq, head_hash, key_id, ts}` to an **external append-only sink** the agent cannot write. Options, in order of strength: (a) a separate host or container that stores heads and accepts only appends; (b) a transparency log service; (c) a local file owned by the service identity (weakest; detects only accidental loss). The sink's identity must be separate from the service.
- **Agent-side reads** go through the API. The agent sees verdicts, not the file.
- **Verifier** is a service command plus an offline tool that takes the log, the head records, and the key (held by the operator). It reports the first failing `seq`.

### 5.3 What this does and does not prove

- Proves: no rewrite of a record that was anchored, and no removal of anchored records, unless the attacker also controls the anchor sink or the service key.
- Does not prove: that every real install was verified. A bypass that never reaches the service leaves no record. That is what D1 and the gateway address (egress control), not the audit log, must cover.
- Symmetric HMAC means anyone who can verify can also forge. Verification must happen only with keys held by the operator or the service. Public verifiability needs asymmetric signatures and remains an ADR item.

## 6. Protecting the rate limit

- Counters live in the service; the agent gets only verdicts.
- Credit (`hook_allows`) entries are service-side as well.
- A missing or unreadable counter store **blocks** (existing rule, kept), and the service never recreates an empty store while a log exists (the same rule as the key).
- The limit must count requests per session token and per package key, so a new process cannot reset it (R-4.7, R-G-11 carry over unchanged).

## 7. Agent/service permission model

| Principal | Holds | Can do | Cannot do |
|---|---|---|---|
| **Human operator** | Ops access to the service host (and the sink) | Start, stop, rotate keys (logged), archive logs, verify the chain | Approve packages through the agent path |
| **Human approver** | Approval private key on a personal device | Sign approvals | Anything on the service host |
| **Service identity** (`slopseal-svc`) | Seal key, policy pin, audit writer, state, upstream allow-list | Verify, count, record, serve artifacts (gateway) | Accept requests not carrying a valid session token; approve without a signature |
| **Agent identity** (developer user, or root in a container) | Its session token; the MCP client; a socket it can connect to | Request verdicts; read its own verdict history; request an artifact through the gateway | Read secret or state files; reach the registries directly (D1); change the pin; approve |
| **MCP server** | The session token (stored as the agent identity's file, mode 0600) | Forward requests, show status | Hold a key; decide anything locally; return keys or state |
| **Gateway (served from the service)** | Upstream allow-list, digest cache | Serve bytes for ALLOW only | Serve without a verdict; reach hosts outside the allow-list (SSRF guard) |
| **Kiro platform** | Its own files and sandbox | Enforces its own configuration protection (tested read-only for Web) | Not part of SlopSeal's trust base; treated as a platform boundary to be tested |

Token rules: issued by the service after a local, human-triggered setup step; scoped to verification and read-own-history; revocable from the service; short-lived with renewal; never logged.

## 8. Fail-closed behaviour

| Situation | Behaviour |
|---|---|
| Service unreachable | MCP returns "NO VERDICT, do not install"; hook refuses installs; gateway serves nothing |
| Key missing with existing audit state | Refuse all verdicts; report `SEAL_KEY_MISSING` |
| Head anchor mismatch | Refuse verdicts; report `AUDIT_ANCHOR_MISMATCH` |
| Counter store unreadable or missing with history | Block (existing rule, kept) |
| Token invalid or revoked | Deny with no verdict |
| Approval signature invalid | Reject the approval; quarantine stays open |
| Policy hash differs from the pin | Refuse verdicts; report `POLICY_PIN_MISMATCH` |

## 9. Migration strategy

Goal: no period in which a verdict is issued without audit state, and no period in which the old local state is trusted after the new one exists.

| Step | Work | Exit check |
|---|---|---|
| M0 | Inventory current state (done here: key, log, counters, quarantine, policy). Freeze the current code | Inventory accepted |
| M1 | Service skeleton with no behaviour change: serves verdicts on a socket, reads the old state read-only | Same decisions as today on the decision-equivalence corpus |
| M2 | New key and log in the service. Old local log is archived read-only, marked **legacy, unanchored**, and never extended | Old log still verifies with its old key; new log verifies with the new key |
| M3 | MCP and hook become clients. Local state writes stop. Fail-closed on service loss | Probe: killing the service blocks every install path |
| M4 | Head anchor sink in place | Truncation test passes (F-04) |
| M5 | Delete local state from the workspace after archive | Agent-side read of the old paths fails |
| M6 | Retire the local-state code path | Test suite green, property tests green |

Compatibility: the verifier accepts both legacy (`unanchored`) and new (`anchored`) logs and labels them. A legacy log never reports "anchored".

## 10. Testing and acceptance criteria

### 10.1 Acceptance criteria (D2 is done only when all pass)

| ID | Criterion | Test |
|---|---|---|
| AC-1 | Agent identity cannot read the key | Attempt read from the agent shell: must fail (T-IDE-2, T-WEB-1) |
| AC-2 | Agent identity cannot change audit records | Attempt write or truncate: must fail; if it succeeds, the anchored verifier must detect it |
| AC-3 | Counters cannot be reset from the agent side | Delete attempt, restart MCP, restart agent: counter preserved |
| AC-4 | Missing key blocks | Remove key with audit state present: next verdict refused, no new key created |
| AC-5 | Service down blocks every install path | Stop service: hook, MCP, gateway all refuse |
| AC-6 | No secret in MCP responses or env | Scan all MCP responses and the MCP process environment for key bytes and state paths |
| AC-7 | Token replay and revocation | Revoked token refused; replayed approval refused |
| AC-8 | Anchor detects truncation | Truncate the log: verifier reports mismatch |
| AC-9 | Decision equivalence after migration | Same corpus as the UX work: identical outcomes |
| AC-10 | Legacy logs labelled | Legacy log reports `unanchored` |
| AC-11 | Property and integration suites green | Full suite, with Hypothesis installed |

### 10.2 Test environments

- Kiro IDE and CLI: throwaway user profiles, per the protocol in `reports/SlopSeal_KIRO_IDE_CLI_TEST_PROTOCOL.md`.
- Kiro Web: advisory. Only the remote-service variant can satisfy AC-1 to AC-3 there. Tested in a throwaway workspace with administrator access (decision 3).
- Container tests: a Linux host with Docker (not available in this sandbox).

## 11. Open questions

1. Is the agent process a non-root user on the developer's machine for IDE and CLI? (T-IDE-1)
2. Can a non-root agent process read another user's files through the Kiro sandbox? (T-IDE-3)
3. Can the Kiro sandbox reach a unix socket owned by another user? (T-IDE-4)
4. Which external anchor sink is acceptable for the product (self-hosted, or a managed transparency log)?
5. How are approval devices enrolled, and how is the public key distributed?

## 12. Updated SlopSeal security roadmap

| Phase | Goal | Depends on | Exit |
|---|---|---|---|
| **D2-a** | This architecture approved; IDE/CLI test protocol executed | Your review; throwaway installs | Results recorded in the protocol report |
| **D2-b** | Service skeleton (M1) and key/state move (M2) | D2-a | AC-9 green; AC-1 to AC-4 green on IDE/CLI |
| **D2-c** | Clients switched; fail-closed (M3); anchor sink (M4) | D2-b | AC-5, AC-6, AC-8 green |
| **D2-d** | Local state removed; legacy labelling (M5, M6) | D2-c | AC-10, AC-11 green |
| **D3** | Approval channel (Ed25519 needs an ADR) | D2-b and an ADR | AC-7 green; F-02 Part B closed |
| **W** (Web, advisory) | Remote service mode and the Web allow-list test | D2-b; decision 3 testing | Status shown as advisory |
| **Setup wizard** | Kiro-native guided setup and status | D2-d, D3 | Only after D2 and D3 are done |

Enforcement claim: ENFORCED is not claimed on any surface before D2-c, and only for IDE and CLI, and only when the probes in the test protocol pass.

## 13. Decisions needed before implementation

1. Approve the separate-identity design for IDE/CLI, pending the tests in section 11.
2. Approve the remote-service design for Web (advisory) and state that it needs hosting.
3. Choose the anchor sink (section 11.4).
4. Accept fail-closed on missing key (AC-4), which will break any setup where the key is deleted.
5. Accept that approvals wait for an ADR on an asymmetric signature library (section 4.4).
