# D2: Security-State Ownership Architecture (revision 2, design, not implemented)

- Status: **design and threat model only.** No code, configuration, firewall, network, sandbox, or Kiro setting was changed. D2 is not implemented. D3 and the setup wizard are not started. PR #35 stays Draft. PRs #32, #33 and #34 are untouched.
- Scope: Kiro IDE and Kiro CLI (first enforcement targets). Kiro Web is advisory in v1 and uses a remote service.
- Revision 2 answers the four review points. Sections marked **[rev2]** are new or changed. The IDE/CLI test protocol is unchanged.

Evidence labels: **[tested]** measured by a probe in this Kiro Web session or in a throwaway test on this machine; **[code]** read from the repository; **[doc]** official documentation; **[design]** proposal, untested.

## 1. The problem, confirmed

| # | Fact | Evidence |
|---|---|---|
| P1 | The agent shell reads SlopSeal's `secret.key`, `audit.jsonl`, and `ratelimit.json` and can write them | [tested] Kiro Web: permission checks on `/projects/sandbox/.slopseal/` show readable and writable (contents not read) |
| P2 | The agent shell runs as root with the full capability set in Kiro Web, including `CAP_NET_ADMIN` | [tested] `CapEff=000001ffffffffff` |
| P3 | The MCP server runs as the same user and shares the filesystem | [tested] it wrote `.slopseal` at 13:14 as uid 0, matching its two verdicts |
| P4 | **A deleted key is silently replaced.** `load_or_create_key` creates a new key when the file is missing, and `build_context` calls it on every verdict. The verdict returns ALLOW; the existing log fails only when someone runs `verify` | [code] `audit/seal.py` lines 31–45, `runtime.py` line 81. [tested] throwaway probe: after deleting the key, the next verdict was ALLOW, and `verify` then failed at seq 1 |
| P5 | Deleting `ratelimit.json` resets the install rate limit | [code] `quarantine/rate_limit.py`. [tested] earlier probe: `limit 1: True False`, then `True` after deletion |
| P6 | The audit chain has no external anchor, so the newest lines can be removed | audit finding F-04, reproduced |

P4 is a design flaw even without a malicious agent. Losing the key, or a disk fault, silently turns a verifiable log into an unverifiable one while SlopSeal keeps answering.

## 2. Why moving the files is not enough

Moving state to another directory while the agent keeps the same privileges changes nothing. Protection must come from one of these:

1. **A different OS identity** that the agent process cannot become. This works only when the agent process has no route to that identity (section 7.1).
2. **A different machine or container boundary** the agent cannot enter.
3. **An external service** that holds the secrets and answers only authenticated questions. The agent never receives a key, state, or a way to compute keyed values.

Root in the agent's environment defeats option 1 completely. On Kiro Web the agent is root, so only option 3 can protect a secret there.

## 3. Architecture

### 3.1 Components and trust zones

```
 ZONE A: agent environment (untrusted)
 +----------------------------------------------------------------------------+
 |  AI agent + shell (root on Web; agent identity on IDE/CLI)                  |
 |   +-- slopseal-mcp (MCP client): holds ONE session token. No key, no state. |
 +------|---------------------------------------------------------------------+
        | Channel 1: verdict API (unix socket with SO_PEERCRED, or TLS on Web)
        | carries: verify request, own-history read, status. Never: key, state,
        | approval, policy change, rate-limit change, anchor access
        v
 ZONE B: SlopSeal service (trusted; service identity or remote host)
 +----------------------------------------------------------------------------+
 |  slopseal-svc: verifier, rate limiter, quarantine store, audit writer,       |
 |                gateway (artifact server), approval verifier                  |
 |   - seal key            (only here; never leaves this zone)                  |
 |   - policy pin          (only here)                                          |
 |   - audit log           (written here; anchored, section 6)                  |
 |   - rate-limit state    (only here)                                          |
 |   - artifact grants     (issued here, verified by the gateway, section 7.2)  |
 +------|--------------------------------------------|-------------------------+
        | Channel 2: anchor (append, receipt)        | Channel 3: gateway-to-service
        v                                            v  (separate credential)
 ZONE S: anchor sink (append-only, separate identity)   ZONE C: registries (allow-listed)
 ZONE H: human approver device (Ed25519 private key; never on A or B)
```

Three channels, three credentials. A compromise of the agent's credential does not give access to the anchor or to the gateway's grant path.

### 3.2 Placement by surface

| Surface | Agent identity | Service placement | What it protects | Status |
|---|---|---|---|---|
| Kiro IDE/CLI, production (section 7.1) | Unprivileged agent account with no sudo and no Docker | Service identity `slopseal-svc`, nologin shell, own state directory | Key and state from the agent, provided the agent has no route to `slopseal-svc` | Design; test T-IDE-1 to T-IDE-5 |
| Kiro IDE/CLI on a developer account that has sudo | The developer account | Same service identity, but **the agent can escalate** | Nothing against the agent. Labelled **NOT ENFORCED** | Not a supported enforcement configuration |
| Kiro Web | Root in a platform container | Remote service only | Only option 3 | Advisory in v1 |

## 4. Key and state storage design

### 4.1 Secret and state inventory

| Item | Secret? | Owner | Agent may read? | Agent may write? |
|---|---|---|---|---|
| Seal key (HMAC) | Yes | service only | No | No |
| Installation record (section 5) | Integrity-critical | service | Its own summary through the API | No |
| Anchor receipts | Integrity-critical | sink | No | No |
| Approval public key | No | service | Yes | No |
| Approval private key | Yes | human device | No | No |
| Policy file and pin | Integrity-critical | service | Pin hash through the API | No |
| Audit log | Integrity-critical | service | Verdict history through the API | No |
| Rate-limit state | Integrity-critical | service | No | No |
| Quarantine store | Integrity-critical | service | Status through the API | No |
| Session token | Bearer | service issues, agent holds one | Its own token only | No |
| Gateway credential, grant key | Yes | gateway identity | No | No |

### 4.2 Key handling rules

- Generated only by the service, and only during an explicit bootstrap (section 5). Never by the verdict path.
- Never regenerated automatically. Rotation is an operator action that writes a new `key_id`, and old seals keep their `key_id`.
- Never in an MCP response, a log line, an environment variable, or a command-line argument.
- Stored in a directory owned by the service identity, mode 0700, file mode 0600, outside every workspace.

## 5. Bootstrap and the "new install or wiped install" question [rev2]

### 5.1 The problem

If the key and the audit log are both gone, the service sees an empty state directory. Two cases look identical from the directory alone:
- a genuinely new installation, and
- an existing installation whose key and log were deleted.

Accepting the second case as the first would let an attacker with write access to the state directory restart the chain with a fresh identity and no history.

### 5.2 Decision: the anchor is the memory, and bootstrap is explicit

- At first setup, the operator runs `slopseal-svc init`. This is the **only** operation that creates a key and an audit log. The verdict path, the MCP server, the hook, and the gateway cannot create them.
- `init` generates a random `installation_id`, creates the key, writes a genesis record, and **publishes an installation record to the anchor sink** before it returns: `{installation_id, key_id, created_at, genesis_head}`.
- Every later service start performs a **startup reconciliation**:

| Local state | Sink record for `installation_id` | Result |
|---|---|---|
| Present and consistent | Present, head matches | Start normally |
| Missing (key, log, or both) | **Present** | **Refuse to start.** Report `INSTALLATION_STATE_LOST`. Do not create anything. Operator recovery only (section 5.4) |
| Present | Missing | Refuse: `ANCHOR_RECORD_MISSING`. The sink was reset or is wrong |
| Missing | Missing, and no `init` ran | Refuse: `NOT_INITIALISED` |
| Missing | Missing, and `init` ran with approval | Start as a new installation |
| Anything | Sink unreachable | Refuse to start (fail closed). Bootstrap is impossible without the sink |

The `init` command requires the operator to confirm on the host and records the confirmation in the sink. A bootstrap cannot happen silently.

### 5.3 Residual risk

If an attacker controls the service host **and** the anchor sink, they can create a fresh installation that looks legitimate. That is outside the boundary: an attacker holding both is an operator. The design makes the attack visible in the sink history (a second `init` for the same operator identity), and the verifier reports the installation count.

### 5.4 Recovery (the only way past `INSTALLATION_STATE_LOST`)

1. Operator restores the key and log from backup, and runs `slopseal-svc verify`. The anchor head must match.
2. If the state is genuinely lost, the operator runs `slopseal-svc retire --installation <id>`, which marks the old installation as retired in the sink, archives nothing, and reports that the chain ended. A new `init` then creates a new installation with a new id. The old installation's history stays verifiable from the sink.

Recovery is never automatic and never triggered by the agent.

## 6. Audit anchoring and anchor failure [rev2]

### 6.1 Write ordering (applies to every verdict and every artifact)

1. Compute the verdict.
2. Build the audit record, seal it, and append it to the local log, uncommitted.
3. Send the record's head to the anchor sink. Wait for a **signed receipt** that names the same `seq`, `head_hash`, and `key_id`.
4. On a valid receipt, commit the record locally and return the result.
5. Only then return ALLOW, and only then issue an artifact grant (section 7.2).

No ALLOW leaves the service before step 4. The gateway serves no bytes before step 4.

The sink's receipt is signed with the sink's own key (Ed25519 in the target design, per D3). A receipt that fails signature verification is a failure, not a success.

### 6.2 Failure definitions and required behaviour

| Condition | Definition | Behaviour |
|---|---|---|
| **Unavailable** | No response, timeout, connection refused, or 5xx within the anchor timeout | **Degraded.** Return NO VERDICT for every request (including BLOCK), so the state is visible. Keep the record in a pending queue. Retry with bounded backoff. The degraded state is reported in the MCP status line |
| **Rejected** | 4xx, a sequence conflict, or an explicit refusal | **Halted.** Return NO VERDICT for every request. Do not retry automatically. Operator must investigate. Written to the local log as an event |
| **Inconsistent head** | The sink returns a head for a `seq` that differs from what the service holds, a `seq` that goes backwards, or a receipt for a different `installation_id` | **Halted, integrity alarm.** Return NO VERDICT. Never auto-repair. Operator runs `slopseal-svc verify` |
| **Invalid receipt** | Signature fails, or the receipt is missing fields | Treated as **Rejected** |
| **Recovered** | Sink available again after Degraded | Replay the pending queue in `seq` order. Each replayed record must receive its own receipt. Duplicates are rejected by `seq`. Then return to Normal |

### 6.3 The rules in one place

- The service **fails closed**: any anchoring failure means NO VERDICT for all requests until the state is Normal again.
- A pending record is never served, never counted as ALLOW, and never deleted.
- Pending records survive restart. On start, the service reconciles pending records against the sink before it accepts requests (section 5.2).
- A failed anchor never downgrades to a local-only log. There is no "anchor optional" mode in production.

### 6.4 Limits

- An attacker who controls the sink can present a consistent but false history. The sink is therefore a separate identity with append-only storage and its own receipt key, and its operator is separate from the service operator where possible.
- Anchoring proves that a record existed when the sink accepted it. It does not prove that every real install passed through the service. Bypasses (D1) are closed by network controls, not by the log.

## 7. Host privilege, separation, and the production installation model [rev2]

### 7.1 Why the separate identity alone is not enough

On a developer machine, the developer account usually has `sudo`. The agent runs as that account (to be confirmed by T-IDE-1). If the agent can run `sudo`, it can become `slopseal-svc`, or root, and read the key directly. **A separate service identity protects nothing against an agent that can escalate.** Each of the following is an escalation route the production model must close:

| Route | Why it matters | Required control |
|---|---|---|
| `sudo` (any rule, including `NOPASSWD` and cached timestamp) | Direct switch to the service identity or root | The agent identity has no sudo rules. Verified by the installer |
| `su` with a known password, or a `pkexec`/polkit rule | Same | The agent identity has no password path and no polkit rule. Installer checks `sudo -l` and polkit rules |
| Docker group or the Docker socket | Root equivalent: start a container with the host filesystem | Agent identity not in `docker`. Socket not mounted into the agent. Installer checks group membership and socket reachability |
| Writable service executables or config | Code injection into the service | Service files owned by root, not writable by the agent or the service identity |
| `ptrace` of a service process | Reading key memory | Yama `ptrace_scope` at least 1, and no `CAP_SYS_PTRACE` for the agent. Installer checks |
| Shared group membership | Read access by group | Separate primary groups. Service directory 0700 |
| Writable anchor or receipt paths from the agent | Forging the audit history | Anchor is a separate host or container. If local, its directory is owned by the sink identity |
| Kiro's own sandbox escape routes (for example an unsandboxed retry) | Commands run outside the sandbox with the developer's rights | Managed policy disables them where Kiro allows (tested in protocol N5, N6) |

### 7.2 Production installation model (separate from the test account)

| Element | Production | Throwaway test (protocol) |
|---|---|---|
| Agent account | A dedicated OS account that runs Kiro, with no sudo, no docker group, no password, no polkit. Created by an administrator | `kiro-test-ide`, not root, not in `sudo` or `docker`. Used to learn behaviour |
| Developer account | Separate. Does not run the agent. Used for the human approval and the `init` step | The tester's own account |
| Service account | `slopseal-svc`, system account, nologin shell, no login, owns `/var/lib/slopseal` (0700) | Created for the test, deleted afterwards |
| Anchor sink | Separate host or container, own account, append-only storage | Local directory owned by a second test account, labelled as a simulation |
| Installer | Refuses to report ENFORCED if any escalation route in 7.1 is open. Prints each finding | Runs the same checks, reports them, and changes nothing |
| Administrator | Required to create the agent account, set sudo and docker rules, and install the service | Tester performs the same steps on the throwaway VM |

The throwaway test proves the separation primitives (file access, socket authentication, process isolation). It does **not** prove production enforcement, because the test account is not the production configuration. The protocol's results must say which parts were run against which model.

Kiro Web does not have a developer account and cannot use section 7.2 at all. It uses the remote model (section 3.2).

### 7.3 Installer preflight

Before the service reports ENFORCED, the installer must confirm, and record each result:
1. The agent account has no sudo rule (`sudo -l -U <agent>` shows nothing).
2. The agent account is not in `docker`, and the Docker socket is not reachable from it.
3. The agent account cannot read or write `/var/lib/slopseal` or the service executables.
4. Yama `ptrace_scope` is at least 1.
5. The anchor sink is reachable only through the service's credential.
6. The agent cannot reach the service through any route other than the verdict socket.

Any failed check means the status is NOT ENFORCED (or PARTIALLY ENFORCED if the verdict path works and no escalation route is reachable). The installer never escalates privileges to fix a failed check. It prints the change a human must make.

## 8. Session tokens, gateway credentials, and channel security [rev2]

### 8.1 Credentials

| Credential | Holder | Purpose | Scope |
|---|---|---|---|
| **Session token** | Agent (file, mode 0600, owned by the agent account) | Verdict API | Verify, read own verdict history, read status. Nothing else |
| **Gateway credential** | Gateway process only (service identity) | Gateway to verifier channel | Request artifact grant verification and serve bytes |
| **Grant** | Issued per ALLOW, handed to the agent in the verdict response | Artifact download | One artifact, one verdict id, short-lived, single use |
| **Anchor credential** | Service only | Append to the sink | Append only, no read of other installations |
| **Approval signature** | Human device | Approval | One quarantine, one decision |

No credential in this table can be converted into another. The session token is refused by the gateway and by the anchor channel.

### 8.2 Session token specification

| Property | Specification |
|---|---|
| Generation | 256 bits from the service CSPRNG, base64url, prefixed with a version tag |
| Storage at the service | Only a keyed hash (HMAC with a service key), never the token itself |
| Permissions | Allow-list per credential class (section 8.3). Enforced in the service API, not by the client |
| Lifetime | Idle expiry 30 minutes; absolute expiry 8 hours. Renewal requires an operator action on the host (or a fresh setup for Web), not an agent action |
| Rotation | On renewal the service issues a new token and invalidates the old one at once |
| Revocation | Operator command, and automatic on: pin mismatch, key rotation, Halted anchor state, more than 20 authentication failures in 10 minutes |
| Binding (IDE/CLI) | Unix socket with `SO_PEERCRED`. The request must come from the agent account's uid, in addition to the token |
| Binding (Web) | TLS with server authentication. Web token is bound to the session only and is advisory in v1 |
| Replay | Each request carries a random request id and a timestamp. The service keeps the request ids seen in the last 10 minutes. A repeated id returns the cached verdict and **does not** count against the rate limit again |
| Logging | Tokens never appear in logs, verdicts, MCP responses, or error text. Only the token id (a prefix of the keyed hash) is logged |

### 8.3 Operation allow-lists

| Operation | Session token | Gateway credential | Anchor credential | Operator (host) | Approver (device) |
|---|---|---|---|---|---|
| `verify` | Yes (counted) | No | No | Yes | No |
| Read own verdict history | Yes (own records only) | No | No | Yes | No |
| Read status line | Yes | No | No | Yes | No |
| Serve artifact | No | Yes, with a grant | No | No | No |
| Verify grant | No | Yes | No | No | No |
| Append to the sink | No | No | Yes | No | No |
| Read the seal key | **No** | **No** | **No** | No (only through `init`/`rotate`, logged) | No |
| Modify audit | **No** | **No** | No (append only) | No (only `verify` and archive, logged) | No |
| Reset or modify rate limit | **No** | No | No | No | No |
| Approve or escalate quarantine | **No** | No | No | No | **Yes, signed** |
| Change policy or pin | **No** | No | No | Yes, logged, with a pin update | No |
| Issue or renew tokens | **No** | No | No | Yes | No |

Each forbidden call returns a denial and writes a `DENIED_OPERATION` event. The MCP tool has no operation for any bold entry, so the agent cannot ask for it.

### 8.4 Grants (gateway and artifact)

- A grant is `{verdict_id, ecosystem, name, version, artifact_digest, expires_at}` plus a MAC from the service.
- The gateway verifies the grant with the gateway credential. The agent cannot create a grant, and a grant does not work for another package, version, or digest.
- A grant expires after 120 seconds and is single use (the gateway records the grant id).
- No grant is issued without a completed anchor write (section 6.1).

## 9. Fail-closed behaviour (updated)

| Situation | Behaviour |
|---|---|
| Service unreachable | MCP returns NO VERDICT. Hook refuses installs. Gateway serves nothing |
| Key missing, with a sink record present | Refuse to start: `INSTALLATION_STATE_LOST` (section 5.2) |
| Key missing, no sink record, no `init` | Refuse to start: `NOT_INITIALISED` |
| Sink unreachable at start | Refuse to start |
| Anchor Degraded or Halted | NO VERDICT for all requests (section 6.2) |
| Anchor receipt invalid | Treated as Rejected |
| Head inconsistent with the sink | Halted, integrity alarm |
| Counter store missing with history | Block (existing rule, kept) |
| Token invalid, expired, revoked, or wrong binding | Deny with no verdict |
| Approval signature invalid | Reject; quarantine stays open |
| Policy hash differs from the pin | Refuse verdicts: `POLICY_PIN_MISMATCH` |
| Request id replayed | Return the cached verdict; no new count |

## 10. Rate-limit protection

- Counters live in the service, keyed to the session token's installation and token id.
- Credit entries live in the service too.
- A missing or unreadable counter store blocks, and the service never recreates an empty store while a sink record exists (the same rule as the key).
- Replays do not count again (section 8.2). Restarts do not reset counts.
- Requirements R-4.7 and R-G-11 carry over unchanged.

## 11. Migration strategy (unchanged from revision 1, with the bootstrap step added)

| Step | Work | Exit check |
|---|---|---|
| M0 | Inventory current state (done: key, log, counters, quarantine, policy) | Inventory accepted |
| M1 | Service skeleton with no behaviour change, reads the old state read-only | Same decisions on the equivalence corpus |
| M2 | `slopseal-svc init`: new installation, key, log, and sink record. Old log archived read-only, labelled **legacy, unanchored**, never extended | Old log verifies with its old key; new log verifies with the new key; sink holds the record |
| M3 | MCP and hook become clients; local state writes stop; fail-closed on service loss | Killing the service blocks every install path |
| M4 | Anchor sink receipts in place, with the Degraded, Halted and Recovered paths tested | AC-15 to AC-19 pass |
| M5 | Local state removed from the workspace after archive | Agent-side reads of the old paths fail |
| M6 | Retire the local-state code | Suites green, property tests green |

## 12. Testing and acceptance criteria (updated)

### 12.1 Acceptance criteria

| ID | Criterion | Test |
|---|---|---|
| AC-1 | Agent cannot read the key | Attempt from the agent shell: must fail (T-IDE-2, T-WEB-1) |
| AC-2 | Agent cannot change audit records | Attempt write or truncate: must fail; if it succeeds, the anchored verifier detects it |
| AC-3 | Counters cannot be reset from the agent side | Delete attempt, restart MCP, restart agent: count preserved |
| AC-4 | Missing key blocks | Remove key with audit state present: next verdict refused, no key created |
| AC-5 | Service down blocks every install path | Stop service: hook, MCP, gateway all refuse |
| AC-6 | No secret in MCP responses or env | Scan MCP responses and the MCP environment for key bytes and state paths |
| AC-7 | Token replay, expiry, and revocation | Replayed request id returns cached verdict, no new count; expired and revoked tokens refused |
| AC-8 | Anchor detects truncation | Truncate the log: verifier reports mismatch |
| AC-9 | Decision equivalence after migration | Equivalence corpus: identical outcomes |
| AC-10 | Legacy logs labelled | Legacy log reports `unanchored` |
| AC-11 | Suites green | Full suite with Hypothesis installed |
| **AC-12** | **Existing installation cannot bootstrap silently.** Create an installation, verify, then delete key and log (keep the sink). Start the service and submit a verdict. | Start refused with `INSTALLATION_STATE_LOST`. No key file created. Verdict returns NO VERDICT. Sink record unchanged |
| **AC-13** | **Bootstrap needs an explicit init.** Empty state, no sink record, no `init`. | Refused with `NOT_INITIALISED`. Nothing created |
| **AC-14** | **Bootstrap fails when the sink is unreachable.** Run `init` with the sink down. | `init` fails. No key created. No record written locally |
| **AC-15** | **Anchor unavailable, fail closed.** Make the sink unreachable during an ALLOW verdict. | No ALLOW returned. No artifact served. Status Degraded shown. Record pending, not committed |
| **AC-16** | **Anchor rejects an append.** Sink returns a rejection. | Halted. NO VERDICT for all requests, including BLOCK. No automatic retry |
| **AC-17** | **Inconsistent head is an alarm.** Sink returns a head with a different hash for an existing seq, or a seq going backwards. | Halted with integrity alarm. No repair. `verify` reports the first mismatching seq |
| **AC-18** | **Invalid receipt is a rejection.** Corrupt the receipt signature. | Treated as Rejected. No ALLOW |
| **AC-19** | **Recovery replays in order.** Sink returns after Degraded with three pending records. | Each record receives its own receipt in seq order. No duplicate seq. Then Normal |
| **AC-20** | **Sudo route closed.** Installer run on an agent account with a sudo rule. | Preflight fails. Status not ENFORCED. Installer changes nothing |
| **AC-21** | **Docker route closed.** Agent account in the `docker` group, or socket reachable. | Preflight fails. Status not ENFORCED |
| **AC-22** | **Session token cannot reach forbidden operations.** Use the session token for each row of the forbidden set in 8.3: read seal key, modify audit, reset rate limit, approve, change pin, issue token. | Each refused with `DENIED_OPERATION`. Nothing changed. Each denial logged |
| **AC-23** | **Gateway credential is not a session token.** Present the session token to the gateway and the anchor channel. | Both refuse. The gateway credential presented to the verdict API is refused |
| **AC-24** | **Grant is narrow.** Reuse a grant for another package, version, digest, or a second time, and after 120 seconds. | Each refused. Each refusal logged |
| **AC-25** | **Peer binding.** Connect to the verdict socket from a different uid holding a valid token. | Refused by `SO_PEERCRED` |

### 12.2 Test environments

- Kiro IDE and CLI: throwaway accounts per the protocol. These test primitives. AC-20 and AC-21 need an administrator and a host where a sudo rule can be set and removed.
- Production-model tests (AC-20, AC-21, AC-25, and the ptrace check) run on a Linux VM set up as in section 7.2.
- Kiro Web: remote-service tests only (advisory).
- Container tests: a Linux host with Docker (not available in this sandbox).

## 13. Open questions (carried forward)

1. Is the agent process a non-root account on the developer machine? (T-IDE-1)
2. Can a non-root agent read another account's files through the Kiro sandbox? (T-IDE-3)
3. Can the sandbox reach a socket owned by another account? (T-IDE-4)
4. Which anchor sink is acceptable for the product (self-hosted, or a managed transparency log)?
5. How is an approval device enrolled and its public key distributed?
6. Does Kiro's sandbox let a non-root agent run `sudo` with a cached credential? (new, test on a throwaway VM)

## 14. Roadmap (updated)

| Phase | Goal | Depends on | Exit |
|---|---|---|---|
| D2-a | Revision 2 approved; IDE/CLI protocol executed on throwaway accounts | Review; throwaway accounts | Results recorded in the protocol report |
| D2-b | Installer preflight (section 7.3) and production model checks (AC-20, AC-21, AC-25) on a VM | D2-a | Preflight passes only on a correctly configured host |
| D2-c | Service skeleton (M1), `init` and sink records (M2) | D2-b | AC-9, AC-12, AC-13, AC-14 green |
| D2-d | Clients switched; fail-closed; anchor paths (M3, M4) | D2-c | AC-5, AC-15 to AC-19, AC-22 to AC-24 green |
| D2-e | Local state removed; legacy labelling (M5, M6) | D2-d | AC-1 to AC-8, AC-10, AC-11 green |
| D3 | Approval channel (Ed25519 ADR first, also for sink receipts) | D2-c and the ADR | AC-17, AC-18 green for signed receipts; F-02 Part B closed |
| W | Web remote service, advisory | D2-c; Web testing with administrator access | Status shown as advisory |
| Wizard | Kiro-native guided setup | D2-e, D3 | After D2 and D3 |

ENFORCED is not claimed on any surface before D2-e, and only for IDE and CLI in the production model, and only when the probes and preflight pass.

## 15. Decisions still open

1. Anchor sink choice (section 13.4).
2. Approval key enrolment (section 13.5).
3. Whether sudo with a cached credential must be disabled for the agent account, or the agent account must have no sudo at all (recommended: no sudo at all).
