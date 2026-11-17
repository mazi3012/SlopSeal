# D2: Security-State Ownership Architecture (revision 3, design, not implemented)

- Status: **design and threat model only.** No code, configuration, firewall, network, sandbox, or Kiro setting was changed. D2 is not implemented. D3 and the setup wizard are not started. PR #35 stays Draft. PRs #32, #33 and #34 are untouched.
- Scope: Kiro IDE and Kiro CLI (first enforcement targets). Kiro Web is advisory in v1 and uses a remote service.
- Revision 3 (documentation only) binds replayed requests to their original content and token (8.4), states audit recovery limits and requires a protected replica (6.6), makes enforcement status deterministic (7.4), defines the artifact route (7.5), and binds anchor receipts to the installation (6.5). Sections marked **[rev2]** and **[rev3]** are new or changed. The IDE/CLI test protocol is unchanged.

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
 |   - artifact grants     (issued here, verified by the gateway, section 7.5)  |
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
3. Send the record's head to the anchor sink. Wait for a **signed receipt** that names the same `installation_id`, `seq`, `head_hash`, and `key_id` (section 6.5).
4. On a valid receipt, commit the record locally and return the result.
5. Only then return ALLOW, and only then issue an artifact grant (section 7.5).

No ALLOW leaves the service before step 4. The gateway serves no bytes before step 4.

The sink's receipt is signed with the sink's own key (Ed25519 in the target design, per D3). The signed payload is the canonical JSON of `{installation_id, key_id, seq, head_hash, sink_id, issued_at}`. The service verifies the signature and then checks that `installation_id`, `key_id`, `seq`, and `head_hash` equal the values it sent. A receipt that fails any of these checks is a failure, not a success (section 6.2, "Invalid receipt"). Section 6.6 gives the acceptance test for a validly signed receipt that belongs to another installation.

### 6.2 Failure definitions and required behaviour

| Condition | Definition | Behaviour |
|---|---|---|
| **Unavailable** | No response, timeout, connection refused, or 5xx within the anchor timeout | **Degraded.** Return NO VERDICT for every request (including BLOCK), so the state is visible. Keep the record in a pending queue. Retry with bounded backoff. The degraded state is reported in the MCP status line |
| **Rejected** | 4xx, a sequence conflict, or an explicit refusal | **Halted.** Return NO VERDICT for every request. Do not retry automatically. Operator must investigate. Written to the local log as an event |
| **Inconsistent head** | The sink returns a head for a `seq` that differs from what the service holds, a `seq` that goes backwards, or a receipt for a different `installation_id` | **Halted, integrity alarm.** Return NO VERDICT. Never auto-repair. Operator runs `slopseal-svc verify` |
| **Invalid receipt** | Signature fails, the receipt is missing fields, or any of `installation_id`, `key_id`, `seq`, `head_hash` differs from what the service sent. A validly signed receipt for another installation is in this class | Treated as **Rejected** (Halted, section 6.2) |
| **Recovered** | Sink available again after Degraded | Replay the pending queue in `seq` order. Each replayed record must receive its own receipt. Duplicates are rejected by `seq`. Then return to Normal |

### 6.3 The rules in one place

- The service **fails closed**: any anchoring failure means NO VERDICT for all requests until the state is Normal again.
- A pending record is never served, never counted as ALLOW, and never deleted.
- Pending records survive restart. On start, the service reconciles pending records against the sink before it accepts requests (section 5.2).
- A failed anchor never downgrades to a local-only log. There is no "anchor optional" mode in production.

### 6.4 Limits

- An attacker who controls the sink can present a consistent but false history. The sink is therefore a separate identity with append-only storage and its own receipt key, and its operator is separate from the service operator where possible.
- Anchoring proves that a record existed when the sink accepted it. It does not prove that every real install passed through the service. Bypasses (D1) are closed by network controls, not by the log.

### 6.5 Receipt binding to the installation [rev3]

Every receipt is checked against the installation it claims to belong to. The verifier does not trust a signature by itself: a receipt is accepted only when all of these match the service's own state:

| Field | Source of the expected value | Check |
|---|---|---|
| `installation_id` | Local installation record, confirmed at startup against the sink (section 5.2) | Must equal |
| `key_id` | Current seal key id | Must equal |
| `seq` | The record that was sent | Must equal |
| `head_hash` | The head the service computed for that `seq` | Must equal |
| signature | Sink receipt key, from the sink's pinned public key | Must verify over the canonical payload in section 6.1 |

A receipt signed by the sink for a **different** installation has a valid signature and still fails the `installation_id` check. The same sink can hold several installations, so the signature alone identifies only the sink, not the installation.

### 6.6 Audit recovery and data durability [rev3]

**What the anchor sink preserves.** The sink stores, for each `seq`, the installation id, the key id, and the head hash (receipts). It does **not** store the audit records themselves. A head hash is a fingerprint: it lets anyone check that a record they hold is the one that was chained at that position, but it cannot produce the record's content.

**Consequences, stated without qualification:**

1. The anchored sequence numbers and head hashes do **not** preserve the audit records. They prove integrity; they do not provide content.
2. If the local audit log is lost and no other copy exists, the lost records **cannot be reconstructed** from the sink. The sink can establish only the final anchored head (and the head hash for each earlier sequence number), not what the records said.
3. The sink alone does **not** preserve or reconstruct the complete audit history. Do not describe it as a backup.

**Required protection: a protected replica.** A complete copy of every sealed record must be written, after each commit, to a replica that the agent cannot write or read, held by a different identity from the service where possible. The replica is append-only, and it holds the sealed records exactly as committed (not an unanchored or pending copy). The replica is part of the audit integrity design, so its presence and its verification are preflight checks (section 7.4).

**Recovery procedure (with a replica):**

1. Operator restores the sealed records from the replica into a new local log.
2. The verifier checks each record's chain and seal, and then checks the head hash for every `seq` against the sink.
3. Only when every check passes does the service return to Normal. Any mismatch is Halted (section 6.2).

**Permanent local-log loss without a replica** is not recoverable. The service refuses to issue verdicts (section 5.2, "Missing, with a sink record present"). The operator may archive the installation as retired (section 5.4). The retired installation keeps its final anchored head as proof that the chain ended at that head. The lost records are not reconstructed, and the history before the final head cannot be shown to the auditor in full.

**Durability limit.** A replica is not an unlimited guarantee. Loss of the replica together with the local log is permanent loss of content, and it is the operator's responsibility to keep the replica on separate storage.

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
7. A protected audit replica exists, is written after every commit, and its head hashes match the sink (section 6.6).
8. The approved artifact route works and the agent has no direct registry route (section 7.5).

Each check is recorded as PASS, FAIL, or NOT RUN. The overall status is then derived only by the rules in section 7.4. The installer never escalates privileges to fix a failed check. It prints the change a human must make.

### 7.4 Deterministic enforcement status [rev3]

The status is a pure function of the preflight and probe results. No wording in a result or a log may override it.

**Check classes:**

| Class | Checks | Meaning of a failure |
|---|---|---|
| **Class A: security-critical** | A1 no sudo, su, or polkit route for the agent account (7.1, rows 1–2). A2 no Docker group or socket route (7.1, row 3). A3 service writable executables and shared groups closed, and the key, state, and service sockets unreadable by the agent except the verdict socket (7.1, rows 4 and 6). A4 `ptrace_scope` at least 1 and no `CAP_SYS_PTRACE` for the agent (7.1, row 5). A5 anchor integrity: sink reachable, receipts verify, `installation_id`, `key_id`, `seq`, and head match (6.5), and the anchor is not writable by the agent (7.1, row 7). A6 no direct registry route from the agent: every probe to a registry, by any client, fails (7.5 and the probe matrix). A7 policy pin matches. A8 verdict socket binding (`SO_PEERCRED`) active. A9 Kiro escape routes that run commands outside the sandbox are disabled where Kiro allows (7.1, row 8; protocol tests N5 and N6) | **Any failure or NOT RUN → NOT ENFORCED** |
| **Class B: coverage and durability** | B1 protected audit replica present and head-verified (6.6). B2 approved artifact route answers for an ALLOW grant (7.5). B3 probes that cannot run on this host (for example IPv6 on a host with no IPv6), where the probe class has no route to a registry in the other probes | **Any FAIL → PARTIALLY ENFORCED at most. Any NOT RUN → NOT ENFORCED** (Option A, see the note below the outcome table) |

**Outcomes:**

| Status | Rule (all must hold) |
|---|---|
| **ENFORCED** | Every Class A check PASS **and** every Class B check PASS. No probe is NOT RUN |
| **PARTIALLY ENFORCED** | Every Class A check PASS, **and** at least one Class B check is FAIL, **and** no Class B check is NOT RUN, and no Class A check is FAIL or NOT RUN. Each failed Class B check is named in the status |
| **NOT ENFORCED** | Any Class A check FAIL or NOT RUN, **or** any Class B check NOT RUN, **or** any condition in section 7.4.1 holds |

**Option A (owner decision, tracked in issue #38).** A Class B check that is NOT RUN gives NOT ENFORCED, not PARTIALLY ENFORCED. Any check that is NOT RUN, in either class, gives NOT ENFORCED. Under this rule a host where a Class B probe such as B3 cannot run cannot reach PARTIALLY ENFORCED. The rule is implemented in `src/slopseal/preflight/rules.py`, rule 3, and tested by PR #36.

**7.4.1 Conditions that always produce NOT ENFORCED**, regardless of the other checks:
1. The agent can escalate privileges (any A1 or A2 route is open, or unknown).
2. The agent can read protected state (the seal key, the audit log, the rate-limit state, or the service identity's files).
3. The agent can reach the service through a route other than the verdict socket, or can reach the anchor or the gateway credential.
4. The agent can obtain package bytes that did not pass through a grant (direct registry access succeeds, or the gateway serves bytes without a grant).
5. An anchor state is Degraded or Halted (section 6.2).
6. The status cannot be determined (a probe error is recorded as NOT RUN, so this also applies whenever A-class evidence is missing).

**Kiro Web (advisory in v1):** the remote-service variant can reach at most PARTIALLY ENFORCED, labelled advisory. It cannot reach ENFORCED in v1.

**Reporting:** every status shows which Class A and Class B checks passed, which failed, and which were not run. A PARTIALLY ENFORCED status lists the named Class B gaps. A NOT ENFORCED status lists the first failing Class A check or the 7.4.1 condition that applies.

### 7.5 Approved artifact route [rev3]

The agent must be able to get approved artifacts, and it must not get them any other way.

**Route:**

1. The agent calls `verify` on the verdict API with its session token. For an ALLOW verdict, the response includes a **grant**: `{grant_id, verdict_id, ecosystem, name, version, artifact_digest, token_id, expires_at}` with a MAC from the service. The grant is delivered only over the verdict socket (or TLS on Web), never in the MCP status text.
2. The agent sends `GET /artifact` to the gateway with the grant in a header and the **session token** in a second header. Both are required.
3. The gateway verifies the grant MAC with the gateway credential, checks that `token_id` equals the token presented, checks expiry (120 seconds), checks that the grant has not been used (it records `grant_id` at first use), and checks that the request matches `ecosystem`, `name`, and `version`.
4. The gateway fetches the upstream artifact over its own egress path, verifies its SHA-256 against `artifact_digest`, and streams the bytes only if all checks pass.
5. The gateway marks `grant_id` as used before it streams bytes, so a dropped connection cannot be retried with the same grant.

**Why the agent gets no direct registry route:** the agent network has no egress to the registries (A6). The only artifact path the agent can reach is the gateway, and the gateway serves only with a grant.

**Limits:**

- A grant is a bearer value for one artifact, for 120 seconds, for one session. If a grant leaks within that window, the same session's token is still needed to use it, so the leak does not give a new session access.
- The gateway index protocol that a package manager needs (R-GW-6, pip simple API and npm registry) is not built. Until it is, the route serves one artifact per request and no package manager can use it directly. That protocol work is a dependency of this route being usable, not of its security.
- The route is narrow only if the agent's network really has no registry egress, which is probe A6.

### 7.6 Acceptance tests for the route

| ID | Test |
|---|---|
| AC-32 | An ALLOW verdict returns a grant. The gateway serves the matching bytes once. A second use of the same grant is refused |
| AC-33 | The gateway refuses a grant presented with a different session token, a different package, a different version, or a different digest, and refuses an expired grant. Each refusal is logged |
| AC-34 | The gateway refuses a request with no grant, even when the session token is valid |

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
| Replay | Bound to the original request, token, and content. See section 8.4 |
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

### 8.4 Request binding and replay [rev3]

A request id on its own is not an identity. Anyone who learns an id could reuse it for a different request. So each id is bound to the token and to the exact content of the request it first named.

**Canonical request.** The service builds the canonical request as UTF-8 JSON with sorted keys and no insignificant whitespace, containing:

- `op` (the operation name, for example `verify`)
- `ecosystem` (normalized, for example `pypi`)
- `name` (normalized package name)
- `version` (exact string)
- `purpose`, `expected_api`, `quarantine_id` (absent fields are written as `null`)
- `token_id` (the id of the presenting session token)
- `timestamp` (the client's request time)

`request_hash = SHA-256(canonical request)`. The hash covers every parameter that can change the verdict or the quota, so no security-relevant field can differ without changing the hash.

**Replay record.** For each accepted request the service stores `{request_id, token_id, request_hash, verdict_id, timestamp, expires_at}`. The record is kept for the replay window, and no longer.

**Rules.**

| Incoming request with a known `request_id` | Decision | Quota | Audit |
|---|---|---|---|
| Same `token_id` and same `request_hash` | **Return the cached verdict.** The verdict is the one already issued (the same `verdict_id`) | Not counted again | `REPLAY_CACHED` |
| Same `token_id`, different `request_hash` | **Reject** with `REPLAY_CONFLICT`. Nothing is evaluated | Not counted | `REPLAY_CONFLICT` |
| Different `token_id` (any hash) | **Reject** with `REPLAY_DENIED`. Nothing is evaluated | Not counted | `REPLAY_DENIED` |
| Unknown `request_id` | Evaluate normally | Counted once | Normal verdict record |

**Freshness.** A request is accepted only if its `timestamp` is within ±2 minutes of the service clock and no older than the replay window (10 minutes). Older requests are rejected with `REQUEST_STALE`, not evaluated and not counted. This is what keeps the replay record small: a request id can be forgotten after the window only because a request that old can no longer be accepted.

**Limits.** A cached verdict returned for an identical request reveals the verdict, not new information. A replayed grant is governed by section 7.5, not by this rule.

### 8.5 Grants (gateway and artifact)

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
| Request id replayed, identical token and content | Return the cached verdict; no new count (8.4) |
| Request id replayed, altered content or different token | Reject (`REPLAY_CONFLICT` or `REPLAY_DENIED`); nothing evaluated; no count (8.4) |
| Request outside the freshness window | Reject (`REQUEST_STALE`); nothing evaluated; no count (8.4) |

## 10. Rate-limit protection

- Counters live in the service, keyed to the session token's installation and token id.
- Credit entries live in the service too.
- A missing or unreadable counter store blocks, and the service never recreates an empty store while a sink record exists (the same rule as the key).
- Identical replays do not count again, and altered or cross-token replays are refused without counting (section 8.4). Restarts do not reset counts.
- Requirements R-4.7 and R-G-11 carry over unchanged.

## 11. Migration strategy (unchanged from revision 1, with the bootstrap step added)

Scope (updated 2026-11-17): M1 and every later step (M2 to M6) are v2.1, not v2. See section 14.

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
| AC-7 | Token expiry and revocation | Expired and revoked tokens refused. Replay behaviour is tested by AC-26 to AC-29 |
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
| **AC-26** | **Identical replay returns the cached verdict.** Send one `verify` request, then send the same request id, token, and content again. | Same `verdict_id` returned. Quota counted once. Audit `REPLAY_CACHED` |
| **AC-27** | **Altered-request replay is rejected.** Same request id and same token, with a different version (or any field in the canonical request). | Refused with `REPLAY_CONFLICT`. Nothing evaluated. Quota not counted. Audit `REPLAY_CONFLICT` |
| **AC-28** | **Cross-token replay is rejected.** Same request id, identical content, but a different session token. | Refused with `REPLAY_DENIED`. Nothing evaluated. Audit `REPLAY_DENIED` |
| **AC-29** | **Stale request is rejected.** Send a request with a timestamp older than the 10-minute window, and one more than 2 minutes in the future. | Both refused with `REQUEST_STALE`. Nothing evaluated, nothing counted |
| **AC-30** | **Receipt for another installation is rejected.** The sink returns a receipt with a valid signature whose `installation_id` belongs to a different installation. | Treated as Invalid receipt, so Halted (section 6.2). No ALLOW. Quota and log unchanged |
| **AC-31** | **Permanent local-log loss.** (a) With a verified protected replica: delete the local audit log, keep the key and the sink record. (b) Without a replica: same deletion. | (a) Service refuses, operator restores from the replica, the verifier checks the chain and every head against the sink, then the service returns to Normal. (b) Service refuses with `AUDIT_RECORDS_UNRECOVERABLE`. The report's limits apply: lost records are not reconstructed, and only the final anchored head is established |
| **AC-35** | **Status is deterministic.** Use four preflight fixtures: (1) all checks pass; (2) only a Class B check fails (for example the replica); (3) a Class A check fails while every Class B check passes; (4) a Class A check is NOT RUN with every Class B check passing. Also (5) a direct registry probe succeeds. | (1) ENFORCED. (2) PARTIALLY ENFORCED, naming the failed Class B check. (3) and (4) NOT ENFORCED, naming the Class A check. (5) NOT ENFORCED under section 7.4.1, condition 4. The same input always yields the same status |

The artifact-route tests AC-32, AC-33 and AC-34 are defined in section 7.6 and are part of this list.

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

Scope (updated 2026-11-17). v2 covers D2-a and D2-b. The following are v2.1, not v2, because they depend on the M1 service skeleton or on the probe harness:

- M1 (service skeleton) and M2 to M6 (section 11).
- The probe harness, tracked in issue #39 (PR F). The ENFORCED path requires it.
- The artifact route (section 7.5), implemented as PR D. PR D stays stopped until v2.1 starts.
- Phases D2-c, D2-d, D2-e, D3, W and Wizard, which depend on M1 in the table below.

| Phase | Goal | Depends on | Exit
|---|---|---|---|
| D2-a | Revision 2 approved; IDE/CLI protocol executed on throwaway accounts | Review; throwaway accounts | Results recorded in the protocol report |
| D2-b | Installer preflight (section 7.3), deterministic status (7.4), and production model checks (AC-20, AC-21, AC-25, AC-35) on a VM | D2-a | Preflight passes only on a correctly configured host; status matches AC-35 fixtures |
| D2-c (v2.1) | Service skeleton (M1), `init` and sink records (M2), protected replica (6.6) | D2-b | AC-9, AC-12, AC-13, AC-14, AC-31 green |
| D2-d (v2.1) | Clients switched; fail-closed; anchor paths (M3, M4); request binding (8.4); artifact route (7.5) | D2-c | AC-5, AC-15 to AC-19, AC-22 to AC-24, AC-26 to AC-30, AC-32 to AC-34 green |
| D2-e (v2.1) | Local state removed; legacy labelling (M5, M6) | D2-d | AC-1 to AC-8, AC-10, AC-11 green |
| D3 (v2.1) | Approval channel (Ed25519 ADR first, also for sink receipts) | D2-c and the ADR | AC-17, AC-18 green for signed receipts; F-02 Part B closed |
| W (v2.1) | Web remote service, advisory | D2-c; Web testing with administrator access | Status shown as advisory |
| Wizard (v2.1) | Kiro-native guided setup | D2-e, D3 | After D2 and D3 |

ENFORCED is not claimed on any surface before D2-e, and only for IDE and CLI in the production model, and only when the probes and preflight pass.

## 15. Decisions still open

1. Anchor sink choice (section 13, open question 4).
2. Approval key enrolment (section 13, open question 5).
3. Whether sudo with a cached credential must be disabled for the agent account, or the agent account must have no sudo at all (recommended: no sudo at all).
4. Where the protected audit replica is hosted (section 6.6). It must not be on the agent's host, and it must be a different identity from the service where possible.
5. The `sink_id` format and the sink's receipt key enrolment (sections 6.1 and 6.5).
