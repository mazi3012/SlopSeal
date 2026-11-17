# D1 Egress Restriction Experiment: Result

- Date: 2026-11-17
- Branch: `feat/package-source-gateway` (PR #32, draft, not merged)
- Decision under test: D1. The sandbox must not reach PyPI or npm directly. Only the gateway may reach approved registries.
- **Result: D1 is NOT enforced. The experiment was stopped before any change was made to the sandbox network.**

## 1. Why the experiment stopped

Requirement 8 of the approval says: if the platform cannot enforce process-level egress restrictions, stop and report. The findings below show the restriction cannot be enforced against this agent from inside the sandbox.

1. **The platform reports open internet.** `get_sandbox_info` returns `network_mode: OPEN_INTERNET`. The network mode is set in the platform settings, not from inside the session, and I cannot change it from here.
2. **The agent holds the privileges that would enforce a rule.** The process runs as `root` (uid 0), with `CapEff` = `000001ffffffffff`. That includes `CAP_NET_ADMIN`, so the agent could add iptables rules. The same privilege lets it delete them again (`iptables -F`), or run a process that bypasses them. A rule set inside the sandbox stops accidents, not a deliberate bypass by the same agent.
3. **No restriction exists to test against.** The OUTPUT chain has only the default policy and one platform rule that rejects `169.254.169.254` (the cloud metadata address). Nothing rejects registry traffic.

Adding a firewall rule to run the experiment would have been a change to shared sandbox networking, with a rollback that the agent itself controls. I did not do it.

## 2. Configuration changed

None. The sandbox network, the firewall rules, the environment, and the hook are unchanged. The rollback procedure is therefore not needed.

## 3. Direct access test results (read-only, HEAD requests only, run from the sandbox)

| Request | HTTP status | Meaning |
|---|---|---|
| `https://pypi.org/simple/requests/` | 200 | PyPI reachable directly |
| `https://registry.npmjs.org/express` | 200 | npm registry reachable directly |
| `https://files.pythonhosted.org/` | 404 | Artifact host reachable (404 is the server's answer to the root path) |

The requested commands `pip download requests` and `npm view express` were not run through the shell. The SlopSeal hook intercepts those commands in this session and blocks them for being unpinned, so that result would reflect the hook, not the network. The HTTP results above are what `pip` and `npm` use underneath, and they show the registries answer.

**Result: direct access is NOT blocked.** Requirement 1 is not met.

## 4. Gateway access test results

- Unit tests (`src/tests/unit/test_gateway.py`, 22) and HTTP tests (`src/tests/integration/test_gateway_http.py`, 6) pass. They use a fake upstream.
- The gateway cannot reach its real upstream yet, because the live upstream adapter (artifact URL and published digest from PyPI and npm) is not implemented (ADR 0004, R-GW-6). So requirement 4 cannot be verified against a live registry.
- ALLOW, BLOCK and QUARANTINE behaviour with respect to bytes is covered by the tests. ALLOW with a matching digest returns the bytes. BLOCK, QUARANTINE and RATE_LIMITED return 403 with no bytes. Digest mismatch, a missing digest, an upstream failure and a verifier error each return an error with no bytes. The live path has not been exercised.

## 5. Bypass attempts tested

| Route | Result |
|---|---|
| Direct HTTPS to `pypi.org` | Succeeds (200) |
| Direct HTTPS to `registry.npmjs.org` | Succeeds (200) |
| Command forms the hook misses (F-01), for example `timeout 60 pip install ...` | Not re-tested here. Audit result still applies: the hook passes them. |
| Gateway route validation (`parse_route`) | Refuses bad ecosystems, versions, and encodings (tested) |

Any tool that makes HTTPS requests bypasses the gateway, because nothing stops it. A Python `urllib` call or `curl` reaches the registry in the same way.

## 6. Remaining security gaps

1. **D1 not enforced.** Direct registry access works. This is the most important gap, and it means the gateway is not yet a boundary.
2. **Agent holds root and network admin.** Any local rule can be removed by the agent.
3. **Gateway is not reachable by package managers.** pip and npm cannot use it as an index yet (R-GW-6).
4. **Live upstream not built.** The gateway cannot be tested against a real registry.
5. **F-01 bypasses** remain, because the hook is still the only check on command text.
6. **Key and state location (D2) and approvals (D3)** are unchanged. The agent can read the key and reset the rate limit.

## 7. Whether D1 can be considered enforced

**No.** D1 cannot be called enforced, and the sandbox does not currently enforce it. Two things would be needed:

- **Platform-level restriction.** The operator sets the sandbox network mode to an allow-list that excludes PyPI and npm. This is set outside the session. Once set, it needs a test that `curl` to `pypi.org` and `registry.npmjs.org` fails from the sandbox.
- **An egress path the agent cannot undo.** For example, the gateway runs outside the agent's sandbox, and the agent's network can reach only the gateway's address. Enforcement by the agent's own root user is not enough.

## 8. Recommended next step (not started)

Ask the platform owner to set the sandbox network mode to an allow-list that contains only the gateway host. Then re-run sections 3 and 5 and record the results here. Wait for your review before D2 or D3.
