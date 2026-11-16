# SlopSeal Failure Taxonomy

Two kinds of failure: failures SlopSeal prevents, and failures SlopSeal itself can have. Each row ties to a requirement so a gap is easy to see.

## 1. Failures SlopSeal prevents

| ID | Failure | Example | Detected by | Outcome | Requirement |
|----|---------|---------|-------------|---------|-------------|
| P1 | Slopsquatting | Agent installs `react-codeshift`, a blend of two real tools, registered by an attacker | Existence, slopsquat signature, age, malware feed | BLOCK | R-2.1, R-2.3, R-2.4, R-2.7 |
| P1b | Typosquat of a popular package | `reqeusts` published last week | Typosquat distance AND age | BLOCK | R-2.2 |
| P1c | Near-name of a popular package, not new | `requestss` published a year ago | Near-name similarity | ALLOW with WARN | R-2.11 |
| P2 | Semantic mismatch | Agent needs `csv.reader`, picks `csv-parser` that exports `parse` | API-surface check | QUARANTINE | R-Q-1 |
| P2b | Purpose mismatch with a valid API name | Package exports the right function name but does something else | L2, only if the M1 gate passes | QUARANTINE | R-3.5 |
| P3 | Silent policy erosion | Agent changes the unknown-state rule to ALLOW | Property suite, pre-commit guard, policy hash in seals | Edit rejected | R-PBT-2, P-FC-8 |
| P4 | Known-vulnerable version | Exact version has a critical CVE | OSV lookup | BLOCK | R-2.6 |

## 2. Failures SlopSeal can have

| ID | Failure | Impact | Handling | Requirement or property |
|----|---------|--------|----------|-------------------------|
| F1 | False negative: bad package gets ALLOW | Core failure | Layered checks; limits documented in `THREAT_MODEL.md` section 6 | R-2.*, README Limitations |
| F2 | False positive: good package blocked | Friction, loss of trust | Typosquat needs both distance and age; near-name is WARN only; allow list; `--allow-unsafe` with audit | R-2.2a, P-TY-1, P-TY-2, R-1.5 |
| F3 | Unknown state treated as safe | Silent fail-open | Explicit `Unknown` values; failclosed wrapper | P-FC-1, P-FC-2, P-FC-3 |
| F4 | Quarantine never ends | Agent or CI hangs | Terminal states, expiry, budget of 1 | P-SM-1, P-SM-2, R-Q-7 |
| F5 | Quarantine mistaken for allow | Agent proceeds with install | Distinct exit code 75; payload on stdout | R-Q-4 |
| F6 | L2 blocks a legitimate package | Friction | L2 can only QUARANTINE, never block | R-3.7, P-FC-5 |
| F7 | Tampered snapshot, policy, or log trusted | Forged verdicts | Checksums, hash chain, seals | P-SN-1, P-AU-1, P-AU-2 |
| F8 | Non-deterministic output | Demo and replay break | Injected clock, canonical JSON, no randomness in checks | P-SN-2, P-AU-3 |
| F9 | Replay cannot reproduce | Evidence is unusable | Log stores policy hash and snapshot id; replay reports when inputs are missing | P-AU-3 |
| F10 | Unsupported install command passes through | Bypass | Unparseable install commands block | design section 11 |
| F11 | Policy typo falls back to a default | Silent weaker policy | Unknown keys are policy errors | design section 7 |
| F12 | Intent tuned to pass the check | Mismatch slips through retry | Retry intents logged; escalation shows diff; check uses the package's own exports | design section 9 |

## 3. How to use this file

- A new check or behavior should map to at least one row in section 1.
- A new failure found in testing becomes a row in section 2, with a requirement or property that covers it.
- A row with no requirement or property in the last column is a gap, to be closed or accepted in `THREAT_MODEL.md` section 6.
