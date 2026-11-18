# SlopSeal v2-complete: Properties

Each property names the requirement it checks. Each gets a Hypothesis test under `src/tests/properties/` and a mutant run, as the earlier phases do. A property is never loosened to pass a change.

## P-V2C-1: the launcher never fails open while plugged (R-AP-4, R-AP-5, R-AP-6)

*Statement.* For any set of config trees (any mix of absent, unreadable, invalid JSON, enabled entry, disabled entry, other servers) the launcher exits 0 without running the hook module only when at least one file was read and no readable file holds an enabled `slopseal` entry. In every other case it runs the hook module, and exits 2 when that module cannot run.

*Generators.* A tree of up to four config paths (working directory, two parents, user), each one of: missing, unreadable, truncated JSON, valid JSON with no `mcpServers`, with other servers only, with `slopseal` enabled, with `slopseal` and `"disabled": true`, with `slopseal` and `"disabled": false`, with the key in a different case. Entry names include near-misses such as `slopseal-dev` and `SlopSeal`.

*Mutants.* (a) A disabled entry cancels an enabled one. (b) Invalid JSON counts as unplugged. (c) An empty read set counts as unplugged. (d) The launcher matches `slopseal` as a substring of the server name. Each must fail the property.

## P-V2C-2: the managed hook is refreshed and never clobbers a user file (R-AP-2)

*Statement.* Starting the server any number of times leaves exactly one hook file. A managed file with an older marker is replaced by the current text. An unmanaged file is byte-identical afterward. The replacement never leaves a state where the file is empty or partial.

*Generators.* Initial hook state (none, managed old, managed current, unmanaged, empty, unreadable), a read-only directory, and an interrupted write (a fault injected between the temporary write and the rename).

*Mutants.* (a) Overwrite an unmanaged file. (b) Write in place, not through rename. (c) Skip the refresh when the marker version differs.

## P-V2C-3: the agent channel never lowers strictness, and the effective policy always passes the floors (R-SET-5, R-SET-6, R-SET-7, R-SET-11)

*Statement.* For any current settings and any sequence of agent-channel requests, the strictness of every knob is non-decreasing, and `enforce_floors(effective policy)` returns no violation. A request with any invalid or loosening part leaves the settings unchanged. No request can disable verification or remove the hook.

*Generators.* Random knob values inside and outside the floors, lists with additions and removals, mode changes, unknown fields, requests that mix a tightening part with a loosening part.

*Mutants.* (a) The direction check is inverted for one knob. (b) A mixed request applies its tightening part and skips the refusal. (c) The floors are checked before the overlay is applied. (d) An unknown field is accepted.

## P-V2C-4: first-run offer is shown once, and skip persists (R-SET-3, R-SET-4)

*Statement.* With no settings record, exactly one offer is shown per connection. After `skipped` is recorded, no tool result or hook message contains an offer until setup is started again. With no input at all, the effective policy equals the Balanced preset.

*Generators.* Sequences of tool calls and hook calls, with skip, setup, and neither, across reconnects.

## P-V2C-5: no write to MCP or Kiro settings (R-AP-7)

*Statement.* Under a fake filesystem that records writes, no server or launcher code path writes outside `.slopseal/` and `.kiro/hooks/`.

## P-V2C-6: the status line never overclaims (R-ST-1, R-ST-2, R-NB-8)

*Statement.* The status line is a pure function of the tier and the preflight result. The word ENFORCED appears only when every probe is PASS. A probe that is NOT RUN gives NOT ENFORCED. The Tier 0 line never contains ENFORCED, firewall, or boundary except in "Not a boundary".

*Generators.* Every combination of probe results, with both tiers.

*Mutants.* (a) A NOT RUN probe counts as PASS. (b) Tier 0 reads the Tier 1 line. (c) A stale probe result is accepted.

## P-V2C-7: every settings change is audited (R-SET-8)

*Statement.* For every request, accepted or refused, the audit log gains exactly one event with the old value, the new value, the channel, and the result, and the chain still verifies.

## P-V2C-8: live failure is a block (R-LV-4)

*Statement.* For any failure of a live lookup (timeout, connection error, HTTP error, bad JSON, oversize body, missing field), the verdict is BLOCK with a typed reason, never ALLOW. This restates the existing fail-closed property for the new default mode. The existing property test is extended to run in live mode with an injected transport.

## P-V2C-9: Tier 1 gateway serves bytes only for ALLOW (R-NB-3)

*Statement.* The gateway returns artifact bytes only when the grant is valid, unexpired, unused, bound to the presented session token and to the exact package, version, and digest, and the verdict was ALLOW. This extends the gateway properties of PR #32 (AC-32 to AC-34).
