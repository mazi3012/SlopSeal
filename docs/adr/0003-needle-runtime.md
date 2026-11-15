# 0003. Needle 3 runtime: needle-rs, not cactus-needle

Status: Accepted (for the M1 spike)
Date: 2026-11-15

## Context

Open Decision 10 (binding for Needle 3) was open from Phase 0. The PRD requires L2 to run on device. Two PyPI packages offer Needle 3 to Python:

| | `needle-rs` 0.3.1 (MIT) | `cactus-needle` 3.2.9 (Apache-2.0) |
|---|---|---|
| Publisher | Third party (geekgineer on GitHub; no author field on PyPI) | Cactus Compute (per the Hugging Face model card) |
| Form | Compiled Rust extension, one `.so` in the wheel | Pure Python package with a CLI and model code |
| Network at run time | None found in the extension (no URLs in the binary) | Downloads weights and engine binaries from Hugging Face. Its telemetry module posts usage events to a third-party Supabase endpoint on first use and by default. |
| Telemetry | None found | On by default. It can be disabled with `NEEDLE_TELEMETRY=0`, `DO_NOT_TRACK`, or `CI`. |
| Model | Loads `needle3.cact` from disk | Fetches `needle3.cact` from Hugging Face |

## Decision

Use `needle-rs` 0.3.1 in the optional `needle` extra, and load `needle3.cact` from a path that is checked against a pinned SHA-256 before use.

Reject `cactus-needle` for v1. Its telemetry sends data off the machine by default, which contradicts SlopSeal's "does not phone home" non-goal. Its runtime downloads code and weights at run time, which the fail-closed model does not allow.

The model checksum was taken from Hugging Face's published LFS OID and matches the downloaded file:
`c9d915eca282ed42d1a09b143b592adb4cc6744ffe2d294adf5cfc5548170c38` (35,335,380 bytes).

## Consequences

- Provenance risk: `needle-rs` is maintained by a third party, not by Cactus. Its README states output is verified token-exact against the upstream JAX reference, which we have not reproduced. The version is pinned, and the wheel hash should be pinned before the M1 result is used in the write-up.
- The spike ran on this machine. We did not run the upstream reference.
- A new dependency needs a PR reason and this ADR, as `tech.md` requires.

## Spike outcome (M1, Nov 15)

The pre-registered gate failed. Match-allow was 0.40 (2 of 5), against a minimum of 0.80. Mismatch-allow was 0.00 (0 of 5), against a maximum of 0.20. Full per-case results are in `docs/needle_spike.csv`.

Why it failed:
- On 3 of 5 matches the model made no tool call. It abstained with confidence 0.77 to 0.89, and the confidence head scored that abstention as high. A bare "no tool" answer is not a usable L2 signal.
- On 1 match (M01) the model chose `parse_file` over `parse`. The label is ambiguous, because both tools fit that purpose. That ambiguity is recorded in the labels file.
- On the mismatch side the model abstained every time. That passes the gate but says nothing about purpose.

The `needle` extra stays, so the spike can be reproduced. L2 is not wired into the verdict pipeline. A future attempt needs a new pre-registration with a different decision rule, not a retuned threshold. Re-running this spike cannot be used to pass the gate.

**Disclosure:** before the official run, I ran one probe on case M01 after the labels were committed. I did not change the labels or the threshold after that probe.
