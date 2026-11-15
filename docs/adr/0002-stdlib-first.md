# 0002. Zero mandatory runtime dependencies

Status: Accepted
Date: 2026-11-15

## Context

SlopSeal is a supply-chain security tool. Every runtime dependency is a supply-chain risk for the tool that guards against supply-chain risk. The project also has a fixed schedule, so reviewing dependencies has a real cost.

## Decision

- **Zero mandatory runtime dependencies.** `pip install slopseal` installs SlopSeal and nothing else. The `dependencies` list in `pyproject.toml` stays empty.
- **Needle is optional.** The Needle adapter lives behind the `slopseal[needle]` extra. Without the extra, L2 is unavailable and the deterministic pipeline is complete. The extra is created empty now and is filled only if the M1 gate passes.
- **Live-mode HTTP uses the standard library.** Registry and OSV requests go through `urllib.request`. No HTTP client library.
- **Standard library first for everything else:** `tomllib`, `hashlib`, `json`, `difflib`, `argparse`.
- A new dependency of any kind, mandatory or in an extra, needs a stated reason in the PR and an ADR.

## Consequences

- A small attack surface and a short audit for the default install.
- Some code is written by hand (Levenshtein, Jaro-Winkler, keyboard distance, retry and timeout handling around `urllib`). Each piece is small and property-testable.
- **Signing constrains Open Decision 6.** The standard library has no Ed25519. The signing scheme must either be implementable with the standard library (for example HMAC-SHA256, which gives integrity but not public verifiability) or live behind an extra such as `slopseal[sign]`. That choice is made at the end of Phase 2 and recorded in a new ADR. Offline snapshot verification and seal verification must work in the default install, so whatever verifies cannot sit behind an optional extra.
- Rejected: pulling a fuzzy-matching library for three small algorithms, and an HTTP client library for two GET endpoints.
