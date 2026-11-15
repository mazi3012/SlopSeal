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
- **Seal scheme for v1 (resolves Open Decision 6 in part):** seals are HMAC-SHA256 over the canonical JSON of the sealed fields, using `hmac` and `hashlib` from the standard library. This is symmetric and integrity-only: anyone who can verify a seal can also forge one. It proves that a seal was produced by a holder of the key and that the sealed fields have not changed. It does not prove who produced it to a third party.
- **Public verifiability is a roadmap item.** Ed25519 signatures, which let anyone verify without holding a secret, go behind the `slopseal[sign]` extra. That extra is created empty now and filled when the roadmap item is scheduled. It needs its own ADR, because it adds the first runtime dependency.
- **Snapshot signing** uses the same HMAC scheme in v1, so verification works in the default install. A snapshot signed with HMAC can be checked only by a holder of the key, so the threat model states that the key holder is trusted.
- Key storage location and rotation remain part of Open Decision 6, due at the end of Phase 2.
- Rejected: pulling a fuzzy-matching library for three small algorithms, and an HTTP client library for two GET endpoints.
