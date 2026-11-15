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
- **Rejected: HMAC-signing the snapshot.** The seal key is random and created per state directory, so a snapshot signed with it could be checked only on the machine that made the key. A committed snapshot would fail verification on every other clone, or the key would have to be committed and the signature would prove nothing. Ed25519 needs a dependency the stdlib does not have. The snapshot therefore uses a checksum manifest (below).
- **Resolved (Open Decision 6):** the seal key is generated on first use into `.slopseal/secret.key` (mode 0600, git-ignored). Snapshot integrity is a static SHA-256 checksum manifest committed to the repo. Neither uses a signing extra, so both work in the default install.
- Rejected: pulling a fuzzy-matching library for three small algorithms, and an HTTP client library for two GET endpoints.
