# 0004. Verifying package gateway: the package source is the boundary

Status: Proposed (MVP implemented on branch `feat/package-source-gateway`; owner review pending)
Date: 2026-11-17

## Context

The install hook reads command text. The Phase 4 audit (F-01) showed that text inspection cannot be complete: a shell can reach an installer through variables, `eval`, scripts, interpreters, or direct downloads. The sandbox also reaches PyPI and npm directly. So any command form the hook misses installs unverified.

The only layer that does not depend on command syntax is the package source. If the agent can fetch packages only through SlopSeal, the way the command is written stops mattering.

## Decision

Add a package source gateway. It serves a package artifact only when `verify_install` returns ALLOW for that exact package and version, and only when the artifact's SHA-256 matches the digest the registry published. Everything else gets an error and no bytes.

The MVP (`src/slopseal/gateway/server.py`) is stdlib-only (ADR 0002). It exposes one route, `GET /v1/<ecosystem>/<name>/<version>/artifact`, and binds to loopback by default.

Proposed defaults for the open decisions in `reports/SlopSeal_PHASE4_REMEDIATION_PLAN.md` (the owner has not confirmed them):

- D1: the agent sandbox should reach only the gateway host, not PyPI or npm. This is an environment change, not part of this repo, and is not yet done.
- D2: the signing key and state should live outside the agent's writable area. This is not done in the MVP. The gateway runs with the same state directory it is given.
- D3: quarantine approval needs a human-held key. Not in the MVP.

## Alternatives considered

- **Keep the hook as the boundary, and add more patterns.** Rejected. Audit F-01 shows the approach cannot be complete.
- **Egress allow-list only.** Necessary, but on its own it blocks legitimate installs with no verifier in the path.
- **Kiro `permissions.yaml` deny rules.** Rejected for Web sessions: the documentation says they do not apply there, and they match command text anyway.

## Consequences

- The gateway is critical infrastructure. If it is down, nothing installs. It needs an availability target and its own threat model before production use.
- The MVP is not a package-manager endpoint. `pip` and `npm` cannot use it as an index yet (R-GW-6). The protocol work comes next.
- Protection is real only when D1 is in place. Until the sandbox egress allow-list is set and tested, direct registry access still works, and the MVP does not claim otherwise.
- The gateway uses the same verdict, rate limit and audit log as the hook and the MCP tool. No second policy exists.
- A digest check protects against a corrupted or swapped artifact. It does not protect against a registry that publishes a matching bad artifact, which is the same limit as T5 in `docs/THREAT_MODEL.md`.

## Next steps

1. Owner review of this ADR and of D1 to D3.
2. Live upstream adapter that returns the artifact URL and published digest for PyPI and npm.
3. pip and npm index protocol (simple API, registry JSON with tarball URLs).
4. Sandbox egress allow-list, then tests that `pip download` and `npm view` fail directly.
5. Move state and key outside the workspace (F-16).
