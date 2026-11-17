# 0005. Ed25519 signatures for anchor receipts and approvals

Status: Accepted (owner approval, 2026-11-17). Implementation may proceed under PR C.
Date: 2026-11-17
Number note: 0004 is reserved by the gateway ADR on the frozen branch `feat/package-source-gateway` (PR #32).

## Context

The D2 architecture (`reports/SlopSeal_D2_SECURITY_STATE_ARCHITECTURE.md`, PR #35) needs two signatures that the verifier must check without holding a secret the agent could obtain:

1. **Anchor receipts.** An external sink signs a receipt for each appended audit head. The service accepts an ALLOW only after a valid receipt for its `installation_id`, `key_id`, `seq`, and `head_hash` (D2 sections 6.1 and 6.5).
2. **Approvals (D3).** A human approves a quarantined package with a signature from a device key that never exists on the agent's host or the service host (D2 section 4.4).

Both need asymmetric signatures. A symmetric MAC would let the service forge receipts: the service must hold the key to verify, so anyone who compromises the service can also sign. The sink receipt is supposed to be the independent check, so the verifier must not be able to sign.

### The v1 scheme this replaces

- **Audit seals.** The current audit log is sealed with HMAC-SHA256 (`src/slopseal/audit/seal.py`). The seal key is a 32-byte random value in the state directory. Anyone who can verify a seal can also forge one. `docs/THREAT_MODEL.md` section 6 accepts this for v1, and `docs/adr/0002-stdlib-first.md` records the reason (stdlib-first, no mandatory dependency).
- **Receipts and approvals.** Neither exists in code. The D2 design specifies them with Ed25519 "in the target design". Nothing ships under the old name, so there is no receipt format to migrate. The only signed artefacts in existence are the HMAC audit seals.

The stdlib does not provide Ed25519 in Python 3.11, so a dependency is required. ADR 0002 requires an ADR for it, and this is that ADR.

## Decision

1. **Algorithm: Ed25519 (RFC 8032).** Fixed for receipts and approvals. Verifiers reject any other `alg` value, so there is no downgrade path.
2. **Library: `cryptography` (pyca), pinned to `cryptography==50.0.2`**, in the `sign` extra that `pyproject.toml` already reserves. The pin is checked again at implementation time. The core install stays stdlib-only, so ADR 0002's zero-mandatory-dependency rule holds. Only the service and the sink install the extra. The HMAC audit verifier needs no new dependency.
3. **Signed payload.** Canonical JSON (sorted keys, UTF-8, no insignificant whitespace), prefixed with a domain separator so a receipt signature cannot be replayed as an approval, and the reverse:
   - Receipt: prefix `slopseal-receipt-v1\n`, fields `{alg, key_id, installation_id, sink_id, seq, head_hash, issued_at}`.
   - Approval: prefix `slopseal-approval-v1\n`, fields `{alg, key_id, quarantine_id, package, version, decision, approver, issued_at}`.
4. **Verifier rules.** Accept only if: `alg` is `Ed25519`; `key_id` is in the pinned key set for that purpose; the signature verifies over the prefixed canonical payload; the installation fields match (D2 section 6.5). Anything else is a rejection, and the service halts (D2 section 6.2).
5. **Pinning.** The service pins the sink's public key(s) in the installation record at `init`, through an out-of-band fingerprint check. The service never trusts a key that arrives over the same channel as the receipt (no trust-on-first-use).
6. **Separate key namespaces.** Receipt keys and approval keys are different keys with a `purpose` tag in the key registry. A receipt key can never approve, and an approval key can never anchor.

## Key rotation

- **Scheduled.** Each sink signing key has `key_id`, `purpose`, `valid_from`, and `valid_until` (default 90 days). A new key is created before the old one expires, so receipts never lack a key. The overlap is 30 days.
- **Registry.** Public keys and their status live in a registry the service pins by hash. Old public keys are kept to verify old receipts, and they are never deleted from the registry.
- **Compromise.** The compromised key is marked `revoked_at`. Receipts issued by it at or after `revoked_at` are rejected. Receipts issued before `revoked_at` remain verifiable, but they only prove what the key signed before the compromise, so the owner must treat any head signed in the suspected window as unproven and re-anchor from the protected replica (D2 section 6.6).
- **Rotation is never automatic in the agent's reach.** Only the sink operator rotates keys, and every rotation is recorded in the sink.

## Migration

1. **No change to existing logs.** HMAC-sealed audit logs stay HMAC-sealed. They are labelled `alg: HMAC-SHA256` in the verifier report. They are not re-signed, because re-signing would need the old key on the same host.
2. **New records.** From the first Ed25519 receipt onward, each record carries both its HMAC seal (for local continuity) and the sink receipt (for independent anchoring). The verifier requires the receipt for any record committed after the migration point.
3. **Migration point.** Recorded in the installation record as the first `seq` anchored with an Ed25519 receipt. Records before it are reported as `unanchored (legacy)`, as D2 AC-10 already requires.
4. **Rollback.** There is no rollback after the first Ed25519 receipt, because the registry and the migration point are then fixed. Before that point, the feature can be turned off by not configuring the sink.

## Consequences

- **Easier.** The sink can be a separate identity that holds its own private key, so a compromise of the service cannot forge receipts. Approvals can come from a device the agent cannot reach.
- **Harder.** One new dependency with native code. It must pass SlopSeal's own verification before it is installed (`verify_install`), and its exact version and hash are pinned. Key ceremonies are needed for the sink and approval keys.
- **Rejected alternatives.**
  - *HMAC receipts.* Rejected: the verifier holds the key, so the verifier can forge. This defeats the purpose of an external sink.
  - *ECDSA (P-256).* Rejected for v1: more implementation choices to get wrong (nonce handling, curve validation) than Ed25519, with no benefit here.
  - *PyNaCl (libsodium).* Acceptable alternative with the same algorithm and a smaller surface. Not chosen only because `cryptography` is the more widely reviewed library for the wider Python ecosystem. The owner may choose PyNaCl instead; the rest of this ADR is unchanged.
  - *RSA.* Rejected: larger keys and signatures, no advantage here.

## Owner decisions (recorded 2026-11-17)

- Library: `cryptography`, pinned to `50.0.2`.
- Rotation: 90 days per key. The 30-day overlap is unchanged from the earlier draft.
- The compromise path in "Key rotation" is the documented procedure for a suspected key compromise.

## Open decisions for the owner

1. Who holds the sink signing key, and where it is stored (links to the §15 "sink key enrolment" decision, which the owner will provide separately).
2. The sink ID format (also a §15 decision).

## Verification of this ADR

- The stdlib claim: Python 3.11's standard library has no Ed25519 implementation. Confirmed by the absence of an `ed25519` module in `hashlib`, `hmac`, and `secrets`, and by the project's own note in `pyproject.toml`.
- Library versions observed on the package index on 2026-11-17 (metadata only, nothing installed): `cryptography` 50.0.2, `pynacl` 1.6.2.
- Stdlib re-check on 2026-11-17 with Python 3.11.15: `ed25519`, `nacl`, and `cryptography` are all not importable in the base interpreter.
- OSV query for `cryptography` 50.0.2 (PyPI) on 2026-11-17 returned no known vulnerabilities.
- The pin is checked again at implementation time, because advisories can be published after this date.
