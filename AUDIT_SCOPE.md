# Besa v1.1 Audit Scope

Status: no independent third-party security audit has been completed for this
release. This file is a review map, not an audit attestation.

## Review objective

Determine whether Besa v1.1 correctly provides cryptographically verifiable
pre-action admission and post-action evidence for the exact artifacts supplied
to it, under the documented trust assumptions.

## In scope

### Cryptographic formats and canonicalization

- `src/crypto.ts`: JSON safety bounds, canonical serialization, SHA-256, key
  parsing, Ed25519 message construction, and domain separation.
- Frozen v1.0 artifacts: signed manifests, receipts, rotations, and admission
  attestations. Their bytes and domains must not change.
- v1.1 artifacts: `ActionEnvelopeV1`, `DelegationV1`, `ActionCapabilityV1`,
  and `ActionEvidenceV1` in `src/action.ts`, `src/delegation.ts`,
  `src/action-capability.ts`, and `src/action-evidence.ts`.
- Cross-artifact binding: action hash, constraint hash, delegation-chain hash,
  capability hash, supplied-result hash, issuer/recorder key IDs, expiry, and
  nonce.

### Admission and runtime enforcement

- `src/action-policy.ts`: strict parsing and deterministic allow/deny rules.
- `src/replay.ts`: verification-only versus enforced semantics, atomic local
  consumption, bounded capacity, expiry, and failure behavior.
- `src/runtime.ts` and `src/mcp.ts`: validation order, capability resolution,
  replay consumption before execution, handler isolation, and evidence append.
- `src/server/hosted-verifier.ts`: request bounds, authorization boundary,
  trust-store usage, rate limit, timeouts, response headers, readiness, and
  action admission/verification routes.

### File and operational safety

- Key, trust, policy, meter, and evidence-log path handling, including
  symlink behavior and write ordering.
- Dockerfile and CI checks for non-root runtime, dependency install scripts,
  shipped package contents, and reproducible local verification commands.

## High-value adversarial cases

1. Change any security-relevant action field after capability signing.
2. Substitute a production resource, transfer amount, or MCP argument.
3. Broaden a signed delegation while preserving a plausible chain shape.
4. Reuse a valid nonce across concurrent runtime calls.
5. Supply a malformed, revoked, retired, substituted, or non-Ed25519 key.
6. Exploit Unicode normalization, accessors, prototype-like properties,
   non-finite values, deeply nested JSON, or oversized input.
7. Bypass admission routes through missing/invalid bearer tokens, HTTP method,
   content type, request target, timeout, or rate-limit edge cases.
8. Corrupt, truncate, race, or symlink an append-only evidence log.

## Evidence available to reviewers

- `conformance/golden-v1.json`: frozen v1.0 public verification vectors.
- `conformance/consequential-action-v1.json`: frozen v1.1 positive chain.
- `conformance/consequential-action-negative-v1.json`: stable failure cases.
- `npm run conformance`, `npm test`, `npm run smoke`, `npm run smoke:server`,
  `npm run test:examples`, `npm run test:package`, and `npm run benchmark`.
- `SPEC.md`, `ARCHITECTURE.md`, `SECURITY.md`, and `docs/THREAT_MODEL.md`.
- `docs/V1_1_SECURITY_REVIEW.md`: internal four-perspective findings,
  mitigations, residual risks, and release disposition.

## Explicitly out of scope

- Correctness or security of upstream IAM/OAuth/MCP authentication.
- Truthfulness of identities or execution results supplied by a caller.
- Payment settlement, cloud authorization, tool implementation, sandboxing,
  secrets management, malware detection, legal compliance, and SIEM retention.
- Availability, durability, and global uniqueness of a replay store not owned
  and operated by the Besa deployment.
- A Besa-operated cloud service; v1.1 is self-hosted only.

## Reporting

Report vulnerabilities privately using the channel in `SECURITY.md`. Include a
minimal reproducer, affected version, expected and actual behavior, and any
conditions required to exploit the issue. Do not publish secrets, private keys,
or customer evidence in a public issue.
