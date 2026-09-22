# Besa v1.1 Internal Security Review

**Review date:** 2026-09-22
**Scope:** v1.1 exact-action protocol, runtime/MCP wrappers, replay contract,
evidence sink, self-hosted HTTP verifier, Docker distribution, compatibility,
package surface, tests, and release documentation.

This is a maintainer-performed adversarial review, not an independent
third-party security audit. No certification or formal verification is implied.

## Method

The review traced attacker-controlled values from JSON/YAML, SDK calls, MCP
calls, and HTTP requests through canonicalization, hashes, signatures, trust
checks, policy, delegation, replay consumption, handler execution, evidence,
storage, packaging, and deployment. It also checked frozen v1 compatibility,
failure ordering, asynchronous time boundaries, configuration startup failure,
resource bounds, and public documentation claims.

## Findings resolved for v1.1

| ID | Severity | Finding | Resolution and evidence |
|---|---|---|---|
| V11-01 | High | A capability issued by an asynchronous resolver after wrapper entry was checked against the stale pre-resolution time and could be rejected as not active. | Runtime now checks at a fresh post-resolution time and again immediately before execution. Regression tests cover fresh issuance and expiry during replay I/O. |
| V11-02 | High | A successful handler returning non-canonical result data could be misclassified and signed as a handler failure. | Handler execution and evidence creation have separate error paths. `EVIDENCE_CREATION_FAILED` never creates false failure evidence. |
| V11-03 | Medium | Invalid bearer-token attempts returned before the in-process rate limiter and did not consume a request budget. | Limiting now runs before authentication. A real HTTP regression test expects `401`, `401`, then `429`. |
| V11-04 | Medium | New artifact schemas compared fingerprints of canonical Base64 without first proving embedded bytes were Ed25519 SPKI. A leaf delegation could therefore carry unusable subject-key bytes. | Delegation, capability, and evidence validation now parse every embedded key as Ed25519 before accepting its key ID. |
| V11-05 | Medium | A huge sparse JavaScript array could force canonicalization to iterate billions of holes before reaching the node limit. | Declared array length is checked against remaining canonical node budget before traversal. |
| V11-06 | Medium | Delegation-chain length was not explicitly bounded for local SDK callers. | Chains above 64 entries fail with `SCHEMA_DELEGATION_INVALID` before signature work. |
| V11-07 | Medium | Programmatic Hosted Verifier startup did not validate all nested trust stores or the legacy admission keypair. | All admission, action, delegation, and top-level security configuration now fails before `listen()`. |
| V11-08 | Low | Action scope ordering used locale collation while policy/delegation used deterministic code-unit ordering. | All protocol list ordering is locale independent; a Unicode regression test protects it. |
| V11-09 | Low | HTTP JSON decoding replaced malformed UTF-8 bytes, which could change the value that was subsequently validated or signed. | Request JSON now uses fatal UTF-8 decoding; malformed byte sequences receive `400`. |
| V11-10 | Release blocker | The v1 upgrade smoke archived moving `HEAD`; after the release commit it would build v1.1 as the supposed v1.0.1 fixture and fail CI. | The smoke pins immutable commit `082157830006d8497bf2ba5c162e8503772b4a9b`; CI fetches history for that job. |

No known Critical or High finding remains open in this internal review.

## Review A: Security engineer

The protocol binds action identity, principal, agent, declared authority, tool,
operation, resource, request hash, scopes, constraints, expiry, nonce, risk,
and optional context through strict canonical hashing. Capabilities redundantly
bind critical fields and are domain-separated Ed25519 signatures. Delegation
requires trusted root issuance, exact parent linkage, and monotonic narrowing.

The review attempted field substitution, signature/key substitution, malformed
key parsing, unknown fields, non-finite values, accessor input, sparse-array
resource exhaustion, chain widening, expiry races, replay, MCP argument/tool
substitution, evidence-link substitution, malformed UTF-8, oversized HTTP
bodies, and token-rate-limit bypass. The resulting fixes are listed above.

## Review B: OSS developer

README-first integration exposes one narrow path: build an Action Envelope,
resolve a capability, wrap the consequence-bearing handler, and retain signed
evidence. The public SDK exports the required types and functions. The MCP
adapter and policy/environment examples compile against the public package.
Self-hosted deployment, trust boundaries, evidence semantics, reason codes,
conformance vectors, benchmark method, contribution rules, and migration are
linked from the repository entry point.

Remaining developer burden is intentional: the application must supply true
identity context, exact resource semantics, policy ownership, key trust,
durable replay where needed, and an evidence retention destination.

## Review C: Platform engineer

The verifier has loopback-by-default host binding, health/readiness endpoints,
bounded body and headers, request/header/keep-alive timeouts, strict media type
and UTF-8 handling, fixed-label metrics, metadata-only logs, per-address rate
limits, token-protected admission, and keyless verification mode. The container
uses a pinned two-stage Node image, runs as `node`, and is CI-tested with a
read-only root filesystem.

The service deliberately does not provide TLS, distributed abuse prevention,
secret management, HSM custody, persistence, HA, global replay, retention, or
monitoring. Operators must supply those controls. In-process rate limits and
metrics reset on restart and may observe only a reverse proxy address.

## Review D: Short seller

AWS, Microsoft, Okta, an MCP gateway vendor, or a customer can implement this
logic themselves. Besa has no defensible claim that the algorithms are
exclusive, that vendor-native authorization is universally insufficient, or
that v1.1 is already an adopted standard.

The credible reason for a separate project is narrower: a provider-neutral,
portable artifact contract with strict formats, public conformance vectors,
independent keyless verification, and reference middleware that can span
identity systems, agent frameworks, tools, and execution rails. Whether that
becomes valuable depends on ecosystem adoption and trustworthy integrations;
the repository now states this limitation directly.

## Residual risk

- No independent third-party audit, formal proof, production history, or public
  Besa-operated service exists.
- Upstream identity and declared authority are supplied by the integrator. Besa
  does not authenticate an agent or prove possession of an identity credential.
- A trusted decision key can issue malicious capabilities; a trusted recorder
  can sign false supplied results.
- Local encrypted keys are not HSM-backed. Admission mode holds decrypted key
  material in process memory.
- In-memory replay is process-local and restart-volatile. Global one-time use
  requires a customer-operated atomic durable store.
- The JSONL sink is not an immutable ledger. A filesystem administrator can
  delete or replace the only copy.
- Signed timestamps rely on local clocks and are not externally timestamped.
- Side effects may have occurred when result capture, evidence creation, or
  evidence append fails. Blind retries are unsafe.
- Public deployment needs external TLS, ingress controls, distributed rate
  limiting, monitoring, backups, and incident response.

## Release disposition

The internal review found no known open release-blocking protocol defect after
the mitigations above. Release remains contingent on every command in
`docs/RELEASE_CHECKLIST.md`, remote CI including the Docker job, dependency
audit, package dry-run, registry authentication, and post-publication registry
verification.
