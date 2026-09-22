# Besa v1.1.0: Consequential Action Admission

Authentication tells a service who an agent is. It does not prove that this
exact consequential action was authorized under these exact constraints.

Besa v1.1.0 adds an additive protocol and runtime for that boundary:

```text
identity/authentication
  -> canonical Action Envelope
  -> deterministic policy + optional delegation
  -> signed ALLOW/DENY Action Capability
  -> guarded execution
  -> signed, linked Action Evidence
```

## Highlights

- Versioned Action Envelope, Delegation, Action Capability, and Action Evidence
  artifacts with strict schemas, bounded canonical JSON, domain-separated
  Ed25519 signatures/hashes, and stable reason codes.
- `withBesa` and `withBesaMcp` runtime wrappers that verify exact authorization,
  enforce configured replay guarantees, block signed denies, and record signed
  evidence after success or failure.
- A strict YAML/JSON action policy format with exact resource and constraint
  matching; no policy DSL, callbacks, or model-generated decisions.
- A self-hosted HTTP verifier with public-key-only full-chain verification,
  token-protected action admission, health/readiness, rate limits, request
  bounds, timeouts, secure headers, metrics, Docker deployment, and security
  failure tests.
- Positive and negative public conformance vectors, fuzz-style mutation tests,
  a reproducible benchmark harness, and four runnable consequence demos.

## Try it

```bash
npm install
npm run demo
npm run conformance
npm run benchmark
```

For a keyless self-hosted verifier:

```bash
npx besa serve --action-trust verifier-trust.json
```

For signed action admission, provision an encrypted key and bearer token, then:

```bash
npx besa serve \
  --trust verifier-trust.json \
  --action-policy examples/action-policy.yaml
```

See `docs/HOSTED_VERIFIER.md` before exposing the service beyond loopback.

## Compatibility

No migration is required for v1.0/v1.0.1 users. Frozen SignedManifest, Receipt,
KeyRotation, and AdmissionAttestation artifacts remain unchanged and continue
to verify. Existing CLI and SDK exports remain available; v1.1 is additive.

## Security boundaries

- No independent third-party audit has been completed.
- Global one-time execution requires a customer-owned atomic replay store; the
  built-in enforced store is process-local.
- Action Evidence proves a trusted recorder signed supplied linked data, not
  that an external payment, deletion, or deployment occurred in the real world.
- The hosted verifier is self-hosted. Operators own TLS, ingress, key custody,
  secret rotation, durable retention, monitoring, and incident response.
- Besa is not IAM, an MCP gateway, a payment rail, a sandbox, SIEM, or a
  compliance guarantee.

Review `SECURITY.md`, `docs/THREAT_MODEL.md`, `AUDIT_SCOPE.md`, `SPEC.md`, and
the conformance fixtures before using Besa on a production boundary.
