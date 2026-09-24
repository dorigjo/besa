# Besa security credibility

Besa is security-sensitive infrastructure. Evaluate the implementation and its
deployment boundary rather than relying on project claims.

> **No independent third-party security audit has been completed.**

The v1.1 review is an internal adversarial review, not a certification,
penetration test, or external audit.

## Reviewable evidence

| Surface | Repository evidence |
|---|---|
| Protocol contract | [SPEC.md](../SPEC.md) |
| Architecture and trust boundaries | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| Threat model | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Audit boundaries | [AUDIT_SCOPE.md](../AUDIT_SCOPE.md) |
| Internal security review | [V1_1_SECURITY_REVIEW.md](V1_1_SECURITY_REVIEW.md) |
| Frozen positive and negative vectors | [`conformance/`](../conformance/) |
| Conformance tests | `npm run conformance` |
| Full test suite | `npm test` |
| Package SBOM | `npm run sbom` |
| Dependency audit | `npm audit --omit=dev` |

The protocol uses bounded strict schemas, canonical JSON, SHA-256 hashes,
domain-separated Ed25519 signatures, explicit artifact versions, configured
trust anchors, stable reason codes, and fail-closed runtime checks.

## Important limitations

- Cryptographic validity is not trust. Verifiers must configure the correct
  public keys and operate revocation and rotation deliberately.
- Local encrypted key files are not HSM-backed keys. Production key custody is
  an operator responsibility.
- Replay prevention requires an enforced atomic `ReplayStore`. The in-memory
  store only protects one process and loses state on restart.
- Signed evidence proves that a trusted recorder signed the supplied result and
  artifact links. It does not independently prove an external side effect.
- The append-only JSONL sink is not an immutable ledger or retention service.
- The self-hosted verifier does not provide TLS termination, a public Besa
  cloud, identity management, global revocation, or a global replay database.
- Besa is not a compliance certification and does not make an execution safe.

## Hosted verifier boundary

Verification endpoints are keyless. Admission is disabled unless the operator
explicitly supplies trust, policy, signing key, and bearer-token configuration.
The operator remains responsible for TLS, ingress controls, secret management,
durable replay state, evidence retention, monitoring, and availability.

See [Hosted Verifier](HOSTED_VERIFIER.md) for deployment details and
[SECURITY.md](../SECURITY.md) for vulnerability reporting.
