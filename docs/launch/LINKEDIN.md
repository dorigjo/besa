# Besa v1.1.0

Authentication tells you who the agent is.

It does not prove that this exact consequential action was authorized under
these exact constraints immediately before execution.

Besa v1.1.0 adds a small cryptographic protocol and TypeScript implementation
for that boundary:

```text
identity/authentication
  -> exact Action Envelope
  -> deterministic ALLOW/DENY
  -> signed Action Capability
  -> guarded execution
  -> signed linked Action Evidence
```

The release includes narrowing delegation chains, explicit replay-store modes,
SDK and MCP runtime wrappers, four consequence demos, public conformance
vectors, fuzz-style tests, reproducible benchmarks, and a self-hosted Hosted
Verifier with Docker deployment, health/readiness, secure request defaults, and
token-protected admission.

Existing v1 manifests, receipts, rotations, attestations, CLI behavior, and SDK
exports remain compatible. No migration is required.

Besa is not IAM, a payment processor, an MCP gateway, or a compliance
guarantee. There has not been an independent third-party security audit. The
repository includes the specification, threat model, audit scope, and immutable
vectors so the claims can be reviewed directly.

Repository: https://github.com/dorigjo/besa
npm: https://www.npmjs.com/package/@dorigjo/besa
