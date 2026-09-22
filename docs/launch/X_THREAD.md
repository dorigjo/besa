# Besa v1.1.0 X thread

1/ Authentication tells you who the agent is. It does not prove that this exact
consequential action was authorized under these exact constraints. Besa v1.1.0
is an open protocol and TypeScript implementation for that boundary.

2/ The flow is deliberately narrow:

```text
identity -> exact action -> deterministic policy -> signed ALLOW/DENY
-> guarded execution -> signed linked evidence
```

3/ An Action Capability binds principal, agent, tool, operation, resource,
request hash, constraints, expiry, nonce, policy, and optional delegation. A
staging authorization cannot be reused for production. EUR 100 cannot become
EUR 10,000 without verification failing.

4/ v1.1 adds narrowing delegation chains, explicit replay-store modes,
`withBesa`, an MCP adapter, signed Action Evidence, conformance vectors,
fuzz-style tests, benchmarks, and four consequence demos.

5/ The Hosted Verifier is fully self-hosted: keyless trust-aware verification
or token-protected signed admission, plus health/readiness, request bounds,
timeouts, default rate limits, secure headers, Docker, and security failure
tests. No Besa-operated cloud instance is part of this release.

6/ Existing v1 manifests, receipts, rotations, attestations, CLI behavior, and
SDK exports remain compatible. Migration: none required.

7/ Boundaries matter: Besa is not IAM, an MCP gateway, a payment rail, or proof
that a real-world side effect occurred. Distributed one-time use requires a
customer-owned atomic replay store. No independent security audit yet.

8/ Run it:

```bash
npm install
npm run demo
npm run conformance
```

https://github.com/dorigjo/besa
https://www.npmjs.com/package/@dorigjo/besa
