# Agent Gateway Integration

Besa is not an agent gateway, MCP router, identity provider, or tool host. It is
the exact-action admission and evidence primitive that an application places in
front of a consequence-bearing handler.

```text
agent request
  -> application authentication and identity context
  -> ActionEnvelopeV1
  -> Besa capability, delegation, expiry, and replay checks
  -> application-owned tool or API
  -> signed ActionEvidenceV1
```

The gateway remains responsible for transport authentication, TLS, routing,
timeouts, tool discovery, request cancellation, and the real side effect.

## Local enforcement

Use `withBesa(config, handler)` when the application already has an exact
`ActionEnvelopeV1`. The wrapper:

1. validates the action;
2. resolves and verifies its signed `ActionCapabilityV1`;
3. verifies a bound delegation chain when supplied or required;
4. atomically consumes replay state when enforcement is required;
5. rechecks expiry immediately before execution;
6. calls the handler only for a valid signed allow; and
7. signs and appends success or handler-failure evidence.

The wrapper performs no hidden network calls. Its capability resolver may call
a customer-operated admission service, load a local artifact, or use another
application-owned transport.

## MCP enforcement

Use `withBesaMcp(config, execute)` at the MCP tool execution boundary. It adds
two checks before delegating to `withBesa`:

- the Action Envelope `tool` must equal the actual MCP tool name; and
- `requestHash` must equal the canonical hash of the actual MCP arguments.

This prevents a capability for one tool or argument set from authorizing a
different call. See
[`examples/consequential-mcp-middleware.ts`](../examples/consequential-mcp-middleware.ts)
for the compile-checked reference integration.

## Independent admission service

Run the self-hosted verifier separately when the decision authority should not
share a process with the executor:

```text
gateway -> POST /v1/actions/admit -> signed ActionCapabilityV1
gateway -> withBesa / withBesaMcp -> tool execution -> ActionEvidenceV1
auditor -> POST /v1/verify/* -> independent verification
```

`POST /v1/actions/admit` requires an explicit action policy, trust store,
existing encrypted signing key, and bearer token. A keyless verifier can run
with `besa serve --action-trust verifier-trust.json`. Besa v1.1 does not operate
a public hosted instance. See [HOSTED_VERIFIER.md](HOSTED_VERIFIER.md).

## Replay and retries

An action nonce is cryptographically bound but is not globally one-time by
itself. `InMemoryReplayStore` protects one process until expiry. A distributed
gateway must provide an atomic shared `ReplayStore` and use
`replayRequirement: "enforce"`.

Once replay state has been consumed, do not blindly retry after an ambiguous
tool, evidence-creation, or evidence-append failure. The side effect may have
happened even when the caller received an error.

## Trust separation

Strong deployments separate these roles where practical:

| Role | Responsibility |
|---|---|
| Identity system | Authenticates the principal and agent upstream. |
| Decision authority | Applies policy and signs Action Capabilities. |
| Executor | Performs the exact approved tool or API action. |
| Evidence recorder | Signs the supplied result linkage. |
| Verifier | Uses pinned public trust to verify artifacts independently. |
| Replay-store operator | Provides atomic one-time consumption guarantees. |

A process that can sign its own authorization or evidence is not independent
of itself. Cryptographic validity establishes origin and integrity only; the
verifier still decides which public keys and operators it trusts.

## Legacy skeleton

`examples/agent-gateway/server.ts` remains a compatibility example for the v1.0
SignedManifest and non-consuming `admit()` flow. It has no authentication, TLS,
durable metering, real tool forwarding, or signed exact-action evidence. Do not
use that skeleton as the v1.1 production integration; use the wrappers and
self-hosted verifier described above.
