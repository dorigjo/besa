# Authentication is not authorization for this exact agent action

AI agents increasingly call APIs that deploy code, mutate infrastructure,
change permissions, send messages, or move money. Most production systems
already have identity and authorization controls. The remaining question is
narrower:

> May this exact operation execute on this exact resource, with these exact
> arguments and constraints, before this expiry, under this delegation?

Besa is an open-source TypeScript implementation of a small protocol for that
boundary. It is not an identity provider, agent framework, gateway, payment
rail, or monitoring platform.

## A concrete failure boundary

Assume an automation agent has valid AWS credentials and may reach an internal
cloud-change tool. Its approved contract is:

```text
agent:       agent:deploy-agent
operation:   deploy
resource:    environment:staging
commit:      abc123
expiry:      2026-09-23T19:00:00Z
```

The same authenticated process requests:

```text
operation:   delete
resource:    database:production-db
```

This is not an authentication failure. It is not necessarily a transport or
tool-discovery failure either. It is an exact-action authorization mismatch.
At the execution boundary Besa returns:

```text
DENY
ACTION_NOT_GRANTED
executor called: no
```

The reason code matters. Calling this a generic constraint violation would make
the screenshot cleaner but would misrepresent the evaluator: no policy rule
grants the requested delete operation.

## Where the boundary sits

```text
Agent
  -> IAM / OAuth / MCP authentication and server authorization
  -> Besa exact-action admission
  -> consequence-bearing handler
  -> signed action evidence
```

IAM remains responsible for identity, roles, credentials, and cloud access.
MCP remains responsible for transport, discovery, sessions, and its own server
authorization. Besa consumes that context; it does not recreate it.

## Three protocol artifacts

### 1. Action Envelope

`ActionEnvelopeV1` canonically describes one proposed action. It binds the
principal, agent, tool, operation, resource, scopes, constraints, request hash,
risk class, expiry, nonce, and authority.

### 2. Action Capability

`ActionCapabilityV1` is a signed allow or deny decision for the exact Action
Envelope hash. It carries the policy and reason code and cannot be reused for a
different resource, argument set, expiry, or nonce without invalidating the
cryptographic link.

### 3. Action Evidence

`ActionEvidenceV1` links the allowed action and capability to the supplied
execution result and recorder signature. A verifier with configured trust
anchors can check those links independently of the executor's private log
format.

Evidence is deliberately not described as proof that an external side effect
occurred. It proves that the configured recorder signed the supplied result.
Claims about an AWS deletion, database commit, or payment settlement depend on
where that recorder runs and whether it independently observes the event.

## Runtime admission

The SDK wrapper is placed immediately before the handler:

```ts
const execute = withBesa(besaConfig, async (action) => {
  return deployExactCommit(action.constraints);
});

const { result, evidence } = await execute(actionEnvelope);
```

Before calling the handler, `withBesa` validates the action, verifies issuer
trust and the signed capability, validates optional narrowing delegation, and
consumes replay state. It fails closed when an enforced replay guarantee cannot
be met. Success and handler failure produce signed evidence; a signed deny does
not call the handler.

The runtime configuration is explicit because trust anchors, key custody,
capability resolution, replay storage, and evidence storage are security
decisions. The project provides small generic HTTP and MCP boundary adapters but
does not hide those responsibilities behind global state.

## Try the real path

```bash
npm install @dorigjo/besa
npx besa demo
```

The demo generates Ed25519 keys in memory, signs an exact capability, blocks the
production-delete handler, runs the matching staging-deploy mock, records signed
evidence, and verifies it. It does not contact AWS or mutate infrastructure.

## MCP calls

`withBesaMcp` additionally checks that the Action Envelope's tool equals the
actual MCP tool name and that `requestHash` equals the canonical hash of the
actual arguments. Place it after normal MCP authentication and immediately
before the privileged tool implementation.

This is complementary to MCP authorization, not a claim that MCP can only
express coarse access. If one MCP server already binds every material argument,
resource, expiry, delegation, and replay condition and no portable signed
artifact is needed, adding Besa may only add complexity.

## Reproducible local performance

The v1.1 reference run used Node 24 on an Intel Core i3-1005G1 with 250 measured
samples after warmup. It reported:

| Operation | Median | p95 |
|---|---:|---:|
| Evaluate action policy | 51.85 us | 81.98 us |
| Verify action capability | 583.21 us | 741.05 us |
| Verify delegation, capability, and evidence | 3.12 ms | 6.31 ms |

These are local cryptographic/policy measurements, not hosted-service latency
or an SLA. They exclude network transit, persistent replay I/O, key generation,
and application execution. The benchmark prints the machine and methodology and
can be reproduced with `npm run benchmark`.

## Trust and security limits

- No independent third-party security audit has been completed.
- Cryptographic validity does not establish that a public key should be trusted.
- Local encrypted key files are not HSM-backed keys.
- Distributed replay prevention requires a customer-owned atomic store.
- The append-only JSONL sink is not an immutable ledger.
- The self-hosted verifier does not supply TLS, identity management, global
  revocation, hosted retention, or a public Besa cloud.
- Correct mapping from a business action to the Action Envelope remains an
  application responsibility.

The repository includes the specification, threat model, audit scope, internal
security review, frozen positive and negative vectors, conformance tests, and
SBOM command so these claims can be inspected rather than trusted.

## Why a separate protocol?

A cloud provider, identity vendor, MCP gateway, or application can build the
same check natively. Besa's case is not exclusive policy logic. It is a stable,
provider-neutral artifact contract that a different issuer, executor, recorder,
or verifier can implement and verify.

That case remains unproven until multiple independent systems use the same
artifacts. Besa may remain a useful product feature rather than become a shared
protocol. External integrations and interoperability are the evidence that
would decide the question; repository polish cannot.

## Source and review material

- Repository: https://github.com/dorigjo/besa
- npm: https://www.npmjs.com/package/@dorigjo/besa
- [Specification](../../SPEC.md)
- [Threat model](../THREAT_MODEL.md)
- [Security credibility](../SECURITY_CREDIBILITY.md)
- [Benchmarks](../BENCHMARKS.md)
- [Besa vs IAM](../BESA_VS_IAM.md)
- [Besa vs MCP Auth](../BESA_VS_MCP_AUTH.md)

Technical criticism of the trust model, artifact split, replay boundary, and
integration cost is more useful than launch engagement.
