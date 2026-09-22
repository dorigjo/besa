# Besa

**Cryptographic admission and evidence for consequential AI-agent actions.**

Authenticate the agent elsewhere. Besa decides whether this exact action may
execute under these exact constraints, then leaves independently verifiable
evidence of the decision and supplied result.

[![CI](https://github.com/dorigjo/besa/actions/workflows/ci.yml/badge.svg)](https://github.com/dorigjo/besa/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@dorigjo/besa)](https://www.npmjs.com/package/@dorigjo/besa)

```text
Agent / automation
        |
existing identity + authentication
        |
        v
      Besa  <--- exact action boundary
        |
deterministic ALLOW / DENY + signed capability
        |
        v
Tool / API / database / deployment / external payment rail
        |
signed, linked action evidence
```

Besa is a small TypeScript protocol implementation, CLI, SDK, and self-hosted
HTTP verifier. Local use needs no account and no remote Besa service.

## 30-second demo

```bash
git clone https://github.com/dorigjo/besa
cd besa
npm install
npm run demo
```

The demo runs four concrete paths:

```text
Production deployment (unreviewed commit): DENY CONSTRAINT_VIOLATION
Production deployment (approved commit): ALLOW <signed capability>
Destructive database delete (staging): ALLOW <signed capability>
Destructive database delete (production): DENY RESOURCE_NOT_GRANTED
External payment rail mock (EUR 100 to merchant-123): ALLOW <signed capability>
MCP authentication: accepted by the example transport
Privileged MCP action: DENY ACTION_NOT_GRANTED
```

It then verifies the linked action evidence. Nothing moves money, deploys code,
or touches a database; those are explicit mock execution boundaries.

## Why authentication is not enough

Authentication can establish that `agent:release` reached a service. A broad
cloud or MCP permission may establish that it can call a deployment tool.
Neither answers:

```text
May this agent deploy commit abc123 from repository dorigjo/besa
to production, with risk <= 20, before this expiry, exactly once?
```

Besa represents that question as a canonical Action Envelope. A deterministic
policy produces a signed Action Capability for the exact hash, resource,
constraints, expiry, and nonce. The runtime verifies it immediately before the
handler and records signed evidence afterward.

## Why a separate protocol

A cloud provider, identity vendor, MCP gateway, or customer can implement the
same control in its own stack. Besa's useful boundary is not exclusive code; it
is a provider-neutral artifact contract that can cross identity systems, agent
frameworks, tools, and execution rails. Frozen formats, public conformance
vectors, and keyless verification let a different party verify the decision
without trusting the executor's private log format.

That value depends on correct integration and real adoption. v1.1 is an
unaudited open-source implementation and conformance surface, not an industry
standard, certification, or claim that vendor-native controls are insufficient
for every deployment.

## Install

```bash
npm install @dorigjo/besa
```

Requires Node.js 20 or later and uses ESM modules.

## The v1.1 protocol

| Artifact | Purpose |
|---|---|
| `ActionEnvelopeV1` | Canonical proposed action: principal, agent, tool, operation, resource, request hash, scopes, constraints, expiry, nonce, and risk. |
| `DelegationV1` | Signed, narrowing authority from a trusted root to an agent. A child cannot broaden its parent. |
| `ActionCapabilityV1` | Signed allow or deny bound to the exact action and policy decision. |
| `ActionEvidenceV1` | Signed link from action and allow capability to the supplied execution result. |

All artifacts use strict schemas, bounded canonical JSON, SHA-256 identities,
domain-separated Ed25519 signatures, and stable machine-readable reason codes.
See [SPEC.md](SPEC.md) and the immutable vectors in [conformance/](conformance/).

## Runtime integration

`withBesa` sits immediately before the consequence-bearing handler:

```ts
import {
  AppendOnlyEvidenceLog,
  InMemoryReplayStore,
  withBesa,
} from "@dorigjo/besa";

const execute = withBesa(
  {
    trustStore,
    capability: getCapabilityForExactAction,
    replayStore: new InMemoryReplayStore(),
    replayRequirement: "enforce",
    evidenceKeyPair: recorderKeyPair,
    evidenceSink: new AppendOnlyEvidenceLog("./evidence.jsonl"),
    recorderId: "recorder:production",
    executorId: "deployment:primary",
    requireDelegation: true,
    delegationChain,
  },
  async (action) => deployExactCommit(action.constraints),
);

const { result, capability, evidence } = await execute(actionEnvelope);
```

Before calling the handler, the wrapper validates the action, verifies issuer
trust and the exact capability, checks optional delegation, and consumes replay
state. A signed deny never executes. Success and handler failure both generate
signed evidence. See [Runtime Admission](docs/RUNTIME_ADMISSION.md).
See also [Agent Gateway Integration](docs/AGENT_GATEWAY.md) for deployment
boundaries and [Evidence Artifacts](docs/EVIDENCE_ENVELOPE.md) for independent
verification semantics.

`InMemoryReplayStore` enforces one-time use only inside one process. Use a
customer-owned atomic `ReplayStore` for durable or distributed replay
protection. Besa fails closed when `replayRequirement: "enforce"` cannot be met.

## MCP reference integration

`withBesaMcp` additionally binds the Action Envelope's tool and request hash to
the actual MCP call. Place it after normal transport authentication and before
the tool implementation.

The minimal typed adapter is in
[examples/consequential-mcp-middleware.ts](examples/consequential-mcp-middleware.ts).
Besa is not an MCP server, router, or control plane.

## Self-hosted Hosted Verifier

Run public signature and Action Envelope verification locally:

```bash
npx besa serve --port 8787
```

Run keyless, trust-aware capability/delegation/evidence verification:

```bash
npx besa serve --action-trust verifier-trust.json
```

Enable token-protected Action Capability issuance from a strict policy:

```bash
export BESA_KEY_PASSPHRASE="<secret-manager-value>"
export BESA_ADMISSION_TOKEN="<high-entropy-bearer-token>"
npx besa serve \
  --trust verifier-trust.json \
  --action-policy examples/action-policy.yaml
```

The server includes `/health`, `/ready`, `/metrics`, bounded JSON bodies and
headers, timeouts, a default 120 requests/minute per-address limit, secure
response headers, structured metadata-only logs, and constant-time bearer-token
comparison. Admission is never enabled without explicit trust, policy, key, and
token configuration.

The repository also ships a non-root, read-only-tested Docker image definition.
See [Hosted Verifier](docs/HOSTED_VERIFIER.md) for endpoints, container commands,
secrets, reverse-proxy requirements, and failure behavior. v1.1 ships no public
Besa-operated instance.

## Consequential-action examples

| Scenario | Exact boundary demonstrated |
|---|---|
| Production deployment | Repository, environment, commit, risk, and expiry are bound before execution. |
| Destructive database action | A staging grant cannot be reused for production. |
| Financial action | Amount and recipient are admitted before an external mock rail; Besa is not the rail. |
| Privileged MCP tool | Normal authentication succeeds while the exact high-consequence call is denied. |

Run all four with `npm run demo`.

## Deployment trust models

- **Local:** SDK and executor share an operator. Fastest integration, weakest
  separation of duty.
- **Customer-controlled gateway:** admission runs in customer infrastructure
  immediately before execution. The customer owns keys, TLS, policy, replay,
  evidence retention, and availability.
- **Independent admission service:** a separately controlled process issues
  capabilities, keeping the decision key away from the executor. This is the
  strongest separation and the largest operational responsibility.

See [ARCHITECTURE.md](ARCHITECTURE.md) for component and trust boundaries.

## What Besa is not

Besa does not replace:

- IAM, OAuth, SSO, agent identity, or MCP authentication
- cloud permissions or application authorization
- MCP orchestration, a generic gateway, or an agent framework
- a wallet, payment processor, payment network, KYC, or settlement system
- SIEM, observability, tracing, prompt scanning, or model monitoring
- a sandbox, secret manager, malware detector, or data-loss-prevention system
- legal review, policy ownership, evidence retention, or compliance programs

It sits after identity context exists and immediately before the consequential
action.

## Security and limitations

Besa provides tamper-evidence, not secrecy. Cryptographic validity is not trust;
verifiers must configure trusted public keys. `ActionEvidenceV1` proves that a
trusted recorder signed the supplied links and result hash. It does not prove a
real-world side effect occurred unless that recorder is independently trusted
to observe it.

No independent third-party security audit has been completed. Local encrypted
keys are not an HSM. The JSONL evidence sink is not an immutable ledger. There
is no external trusted timestamp authority, central revocation distribution,
hosted retention, public cloud service, or global replay database.

Besa does not guarantee regulatory compliance. Its artifacts may be useful
technical evidence in customer-controlled security, governance, or audit
workflows. Read [SECURITY.md](SECURITY.md),
[the threat model](docs/THREAT_MODEL.md),
[the v1.1 security review](docs/V1_1_SECURITY_REVIEW.md), and
[AUDIT_SCOPE.md](AUDIT_SCOPE.md) before using it on a production boundary.

## Conformance and benchmarks

```bash
npm run conformance
npm run benchmark
```

The conformance command verifies frozen v1.0 artifacts plus v1.1 positive and
negative vectors. The benchmark measures canonicalization, action hashing,
capability verification, policy admission, and full action-chain verification;
it reports Node/OS/CPU, methodology, iterations, median, p95, and p99. Numbers
are machine-specific and are never hard-coded as a performance promise. See
[the v1.1 reference run](docs/BENCHMARKS.md) for reproducible baseline results.

## Legacy v1 compatibility

The existing manifest/tool CLI and signed formats remain supported:

```bash
export BESA_KEY_PASSPHRASE="your-passphrase-at-least-16-bytes"
npx besa keys
npx besa load examples/manifest.yaml
npx besa sign examples/manifest.yaml
npx besa verify examples/manifest.signed.json
npx besa admit examples/manifest.signed.json crm.lookup
npx besa receipt crm.lookup examples/manifest.signed.json \
  --request examples/request.json
npx besa verify-receipt .besa/receipts/<id>.json \
  examples/manifest.signed.json --request examples/request.json
```

The frozen receipt shape remains:

```json
{
  "artifactVersion": 1,
  "receiptId": "rcpt_2d7942c7-8f70-4984-9c3f-24876acfd860",
  "manifestHash": "ea7e9ca22d199f40281cdf9e5d6145440c6c7d6bfbe94157c4b1da5527054410",
  "toolName": "crm.lookup",
  "decision": "allow",
  "reasonCode": "ALLOWED",
  "timestamp": "2026-06-19T10:00:00.000Z",
  "requestHash": "b27b80d1227c167a6fca199778645daa77d20a8087782fc48802d11d6281c920",
  "publicKeyId": "f68668614543c4896cf8cee418492f1a4df1f1acdba8850f94728b8a94cf90fe",
  "algorithm": "ed25519",
  "signature": "<base64-ed25519-signature>"
}
```

Migration from v1.0/v1.0.1: **none required**. Adopt the new action artifacts
only where an exact consequential-action boundary is needed.

## Development and release gates

```bash
npm ci
npm run build
npm test
npm run conformance
npm run test:examples
npm run test:docs
npm run smoke
npm run smoke:server
npm run test:package
npm run verify:package-surface
npm audit --omit=dev
```

CI runs Node 20, 22, and 24 and builds/runs the container read-only. See
[CONTRIBUTING.md](CONTRIBUTING.md) for protocol change rules.

## License

[MIT](LICENSE)
