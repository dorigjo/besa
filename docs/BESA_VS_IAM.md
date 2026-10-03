# Besa vs IAM

IAM and Besa answer different authorization questions.

| Layer | Primary question | Typical artifact |
|---|---|---|
| IAM / OAuth / workload identity | Who may authenticate and access a service or resource class? | Identity, role, token, cloud policy |
| Besa | May this exact consequential action execute under this exact contract? | Action Envelope, signed Action Capability, signed Action Evidence |
| EMA / ID-JAG / XAA-style composition | Which principal/client may obtain access to the target service? | Enterprise assertion exchanged for a service access token |
| Besa pre-execution extension | Whether this exact action was admitted under the supplied valid authority and exact policy version, with portable proof | Signed normalized authority and pre-execution admission receipt |

BESA does not replace enterprise identity or authorization systems.
It consumes verifiable authority and binds that authority to an exact
pre-execution decision, producing portable cryptographic evidence.

In the standards-oriented reference adapter, the application verifies the
exchanged access token and authenticated actor. Besa normalizes narrow grants,
checks principal/agent, issuer, service audience, exact resource/operation,
parameters, context, policy hash, validity and nonce, and signs the decision.
An ID-JAG/ID token is never accepted as a tool-execution capability. A workload
identity similarly requires a pinned subject and operator-assigned grants;
identity alone is not authorization. See [the adapter contract](RUNTIME_ADMISSION.md#external-identity-adapters).

## Where Besa sits

```mermaid
flowchart LR
  A[AI agent] --> I[IAM / OAuth]
  I --> B[Besa exact-action admission]
  B -->|ALLOW only| T[Privileged tool or API]
  T --> E[Signed action evidence]
```

Besa consumes identity and authority context established elsewhere. It does not
issue cloud credentials, authenticate workloads, evaluate an AWS IAM policy, or
replace least-privilege roles.

## Concrete boundary

An automation agent has valid AWS credentials and a role that can call a cloud
change service. Its signed Besa contract permits:

```text
agent:      agent:deploy-agent
operation:  deploy
resource:   environment:staging
commit:     abc123
expiry:     2026-09-23T19:00:00Z
```

The same authenticated agent requests:

```text
operation:  delete
resource:   database:production-db
```

IAM can correctly accept the identity and still leave the application with a
business-level authorization decision. Besa rejects this invocation because it
does not match the signed action contract. The protected handler is not called.

## What Besa adds

- A canonical hash for one proposed action, including resource and constraints.
- A signed allow or deny decision bound to that action, expiry, and nonce.
- Optional narrowing delegation between an authority and an agent.
- Replay consumption at the execution boundary when backed by an enforced
  replay store.
- Signed evidence linking the admitted action and supplied execution result.

These properties matter when authorization must cross identity providers,
agent frameworks, tools, or organizational boundaries and remain independently
verifiable afterward.

## When IAM is enough

Do not add Besa merely to duplicate a precise native policy. IAM or a cloud
provider's own authorization may be sufficient when it already binds every
relevant operation, resource, condition, expiry, and one-time-use requirement,
and no portable cryptographic evidence contract is needed.

Besa is not a claim that native cloud controls are weak. It is an additional,
provider-neutral execution contract for boundaries that need that portability.

IAM, XAA and runtime enforcement vendors can implement exact field matching,
scope translation, short-lived grants, replay consumption and pre-execution
checks. Those individual functions are not a unique moat. Besa's proposed
distinction is the signed, versioned artifact contract and independently
verifiable authority/policy/action links across operators. The usefulness of
that portability requires demonstrated external integrations; code quality
alone is not evidence of adoption or defensibility.

See [Architecture](../ARCHITECTURE.md), [Threat Model](THREAT_MODEL.md), and
[Runtime Admission](RUNTIME_ADMISSION.md).
