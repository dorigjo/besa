# Besa v1.1 Threat Model

Status: v1.1 protocol and self-hosted distribution. No independent third-party
security audit has been completed. This document describes technical properties,
not compliance or risk certification.

## Assets

- Trusted public keys, lifecycle state, and rotation/revocation artifacts.
- Encrypted signing keys and their passphrases.
- Frozen v1.0 signed manifests, receipts, rotations, and attestations.
- v1.1 Action Envelopes, delegations, capabilities, action evidence, and
  replay state.
- Hosted verifier availability and configured policy/trust inputs.
- Append-only evidence logs and supplied execution-result data.

## Trust boundaries

Inputs are untrusted until strict validation and cryptographic verification
succeed. The principal, agent, upstream identity system, policy authority,
capability issuer, executor, recorder, replay-store operator, hosted-verifier
operator, and independent verifier may all be different parties.

Cryptographic validity is not trust. A verifier must pin or otherwise obtain a
trusted public key through an authenticated out-of-band process. An executor
that can issue arbitrary capabilities with a trusted key has already crossed
the meaningful authorization boundary.

## Protected by the protocol

| Threat | Control |
|---|---|
| Action field substitution after issuance | Canonical Action Envelope hashing plus signed capability fields bind principal, agent, authority, tool, operation, resource, constraints hash, expiry, and nonce. |
| Capability/evidence modification | Domain-separated Ed25519 signatures over strict artifact bodies fail verification. |
| Signature-domain confusion | Each artifact has a distinct `besa:<domain>:v1` signature or hash domain. |
| Unknown security-sensitive fields | Strict schemas reject extensions rather than accepting ambiguous data. |
| Delegation widening | Chain verification requires child identity, operation, resource, scope, constraint, and time window to narrow the parent. |
| Expired action/capability/delegation use | Canonical timestamps and verification-time checks fail closed. |
| Untrusted, retired, or revoked issuer use | Trust-store checks reject keys according to artifact time and requested purpose. |
| MCP tool/argument substitution | `withBesaMcp` requires the action tool and request hash to equal the actual call. |
| Local in-process replay | An enforced replay store consumes action-hash-plus-nonce before handler execution. |
| Basic hosted HTTP abuse | Body/header bounds, timeouts, rate limits, method/content-type checks, query rejection, and non-sensitive error responses bound common request abuse. |
| Evidence-log path substitution | The local log rejects symlink/non-regular targets, uses no-follow where available, serializes in-process appends, and fsyncs records. |

## Detectable but not prevented by Besa alone

| Condition | What Besa can show | What it cannot stop |
|---|---|---|
| Executor lies about a result | A trusted recorder signed the supplied result hash and links. | An untrusted recorder fabricating an external effect. |
| Capability replay in another process or host | The nonce/action binding is visible in artifacts. | Reuse unless an external shared replay store atomically consumes it. |
| Post-write log manipulation | A deleted/altered record can be detected only if another copy, export, or external retention control exists. | An operator with filesystem authority deleting the sole local log. |
| Clock manipulation | Signed timestamps and local verification time are inspectable. | A compromised clock without an external trusted timestamp source. |
| Policy/key compromise | A resulting signed decision identifies its issuer. | A trusted compromised signer issuing malicious capabilities. |
| TOCTOU after admission | Capability expiry/nonce are bound before handler call. | A downstream executor ignoring the capability or changing its own semantics. |

## Requires customer control or external state

- Upstream agent authentication, identity truth, and authorization context.
- TLS termination, ingress filtering, reverse-proxy rate limits, DNS, and
  host/network isolation for `besa serve`.
- Secret delivery, key custody, rotation, revocation distribution, backup, and
  incident response.
- A durable atomic replay provider for multi-process or multi-host one-time use.
- Evidence-log retention, external archival, access control, and forensic
  correlation to real executor or payment-rail events.
- Policy review. A syntactically valid deterministic policy can still be too
  broad for the intended business risk.

## Out of scope

Besa does not provide IAM, OAuth, agent identity, MCP transport security, a
tool gateway, execution sandbox, payment processing, cloud authorization,
secrets management, malware detection, SIEM, monitoring platform, KYC, legal
review, compliance certification, or a Besa-operated cloud control plane.

It makes no claim that the EU AI Act, SOC 2, DORA, NIS2, or another framework
requires or is satisfied by Besa. Machine-verifiable artifacts may be useful
technical evidence in a customer-controlled audit or governance workflow.

## Hosted verifier threats

### Unauthenticated verification callers

Public verification and health endpoints are intentionally unauthenticated.
They receive bounded processing and default per-address rate limiting. Public
deployment still needs reverse-proxy controls because address-based in-process
limits cannot prevent distributed flooding and may see only a proxy address.

### Protected admission callers

`/v1/admit` and `/v1/actions/admit` require a 32-4096-character non-whitespace
bearer token. Compare is digest-based and timing-safe. Authentication does not
replace authorization: the signed Action Capability is the artifact binding the
exact action. Use a dedicated secret manager and rotate tokens; Besa does not
provide user accounts or token issuance.

### Signing-key process compromise

Keyless `--action-trust` verification avoids loading a private key. Admission
mode necessarily holds a decrypted signing key for process lifetime. Separate
that workload from untrusted executors and prefer independent key custody where
the deployment requires it. A compromised admission signer can issue trusted
capabilities until consumers revoke or replace its key.

### Input and parsing attacks

The protocol rejects non-finite values, non-canonical text, accessors, invalid
base64/key material, excessive canonical JSON, unknown fields, malformed JSON,
and bounded-but-invalid artifacts. Tests cover canonicalization, Unicode,
accessors, oversized input, nested input, key lifecycle, server request bounds,
and v1.1 conformance mutations.

## Security reporting

Use `SECURITY.md` for private reporting. Include version, deployment mode,
preconditions, reproduction steps, and actual versus expected behavior. Do not
include keys, tokens, customer actions, or sensitive evidence in public issues.
