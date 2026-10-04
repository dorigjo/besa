# Besa v1.2 Threat Model

## Pre-execution admission boundary

BESA decides whether a protected agent action may execute and produces
portable evidence of that decision. It does not merely detect malicious
behavior after execution.

BESA does not replace enterprise identity or authorization systems.
It consumes verifiable authority and binds that authority to an exact
pre-execution decision, producing portable cryptographic evidence.

For protected tools using `withPreExecutionAdmission`, the order is intent,
authority verification, deterministic policy, signed admission receipt,
verified receipt storage, enforced replay consumption, final verification,
then executor invocation. Every rejection before invocation leaves the tool
uncalled. DENY receives a signed receipt for representable, schema-valid intent;
unrepresentable or schema-invalid intent cannot receive fabricated evidence.

This is an enforcement property of the wrapper, not a sandbox for arbitrary
agent code. It requires exclusive privileged-tool access through that wrapper.
If an agent can call the tool directly with the same credentials, the deployment
has no enforced Besa boundary. Mappers, policies, signers, verifiers, replay
stores and sinks are trusted components; isolate them from the agent.

| Threat | Pre-execution control and boundary |
|---|---|
| Direct prompt injection | Prompts confer no authority. The actual operation/resource/parameters must satisfy signed external grants and deterministic policy before execution. A bad permitted policy can still authorize a harmful operation. |
| Indirect prompt injection | Retrieved content cannot widen a signed grant. The example requests deletion of production data and proves zero protected-tool invocations. Besa does not classify or sanitize content. |
| Confused deputy | Principal, acting agent, upstream issuer, exact service audience, resource, tool and operation are bound to normalized grants and the admission receipt. The trusted mapper must use verified actor claims, not caller-supplied identity text. |
| Parameter substitution after ALLOW | Request digest covers actual parameters/context; action request/context hashes and constraint values must agree. Wrappers detach and deeply freeze data before awaits. Executors consume that same snapshot. |
| TOCTOU in admission checks | Authority/policy are reverified after resolver, receipt sink and replay awaits, with a synchronous final check immediately before executor invocation. Expiry, revocation or changed policy blocks the tool. |
| TOCTOU in external resource state | Not solved by a receipt. Executor must enforce version/ETag/precondition or transactional checks atomically with the side effect. Mutable remote objects and delayed work inside the executor are outside wrapper control. |
| Replay | New runtime requires enforced atomic action-hash-plus-nonce consumption. Pure admission/audit do not consume state. FileReplayStore coordinates processes/restarts on one trusted local filesystem; distributed deployments require a shared transactional provider. |
| Caller or executor substitution | withBesaExecutor compares host-authenticated agent/principal with the action and requires the configured executor ID in signed hashed context. Caller claims copied from a body/receipt are not authentication. |
| Replay-state crash or replacement | FileReplayStore exclusively creates and fsyncs a claim; strict mode also syncs directories. Partial claims stay spent. Symlink ancestry and unsupported sync fail closed. Privileged directory replacement, rollback, deletion, NFS semantics and ephemeral storage are outside its boundary. |
| Lost side-effect acknowledgement | Consumed claims are not refunded after handler/response failure. The publisher example uses atomic no-replace content addressing for newly admitted retries; other executors require their own transactional/idempotency contract. |
| Duplicate execution | One replay-store winner attempts execution for a given action/nonce. A consumed nonce is not refunded on failure. Exactly-once business effects require executor-side idempotency or a transaction; a fresh nonce can authorize another attempt. |
| Forged agent/principal | A pinned normalizer signs identities from externally verified claims. Policy separately grants those identities. Possession of a generic identity or valid access token is not arbitrary action admission. |
| Forged/invalid delegation | Existing signatures, root trust, principal/agent linkage, narrowing, own-property constraints, issuance time and active interval are checked; the receipt binds the verified chain hash. |
| Stale/revoked authority | Current configured trust rejects revoked normalizer/delegation keys; lifetimes are rechecked at execution. Upstream token/delegation revocations not delivered to Besa remain unknowable offline. |
| Policy mutation | Both request and receipt bind the canonical policy hash, schema version and ID. Changing policy after ALLOW requires a new matching admission; unknown versions fail closed. |
| Receipt forgery/token confusion | Strict v1 receipt schema, pinned issuer key and domain-separated Ed25519 signature. Access/ID tokens, ID-JAGs and legacy capabilities are not accepted as admission receipts. |
| Key rotation | Existing rotation/trust lifecycle is reused. Retired keys fail new execution/admission; supported historical receipts can be audited before retirement. Revoked keys are rejected, including during audit. |
| Downgrade | Strong runtime requires the new request/receipt and enforced replay. Unknown mechanism/schema/policy versions fail; it never falls back to a legacy capability, identity-only flag or verification-only replay store. |
| Fail-open network behavior | Admission-resolution rejection, malformed replies, invalid signatures and unavailable/malformed replay responses block invocation. No network error is converted to ALLOW; no automatic tool retry occurs. Hanging transport blocks execution and needs an application-owned timeout/cancellation policy. |
| Canonicalization ambiguity | Accessors/non-JSON/oversized input and extension fields fail. Schema constraints require own data fields, not inherited properties. The frozen canonicalization is JavaScript JSON, including integer-index key order and negative-zero normalization; cross-language implementations must match SPEC, not assume JCS. Built-in raw JSON boundaries share parseArtifactJson; custom SDK transports must use it before producing objects. |
| Parser disagreement | Duplicate decoded keys at all depths, including escaped duplicates, fail before verification. Malformed UTF-8, unpaired surrogates, leading BOM, lossy decimal tokens and raw depth/node/byte overflow fail closed. Distinct Unicode scalar sequences remain distinct; no confusable-key or NFC normalization silently merges arbitrary parameters. Already externally parsed objects have lost duplicate/rounding provenance and cannot establish raw-input safety. |
| Authority representation confusion | ExternalAuthority is a signed normalizer attestation of safe claims/digests, not an IdP bearer token. EMA uses the exchanged access token. Workload mapping pins exact SPIFFE subject plus issuer/audience and explicit grants. |
| Credentials in evidence | Strict authority and receipt schemas omit raw bearer tokens/private keys; only assertion/authority digests are recorded. Applications must still avoid secrets in action identifiers/constraints and keep assertion verification input private. |
| Receipt storage unavailable | Rejected pre-execution append blocks the tool. Sink operators must ensure that append completion means the required retention/durability; an in-memory sink is not durable proof. Post-execution evidence append failure cannot undo the side effect. |

### Independent verification and trust limits

Offline verification can prove that a trusted normalizer signed claims and a
trusted admission issuer bound them to the exact request, policy and decision.
The original authority/assertion and exact policy are required as verifier input
alongside the receipt. The assertion digest alone does not prove the original
IdP signature or current revocation; that needs secure access to the assertion
and its provider verifier. A dishonest trusted normalizer or admission signer
can fabricate claims/decisions, so key separation and custody remain essential.

The receipt is portable decision evidence, not independently observed execution
evidence. The signed execution record likewise attests to supplied results.
Separate executor/recorder control or a trusted external observer is necessary
for stronger real-world outcome claims.

Status: v1.2 additive executor/authority APIs and self-hosted distribution. No independent third-party
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
- Protected durable local storage for FileReplayStore, or a transactional shared
  replay provider for multi-host one-time use. Strict power-loss mode requires
  actual file/directory fsync support; process mode deliberately has weaker durability.
- Receipt-sink commit guarantees. AppendOnlyEvidenceLog fsyncs file contents but
  does not sync new directory entries; pre-provision durable logs or use a stronger sink.
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
base64/key material, excessive canonical JSON, unknown fields and invalid
artifacts. Built-in JSON transport decoding additionally rejects duplicate keys,
escape-equivalent keys, invalid UTF-8/surrogates and number tokens that lose
decimal meaning. Raw limits bound work before native grammar parsing. HTTP,
CLI, file-loader, offline-verification and deterministic fuzz tests exercise
this boundary; published decoder vectors support independent implementations.
There is no new outbound request, database or parser fallback. Object-based
historical verification and frozen signature bytes remain unchanged; it is the
custom transport integrator's responsibility not to erase ambiguity first.

## Security reporting

Use `SECURITY.md` for private reporting. Include version, deployment mode,
preconditions, reproduction steps, and actual versus expected behavior. Do not
include keys, tokens, customer actions, or sensitive evidence in public issues.
