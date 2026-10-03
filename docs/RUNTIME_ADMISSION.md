# Runtime Admission and Evidence

## Pre-execution admission contract

BESA decides whether a protected agent action may execute and produces
portable evidence of that decision. It does not merely detect malicious
behavior after execution.

Use `withPreExecutionAdmission` when the boundary must bind externally
validated authority and the exact policy digest as well as the action. The
existing `withBesa` capability API remains supported below.

```text
authenticated caller / verified external assertion
  -> trusted adapter -> signed ExternalAuthorityV1
  -> exact PreExecutionRequestV1
  -> authority and delegation verification -> deterministic policy
  -> signed ALLOW or DENY PreExecutionAdmissionReceiptV1
  -> independent verification -> await admissionSink.append(receipt)
  -> ALLOW only: atomic replay consumption
  -> final verification against current authority and policy
  -> protected executor -> signed ActionEvidenceV1
```

`AUTHENTICATED != AUTHORIZED != ADMITTED`. An identity or access token alone
does not authorize an arbitrary operation. External grants and Besa policy
must both allow the concrete action before the executor can be called.

### Request and receipt

`PreExecutionAdmissionInput` contains `request`, `authority`, and an optional
`delegationChain`. The request has exactly seven fields:

- `requestVersion: 1` and the existing `ActionEnvelopeV1` in `action`.
- `parameters`: the actual plain JSON parameter object passed to the executor.
- `context`: the plain JSON execution context, for example CI job or coding
  agent session identifiers. Risk/context claims are data, not implicit trust.
- `audience`: the exact protected service identifier.
- `policy: { id, version, hash }`: a caller-pinned policy reference.
- `requestedAt`: a canonical UTC timestamp no later than admission.

The action's `requestHash` must equal `hashRequest(parameters)` and its required
`contextHash` must equal `hashRequest(context)`. Each declared action constraint
must occur with the same value in `parameters`. The trusted integration mapper
must derive operation/resource/risk from actual tool semantics. The executor
must consume the verified operation, resource and parameter snapshot; it must
not take an overriding resource or command from an unverified prompt, header,
ambient closure or alternate request field.

`admitPreExecution(input, config, at)` evaluates authority, optional delegation
and the pinned `ActionPolicyV1`, then signs a receipt. It is stateless and does
not consume a nonce. The receipt binds request/action digests, principal and
agent, audience, authority/assertion digests, delegation digest, policy
ID/version/hash, ALLOW/DENY, reason, issued time, expiry, nonce, and signing
key identity. ALLOW embeds the existing exact-action capability; DENY embeds
`capability: null`. It contains neither parameters nor raw credentials.

Supported canonical but denied requests receive signed denial receipts,
including expired actions and unsupported requested policy versions. An invalid
schema, non-JSON data, invalid clock, unusable signing key or invalid configured
policy cannot be faithfully signed: these fail before execution without a
fabricated receipt. Malformed authority that is representable as canonical JSON
can produce DENY; its unvalidated claims are not copied into evidence.

`verifyPreExecutionAdmission(receipt, input, config, at)` is an independent
offline verifier. It checks the receipt signature and trusted key, exact input,
policy digest, capability, authority validity at admission and execution,
delegation and decision. Supply the exact policy and signed normalized authority;
no secret token is needed. A valid DENY is `valid: true, authorized: false`.
The optional `"audit"` mode checks ALLOW at its admission time for historical
verification after expiry. Audit validity is never permission to execute.
Audit always returns `authorized: false`; inspect the signed receipt's decision
to establish historical admission.

### Minimal wrapper configuration

```ts
import {
  AppendOnlyEvidenceLog,
  InMemoryReplayStore,
  withPreExecutionAdmission,
  type PreExecutionAdmissionReceiptV1,
} from "@dorigjo/besa";

const execute = withPreExecutionAdmission({
  policy,
  audience: "https://tools.example/release",
  trustStore: admissionAndRecorderTrust,
  authorityTrustStore: normalizerTrust,
  delegationTrustStore: delegationRootTrust,
  resolveAdmission: input => admissionService.admit(input),
  admissionSink: new AppendOnlyEvidenceLog<PreExecutionAdmissionReceiptV1>(
    "./admissions.jsonl",
  ),
  replayStore: new InMemoryReplayStore(),
  evidenceKeyPair: recorderKeyPair,
  evidenceSink: new AppendOnlyEvidenceLog("./execution.jsonl"),
  recorderId: "recorder:release",
  executorId: "executor:release",
}, input => deploy(
  input.request.action.resource,
  input.request.parameters,
));

await execute({ request, authority, delegationChain });
```

All objects named in this snippet are application-supplied. `admissionService`
is an injected transport/client, not a new built-in cloud endpoint. Locally,
`resolveAdmission` can call `admitPreExecution` with an explicitly held issuer
key. Separating that issuer from the executor provides the meaningful security
boundary. The wrapper performs no hidden network calls, routing or retries.

The wrapper snapshots and deeply freezes intent before awaiting the resolver.
It verifies and awaits receipt storage before execution. A rejected append is
`ADMISSION_RECORD_FAILED`; unavailable admission is
`ADMISSION_VERIFIER_UNAVAILABLE`. Neither invokes the tool. After asynchronous
receipt storage and replay consumption it verifies current policy and trust
again immediately before invoking the executor. Late verification failure also
blocks the tool. A runtime failure record may describe this blocked attempt;
it does not assert that the external tool ran.

An ALLOW receipt describes an admission decision, not completion. Multiple
admission attempts may yield ALLOW for the same nonce; only enforced atomic
runtime consumption decides whether that action/nonce may execute once.
Failed or uncertain executions keep their consumed nonce. There is no automatic
retry or refund; the executor needs its own idempotency/resource transaction.

### Executor-side receipt enforcement

`withBesaExecutor(config, execute)` accepts `(input, receipt, caller)`. Unlike
the admission resolver wrapper, it consumes a receipt supplied by another
component; it does not need an admission signing key. It independently verifies
the signed authority, exact request, policy and receipt, commits the receipt,
consumes replay state and revalidates current trust before invoking `execute`.

The host must derive `caller.agentId` and `caller.principalId` from authenticated
transport/job context, not from request JSON or the receipt. They must match the
action. `input.request.context.executorId` must equal the configured executor ID;
the context digest cryptographically binds that ID to admission. Another executor
cannot reuse this receipt. Rejecting caller/executor substitution occurs before
storage. Stable errors are `SCHEMA_EXECUTOR_INPUT_INVALID`,
`ADMISSION_CALLER_MISMATCH` and `ADMISSION_EXECUTOR_MISMATCH`.

All privileged access must pass through the guarded callback. This API does not
authenticate transport, sandbox code, remove alternate credentials or prevent a
malicious executor from writing outside the wrapper. The operator owns that
boundary and must keep current policy/revocation state available to the wrapper.

### External identity adapters

`normalizeAccessTokenAuthority` consumes the output of an application-owned
IdP verifier. The callback must verify token signature or introspection result,
algorithm/key provenance, token type, issuer, protected-service audience,
validity, revocation when required, and the actual authenticated acting agent.
Its `VerifiedAccessTokenClaims` is a callback result, not a remotely trusted
`validated: true` JSON flag. Operator-configured scope-to-action mappings supply
narrow tools, operations, resources and constraints; the asserted scopes must
include the mapping's required scopes.

The `mcp-ema` profile uses the **access token resulting from exchange**, never
an ID token or raw ID-JAG. ID-JAG is an authorization-server grant, not an
execution capability. The adapter rejects those token-use types. Besa neither
implements OAuth nor guesses vendor claim names. An Okta/XAA-like flow is:
enterprise assertion -> resource authorization server exchange -> verified
access token/actor -> this adapter -> Besa admission -> protected action.
See the [MCP EMA specification](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
and [ID-JAG draft](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-03.html).

`normalizeWorkloadAuthority` requires an externally verified JWT-SVID or an
authenticated workload-session proof, the exact expected `spiffeId`, expected
issuer/audience, operator-assigned principal and explicit action grants. A
certificate or workload identity alone is insufficient. The verifier must
validate SPIFFE trust-domain and proof-of-possession/session requirements; the
adapter does not provide X.509/JWT-SVID validation. See [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe/concepts/).

`normalizeDelegationAuthority` reuses existing Besa signed-chain verification
and binds its chain digest. Admission and runtime verification require that
same chain when the normalized authority or policy requires it.
The adapter requires `authenticatedAgentId` from the host's authentication
context and compares it with the leaf subject. Never derive this option from
the requested action: a publicly verifiable delegation proves granted rights,
not who currently holds or presents it. Known explicitly revoked issuer or
subject keys anywhere in the chain are rejected; unlisted intermediary keys
remain transitively authorized by the trusted root, not implicitly revoked.

`ExternalAuthorityV1` is a signed attestation by a pinned normalizer, not the
original IdP artifact. Its signature proves that normalizer's claims. Offline
verification cannot prove the original bearer token's signature from its digest,
retrieve upstream revocation, or establish that the adapter told the truth.
Keep the normalizer key away from the untrusted agent, and distribute current
normalizer/delegation revocations to executors. Short authority lifetimes bound
staleness; immediate upstream revocation requires an external online check.

### Executable reference

After `npm run build`, on Node 24 run:

```sh
node --experimental-strip-types examples/pre-execution.ts
node --experimental-strip-types examples/protected-artifact-publisher.ts
```

The example creates a real signed delegation and normalization artifact. A
prompt-injection-like request to delete the production database yields DENY,
zero executor calls and independently verified denial evidence. A permitted
staging deployment then executes once. Keys and logs are ephemeral for the
example; configure durable sinks and replay storage for deployment.

The same file provides typed `executeEnterpriseAction` and
`executeWorkloadAction` integration entry points. A MCP gateway calls them at
its authenticated tool boundary; a CI/CD agent or coding agent calls them at
the deploy/write/delete executor boundary. This is an SDK composition, not a
gateway/router or vendor client implementation. The existing MCP adapter
remains usable for legacy exact-action capabilities.

The artifact publisher performs a real local content-addressed filesystem write
under an operator-selected root. It validates the signed content hash and resource,
fsyncs a private temporary file and atomically hard-links complete bytes without
replacement. A new valid admission for identical content returns `created: false`;
different content has a different target. This is operation-specific idempotency,
not universal exactly-once execution. The example demonstrates missing-receipt
denial, persisted replay rejection after reconstructing the store, and an
idempotent freshly authorized attempt. It is a reference integration, not evidence
of an independently operated customer integration.

The cross-platform example explicitly selects `durability: "process"`; its local
keys are ephemeral and no private keys are written. On POSIX deployments choose
the strict replay default, provision durable receipt storage, authenticate the CI
job and protect the output/state directories. Hard-link and fsync guarantees
depend on the deployed filesystem. The example is not a multi-host publisher.

## Migration

- Existing v1.0 and v1.1 signed bytes, signature domains, vectors and verification
  paths are unchanged. New authority and receipt artifacts have their own v1
  schemas and domains. Keep supported historical verifiers.
- Existing `withBesa` and `withBesaMcp` signatures remain supported. They now
  freeze their detached action/call data: handlers or mappers that mutate it
  must construct their own working copy. This deliberate behavior change closes
  parameter substitution across asynchronous resolution.
- The HTTP example now expects a plain JSON request DTO, checks its body hash
  and freezes the detached DTO. Do not pass a live framework socket/request.
- Enable `withPreExecutionAdmission` per protected executor, pin the expected
  audience and policy digest, configure normalizer trust and receipt storage,
  and require an enforced replay store. There is no legacy-capability,
  unknown-version, weak-authority or `detect-only` fallback in this path.
- The legacy hosted `/v1/actions/admit` endpoint still returns a v1.1 capability.
  It does not provide the new authority/policy receipt contract. Inject a service
  using the new SDK API for `resolveAdmission`; do not mistake bearer-token
  authentication at the legacy endpoint for the new admission guarantee.
- `ActionEvidenceV1.receiptHash` can now link the new admission receipt as well
  as a legacy receipt. Its field/schema/domain are unchanged; provide
  `hashPreExecutionReceipt(receipt)` to independent evidence verification.
- These additive APIs belong to package v1.2.0. Existing v1.1.1 registry artifacts
  are immutable. Existing callers need no artifact conversion; integrations that
  mutate wrapper inputs must use a working copy as described above.

The Besa runtime is the narrow control point directly before a consequential
handler. It consumes existing identity context, verifies an exact signed action
authorization, optionally verifies delegation, consumes replay state, executes
the handler only on allow, and records signed evidence afterward.

```text
existing authentication
  -> ActionEnvelopeV1
  -> ActionCapabilityV1 verification
  -> delegation verification, when required
  -> replay consumption
  -> guarded handler
  -> ActionEvidenceV1 and evidence sink
```

`withBesa` does not authenticate callers, inspect prompts, route MCP traffic,
or make policy decisions. It enforces a capability that was already issued by
a decision authority. `withBesaMcp` adds one MCP-specific check: the action's
tool name and request hash must match the supplied MCP call and arguments.

## Minimal integration

```ts
import {
  AppendOnlyEvidenceLog,
  InMemoryReplayStore,
  withBesa,
} from "@dorigjo/besa";

const execute = withBesa(
  {
    trustStore: verifierTrust,
    capability: resolveCapabilityForAction,
    replayStore: new InMemoryReplayStore(),
    replayRequirement: "enforce",
    evidenceKeyPair: recorderKeyPair,
    evidenceSink: new AppendOnlyEvidenceLog("./evidence.jsonl"),
    recorderId: "evidence-recorder:production",
    executorId: "payments-rail:primary",
    delegationChain,
    requireDelegation: true,
  },
  async (action) => paymentRail.transfer(action.constraints),
);

const outcome = await execute(actionEnvelope);
```

The capability resolver may call the self-hosted verifier, read a local
artifact, or use another application-owned transport. It must return an
`ActionCapabilityV1` for the exact action. The runtime does not perform hidden
network calls and does not require a Besa-operated service.

## Validation and execution order

1. Validate the Action Envelope and reject expiration or malformed fields.
2. Resolve the Action Capability, then verify it at a fresh post-resolution
   time against the configured trust store.
3. Reject a cryptographically valid signed deny before the handler runs.
4. Validate a supplied delegation chain and require its chain hash to match the
   capability when delegation is required or bound by the capability.
5. Consume the replay key derived from the action hash and nonce.
6. Recheck capability expiry and delegation after the asynchronous replay-store
   call, immediately before recording `startedAt` and invoking the handler.
7. Invoke the handler only after all prior checks succeed.
8. Sign and append success evidence. If the handler throws, sign and append
   failure evidence containing only the error type, then throw
   `BesaRuntimeError` with `ACTION_HANDLER_FAILED`.

If a successful handler result cannot be timestamped, canonically hashed, or
signed, the runtime reports `EVIDENCE_CREATION_FAILED`; it does not create a
false handler-failure record. If evidence append fails, the runtime reports
`EVIDENCE_RECORD_FAILED`. In either case the external side effect may already
have happened; callers must treat this as an operational incident, not retry
the action blindly.

## Replay model

The nonce is cryptographically bound to the action but that alone is not
global replay prevention.

| Store | Runtime mode | Guarantee |
|---|---|---|
| `VerificationOnlyReplayStore` | `detect-only` | Reports that one-time use is not enforced. Useful only when external controls own replay handling. |
| `InMemoryReplayStore` | `enforce` | Atomic one-time consumption within one process until expiry. It is bounded and fails closed at capacity. It does not survive restart or coordinate hosts. |
| `FileReplayStore` | `enforce` | Exclusive persisted claim across processes sharing one trusted local directory; survives process restart. Strict default requires file and directory fsync support. Not distributed or an execution-result cache. |
| Customer-provided `ReplayStore` | `enforce` | Required for durable or distributed one-time-use semantics. Its atomicity, availability, durability, and access control are customer responsibilities. |

When `replayRequirement` is `enforce`, any store that cannot atomically consume
the key fails closed before the handler executes. Do not represent a
verification-only store as global replay protection.

`new FileReplayStore(directory)` uses `durability: "power-loss"`: it checks
non-symlink directory ancestry, syncs directory ancestry, exclusively creates a
domain-separated hashed claim, fsyncs the file and then the directory before
returning `consumed`. Unsupported directory fsync (including Windows), permission,
disk or storage failures return `unavailable`; there is no implicit downgrade.
`{ durability: "process" }` explicitly omits directory fsync and cannot promise
survival of OS crash/power loss. Actual power-loss durability depends on the
filesystem/hardware honoring fsync; this adapter does not certify that stack.

Empty/partial claims remain spent, including after uncertain failure. Expired
claims are not automatically deleted. Preserve this private state, restrict
writer access and manage capacity/retention outside the core. Deleting/restoring
claims can re-enable execution. Do not use this adapter on NFS, independent hosts,
ephemeral serverless storage or a directory an untrusted actor can replace.
Use a deployment-specific durable transactional provider for those environments.

## Evidence and logs

`ActionEvidenceV1` links the exact Action Envelope, allow capability, optional
legacy receipt hash, hash of the supplied execution result, executor ID,
recorder ID, timestamps, and recorder signature. An independent verifier can
prove that those supplied values link and were signed by a trusted recorder.

It cannot prove a bank transfer, database deletion, deployment, or other
outside-world effect happened unless the recorder is independently trusted to
observe that effect. The executor and recorder should be separated when a
stronger evidence boundary matters.

`AppendOnlyEvidenceLog` writes canonical JSONL records, serializes appends in
one process, rejects symlink/non-regular targets, uses no-follow where the
platform supports it, caps one record at 1 MiB, and fsyncs each append. It is
not an immutable ledger, a cross-process lock, a retention system, or a remote
durable store. Rotate, retain, back up, and independently protect logs in the
deployment environment.

The log fsyncs file contents but does not fsync newly created parent directory
entries. If admission persistence must survive power loss, pre-provision and sync
the directory/log or supply a sink with that stronger commit contract. Append
completion alone cannot establish durability beyond the sink implementation.

## MCP reference point

Use [`examples/consequential-mcp-middleware.ts`](../examples/consequential-mcp-middleware.ts)
after normal MCP authentication and immediately before the privileged tool. It
derives `requestHash` from the exact MCP arguments, so an authenticated call to
one tool or parameter set cannot reuse a capability for another.

Authentication answers who reached the MCP service. Besa answers whether the
specific high-consequence action and constraints presented to the tool were
authorized. Neither replaces the other.

## Legacy HTTP attestation

`POST /v1/admit` remains available from `besa serve --trust ...` for v1.0
manifest/tool admission. It issues a signed, non-consuming
`AdmissionAttestation`; it is not an execution receipt and does not provide
distributed budget enforcement. New consequential-action integrations should
use `ActionEnvelopeV1`, `ActionCapabilityV1`, `ActionEvidenceV1`, and the
runtime described here.
