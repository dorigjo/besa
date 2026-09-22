# Runtime Admission and Evidence

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
| Customer-provided `ReplayStore` | `enforce` | Required for durable or distributed one-time-use semantics. Its atomicity, availability, durability, and access control are customer responsibilities. |

When `replayRequirement` is `enforce`, any store that cannot atomically consume
the key fails closed before the handler executes. Do not represent a
verification-only store as global replay protection.

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
