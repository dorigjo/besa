# Runtime Admission (Phase 7)

Architecture, endpoint reference, and threat model for the opt-in admission
route mounted on `besa serve --trust <file>`. No compliance claim, no
marketing language — every statement below is either demonstrated by a test
in `src/tests/server.test.ts`/`src/tests/attestation.test.ts` or explicitly
named as not implemented.

## What this is

An opt-in extension of the Hosted Verifier (`docs/HOSTED_VERIFIER.md`) that
answers a different question: not just "is this signature valid," but "is
this tool call currently admitted, and here is signed proof of that
decision." It reuses, unchanged:

* `admit()` (`src/admit.ts`) — the same pure admission-decision function the
  CLI's `besa admit`/`besa receipt` already call.
* `verifyTrustedSignedManifest()` (`src/trust.ts`) — the same trust-chain
  check `besa verify --trust`/`besa admit` already perform.
* `signWithKeyPair()` (`src/crypto.ts`) — the exact same Ed25519 signing
  primitive `signManifest()`/`createReceipt()` already use.

No new crypto pipeline, no new trust source, no parallel architecture — see
`src/attestation.ts` for the one new artifact type this introduces
(`AdmissionAttestation`) and how it reuses the above.

Enabled only when `besa serve` is started with `--trust <file>`. Without
that flag, `besa serve` is byte-identical to Phase 5 (Hosted Verifier)
behavior — this is purely additive.

## What this is not

**This is not a Receipt, and does not replace `besa receipt`.** The
distinction is the single most important thing to understand about this
feature:

| | `besa receipt` (existing, local) | `POST /v1/admit` (this feature) |
|---|---|---|
| Consumes the meter (budget) | Yes — `admitAndConsume()`, file-locked | **No** — read-only, no lock ever acquired |
| Requires a signing key | Yes, local `.besa/key.json` | Yes, server-held key |
| Proves a tool call was executed | It is the durable evidence *of* an admission decision tied to actual usage | **No** — it proves only "at this timestamp, given this meter snapshot, this decision would have been made" |
| Can block on file lock contention | Yes, briefly, for one CLI invocation | **No**, by design (see "Why this never acquires the meter lock," below) |

A caller that wants a real, budget-consuming, execution-tied signed record
must still use the existing local `besa receipt` flow, run by whoever holds
the signing key and orchestrates actual tool execution. This service only
answers a pre-flight question; it does not enforce or record execution.

It also, like the Hosted Verifier it extends:

* **Never runs a policy engine beyond the existing `admit()` rules.** No new
  rule language, no ABAC, no per-agent policy — see `docs/V1_ROADMAP.md`'s
  own "Policy Engine" node, still unimplemented.
* **Never touches `.besa/receipts/`.** No receipt files are written by this
  route.

## Why this never acquires the meter lock

The local meter lock (`acquireMeterLock` in `src/admit.ts`) uses a blocking
retry loop (`Atomics.wait`) suitable for a short-lived CLI invocation, where
blocking is harmless because nothing else is happening in that process. A
long-running HTTP server is different: if `/v1/admit` acquired that lock
synchronously inside a request handler, meter contention under concurrent
load could stall Node's single event loop for up to the lock's timeout —
freezing *every* connection the server holds, including unrelated `/health`
or `/v1/verify/*` requests. This was identified during Phase 7 design and is
the reason this endpoint is deliberately non-consuming: it only reads the
meter (`loadMeter()` + `getCount()`, a plain synchronous file read, no lock,
no retry loop), never writes to it. This is a scope cut, not an oversight —
building a lock-safe, non-blocking, network-exposed consuming admission
path would need its own separate design and is not part of this phase.

## Endpoint reference

All request/response bodies are JSON. Request bodies are capped at
`MAX_ARTIFACT_BYTES` (1 MiB, `src/io.ts:18`), identical to every other
Hosted Verifier route.

| Method | Path | Body | Response |
|---|---|---|---|
| `POST` | `/v1/admit` | `{ signedManifest: <SignedManifest>, toolName: <string> }` | `200` with a signed `AdmissionAttestation` |

Error responses: `400` malformed JSON, malformed envelope (missing
`signedManifest`/`toolName`), or a `signedManifest` that fails basic shape
validation (no reliable `manifestHash` to attest to); `404`/`405` as usual
for unknown paths/wrong methods; `413` oversized body; `501` if the server
was started without `--trust` (admission not enabled); `500` on an
unexpected local storage error (e.g. corrupt meter file) — fails closed
rather than risk an attestation built from a bad read.

A `200` response does not mean "the call is allowed" — it means "the
service successfully computed and signed an answer." The answer is in the
attestation's own `decision`/`reasonCode` fields, exactly mirroring how
`VerifyResult` already behaves for the rest of the Hosted Verifier.

### AdmissionAttestation shape

```typescript
interface AdmissionAttestation {
  artifactVersion: 1;
  attestationId: string;       // "att_" + UUIDv4
  manifestHash: string;
  toolName: string;
  decision: "allow" | "deny";
  reasonCode: string;          // e.g. ALLOWED, TOOL_NOT_FOUND, BUDGET_EXCEEDED,
                                // RISK_BLOCKED, or a trust-verification code
                                // like E_KEY_UNTRUSTED, E_KEY_REVOKED
  detail: string;
  meterCountAtCheck: number;   // the meter's count at read time; 0 if the
                                // manifest was untrusted or toolName invalid
  timestamp: string;           // ISO-8601, when the attestation was signed
  publicKeyId: string;         // the SERVER's key, not the manifest signer's
  algorithm: "ed25519";
  signature: string;
}
```

Note `publicKeyId` identifies the *admission service's* key — the operator
running `besa serve --trust ... --key-file ...` — not the manifest's
publisher key. A recipient verifies the attestation against whichever key
they trust as their admission service's identity (out of band, the same way
a client today knows which host it's talking to).

## Guarantees

* Byte-identical decision logic to the CLI's dry-run `besa admit` — no
  second admission implementation. `admit()` is called directly.
* Byte-identical signing primitive to `signManifest()`/`createReceipt()` —
  no second crypto pipeline.
* Deterministic: the same signed manifest, tool name, and meter file state
  always produce the same attestation content (timestamp and
  `attestationId` aside).
* Fails closed: malformed input, untrusted keys, revoked/retired keys,
  unknown tools, and budget-exceeded all produce an explicit `deny`
  attestation or a request-level error — never a silent allow.
* Never blocks the event loop on meter contention (see above).
* Additive and backward compatible: a plain `besa serve` (no `--trust`) is
  unchanged from Phase 5 in every respect, verified by
  `src/tests/server.test.ts`'s existing Phase 5 test suite still passing
  unmodified.

## Limitations

| Feature | Status | Notes |
|---|---|---|
| Authentication | Not implemented | Same posture as the rest of the Hosted Verifier — named residual risk below. |
| Rate limiting | Opt-in (`--rate-limit <n>`) | Server-wide — applies to `/v1/admit` the same as every other route. Off by default; see `docs/HOSTED_VERIFIER.md`'s "Rate limiting" section. |
| TLS | Not implemented | Run behind a reverse proxy that terminates TLS. |
| Real-time distributed budget enforcement | Not implemented | This endpoint reads, never consumes, the meter — see "Why this is not a Receipt," above. |
| Policy beyond existing `admit()` rules | Not implemented | No ABAC, no per-agent policy — see `docs/V1_ROADMAP.md`'s Policy Engine node. |
| Persistent state | Reads `.besa/meter.json` (or `--meter <file>`); never writes it | The only file this route touches. |

## Threat model

Per-attacker format matching `docs/PROVIDER_THREAT_MODEL.md` and
`docs/HOSTED_VERIFIER.md`.

### Attacker: unauthenticated caller consuming the operator's compute

* **Assets:** the admission service's compute/network capacity, and its
  signing operation.
* **Trust boundary:** anyone who can reach the listening port, when
  `--trust` is enabled.
* **Attack:** send admission requests at any volume.
* **Mitigation:** no authentication — same posture as the rest of the
  Hosted Verifier. Unlike pure signature verification, though, this route
  performs a privileged operation (uses the server's private key to sign
  every response). The server-wide `--rate-limit <n>` option (Phase 8,
  opt-in, off by default) applies to this route the same as every other,
  capping requests per client address before the signing operation runs.
* **Residual risk:** an operator exposing this publicly without
  `--rate-limit` or their own authentication accepts unmetered use of
  their signing operation. Named, not silently assumed away — this is why
  admission is opt-in (`--trust` required) rather than always-on like
  the stateless verify routes.

### Attacker: budget-exhaustion denial of service

* **Assets:** the shared meter's remaining budget for legitimate callers.
* **Trust boundary:** anyone who can reach the listening port with a
  legitimately signed manifest they observed (signed manifests are not
  secret by design — they are meant to be shared for verification).
* **Attack:** replay a legitimately signed manifest against `/v1/admit`
  repeatedly, hoping to affect the meter state used by legitimate calls.
* **Mitigation:** this route never consumes the meter (see "Why this is
  not a Receipt," above) — it only reads the current count. An attacker
  hammering this endpoint cannot increment or reset any counter, cannot
  exhaust a legitimate caller's remaining budget, and cannot forge an
  `allow` for a call that `admit()` would otherwise deny, because the
  decision logic itself is unchanged and deterministic.
* **Residual risk:** none identified for *budget* integrity specifically —
  this is a materially safer position than a hypothetical consuming
  variant would have had, and is the direct payoff of the non-consuming
  design decision.

### Attacker: signing-key compromise via a longer-lived process

* **Assets:** the admission service's private key material.
* **Trust boundary:** whoever can compromise or inspect the `besa serve
  --trust` process's memory.
* **Attack:** exploit the server process (or the host it runs on) to
  extract the decrypted private key held in memory for the process's
  lifetime.
* **Mitigation:** the same key-loading path as the CLI (`loadExistingKeyPair`,
  AES-256-GCM + scrypt at rest, `BESA_KEY_PASSPHRASE`/`--passphrase-file`) —
  no new decryption or storage mechanism. `besa serve --trust` never
  auto-generates a key (`loadExistingKeyPair`, not `loadOrCreateKeyPair`),
  so an operator must deliberately provision a key for this role.
* **Residual risk:** this is a materially different — and larger — blast
  radius than the Hosted Verifier's own guarantee that it "never loads a
  signing key" (`docs/HOSTED_VERIFIER.md`). A CLI invocation holds decrypted
  key material for one short-lived process; this server holds it for its
  entire uptime. An operator enabling `--trust` on `besa serve` is
  explicitly accepting this trade-off. Named prominently here and in
  `cmdServe()`'s own startup banner, not hidden.

### Attacker: malformed or adversarial request input

* **Assets:** none directly — a correctness/availability concern.
* **Trust boundary:** anyone who can reach the listening port.
* **Attack:** send non-JSON bodies, wrong-shaped envelopes, or a
  `signedManifest` that fails basic shape validation.
* **Mitigation:** `400` for anything that cannot be safely turned into an
  attestation (no reliable `manifestHash`); a well-formed-but-untrusted or
  well-formed-but-denied manifest still gets a signed `deny` attestation,
  never a thrown error or a silent allow.
* **Residual risk:** none identified beyond what already applies to
  `verifyTrustedSignedManifest()`'s existing fail-closed contract.

## Why not exported via the SDK yet

Same judgment already applied to `KeyProvider`/`LocalKeyProvider` (Phase 3)
and `createHostedVerifierServer` (Phase 5): reachable only via `besa serve
--trust`, not through `sdk.ts`'s frozen public export surface
(`sdk-surface.test.ts` unchanged by this phase). A public export is frozen
only once a real second consumer or embedding use case proves the shape is
right.

## Migration and compatibility

* Purely additive: no existing CLI command, SDK export, or artifact format
  changes behavior.
* `AdmissionAttestation` is a new artifact type (`artifactVersion: 1`), not
  a new version of `Receipt` — it does not touch `golden-v1.ts`'s frozen
  vectors and never will, by the same "shape versioning is independent of
  algorithm versioning" discipline in `docs/ALGORITHM_AGILITY_DESIGN.md`.
* A plain `besa serve` (no `--trust`) is byte-identical to Phase 5.
