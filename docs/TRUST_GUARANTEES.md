# Besa Trust Guarantees — Consolidated Statement

Single source of truth for what Besa can guarantee today versus what it
deliberately does not guarantee. Consolidates the guarantee/non-guarantee
sections already stated separately in `TRUST_MODEL.md`,
`PROVIDER_THREAT_MODEL.md`, `PHASE4_HARDENING_AUDIT.md`, and
`KEY_PROVIDER_ARCHITECTURE.md`, plus the Phase 5 analyses
(`REPLAY_PROTECTION_ANALYSIS.md`, `ALGORITHM_AGILITY_DESIGN.md`) and the
Phase 5 SDK-surface and provider-hardening work.

No compliance claim, no certification claim, no production-readiness claim,
no marketing language. Every line below is either a fact demonstrated by a
passing test, or explicitly named as unimplemented. This document does not
supersede the four source documents it consolidates — they remain the
detailed record; this is the short version someone evaluating Besa should
read first.

## What Besa guarantees today

1. **Signature integrity.** A signature that verifies
   (`verifySignedManifest`/`verifyReceiptDetailed`/`verifyKeyRotation`
   returning `valid: true`) means the exact canonical bytes of that artifact
   were signed by the holder of the private key matching `publicKeyId`, and
   have not been altered since. This is a cryptographic guarantee (Ed25519
   via `node:crypto`), not a heuristic — demonstrated by the tamper-rejection
   tests in `golden.test.ts`, `security.test.ts`, and every `provider-*.test.ts`
   file.
2. **No implicit trust.** A `TrustStore` only ever contains keys a consumer
   explicitly added via `trust add`/`trust apply`. There is no ambient,
   default, or hosted trust of any key.
3. **Fail-closed key lifecycle.** `checkTrustedKey()` rejects a revoked key
   unconditionally, including for historical artifacts. It accepts a retired
   key only for artifacts signed before retirement, never for new
   admissions. Both are tested boundary conditions, not documented intent
   only.
4. **Provider self-reports are never trusted.** Whether a manifest/receipt/
   rotation was signed via a raw `KeyPair` or a `KeyProvider`
   (`LocalKeyProvider`, `RemoteSimulationProvider`, or any structurally
   compatible implementation a consumer supplies), verification independently
   recomputes `publicKeyId(publicKey)` and checks the signature via
   `node:crypto`'s `verify()`. A provider that lies about which key it used —
   whether by bug, malice, or a genuine rotation race — is caught, not
   trusted. Demonstrated by the `mismatchedIdentityProvider`/
   `mismatchedPublicKeyProvider` test doubles across `provider-contract.test.ts`
   and `provider-rotation.test.ts`, all of which fail closed with
   `E_PUBLIC_KEY_ID_MISMATCH` or equivalent.
5. **Provider tier-agnostic verification.** Every `KeyProvider` tier
   produces signatures that verify identically through the same path — the
   interface's three methods (`getPublicKey`/`getKeyId`/`sign`) are the only
   contract a provider must satisfy. Nothing downstream special-cases which
   tier signed an artifact.
6. **Provider concurrency correctness.** Parallel calls against one shared
   `KeyProvider` instance (concurrent `sign()` calls, or
   `signManifestWithProvider`/`createReceiptWithProvider` running
   concurrently) each produce independently correct, independently
   verifiable artifacts — proven under load, not assumed. Retry/timeout
   logic (`RemoteSimulationProvider`) is deterministic per attempt number,
   with no shared mutable state that one call's retry loop can corrupt for
   another.
7. **Transient failures are recoverable, permanent ones fail closed.** A
   provider call that times out or errors and then recovers within its retry
   budget resolves successfully; one that never recovers exhausts its retry
   budget and rejects. Both paths are exercised by real async timer races,
   not mocked outcomes (`provider-contract.test.ts`).
8. **Bounded, tested input limits.** `MAX_TOOLS` (256), `MAX_SCOPES` (64),
   `MAX_TRUST_KEYS` (4,096), tool description length (4,096 chars), and scope
   string length (256 chars) are all enforced and tested exactly at their
   boundary — one under passes, one over is rejected with a specific error.
9. **Deliberate, audited public API surface.** Every symbol exported from
   `sdk.ts` was individually decided to have a distinct consumer use case,
   not leaked via a blanket `export *`. `crypto.ts`'s exports were narrowed
   in Phase 5 to remove three primitives (`isCanonicalBase64`,
   `publicKeyFromDer`, `sha256Hex`) with no use case beyond what the
   remaining higher-level exports already serve; `index.ts`'s dead
   `grantGate` export was un-exported entirely. `sdk-surface.test.ts` fails
   the build if this surface drifts unintentionally.
10. **Secrets never leak into signed artifacts or their serialization.**
    Tested directly: a provider-signed manifest's/receipt's serialized JSON
    never contains private key material, and `LocalKeyProvider` construction
    errors never echo rejected key material.
11. **Signature verification is available over HTTP, not just the CLI.**
    `besa serve` (`docs/HOSTED_VERIFIER.md`) exposes the same
    `verifySignedManifest`/`verifyReceiptDetailed`/`verifyKeyRotation`
    functions the CLI already calls behind a stateless HTTP endpoint — a
    third party without the Besa CLI can now independently check whether an
    artifact's signature is cryptographically valid. The server process
    never loads a signing key and never touches the filesystem for trust
    data; a compromised or overloaded verifier process cannot leak signing
    material or forge a decision, because it holds neither.
12. **Runtime admission attestations are signed, deterministic, and
    non-consuming.** `besa serve --trust` (`docs/RUNTIME_ADMISSION.md`)
    issues `AdmissionAttestation`s via the same `admit()` decision function
    and the same `signWithKeyPair()` primitive the CLI already uses — no
    second admission implementation, no second crypto pipeline. The route
    never acquires the meter's file lock, so it can never consume or corrupt
    budget shared with local CLI usage; verified in
    `src/tests/server.test.ts` by asserting the meter file is byte-identical
    before and after a check.

## What Besa deliberately does NOT guarantee

1. **Real-world identity.** Besa verifies *cryptographic continuity* (the
   same key signs the same identity over time), never *real-world identity*.
   That a trusted key belongs to the organization it claims to be is an
   out-of-band decision the consumer made when they ran `trust add` — Besa
   does not authenticate `serverName` or `agentId` against anything.
2. **Agent identity on receipts.** `agentId` is a caller-supplied label
   recorded as evidence alongside an admission decision, not a
   cryptographically authenticated claim. There is no per-agent key today.
3. **Key compromise detection.** Besa has no mechanism to detect that a
   still-active, never-revoked key has been stolen. Revocation is a manual,
   local-to-one-trust-store action; nothing monitors for anomalous use.
4. **Tool behavior or output correctness.** Besa attests to *who published
   this manifest* and *what admission decision was made*, never to what the
   tool itself actually does when called.
5. **Replay protection.** `verifySignedManifest`/`verifyReceipt` answer "is
   this signature valid for this artifact," never "was this artifact already
   used." An attacker who obtains a copy of a previously valid signed
   manifest or receipt can resubmit it, and Besa's verification layer
   accepts it. Analyzed in full in `REPLAY_PROTECTION_ANALYSIS.md`; the
   conclusion is that a general fix requires new persistent, shared,
   cross-consumer state, which is a hosted-layer feature explicitly out of
   this MVP's scope — not a gap that has a smaller local fix.
6. **Cross-consumer revocation propagation.** If a signer's key is
   compromised, they can only ask each consumer individually to run `trust
   revoke`. There is no mechanism to push a revocation to consumers Besa
   does not control — no transparency log, no hosted registry.
7. **Algorithm agility (today).** Only Ed25519 is supported. `algorithm` is
   a TypeScript literal type, and two crypto primitives
   (`isSignature`/`isPublicKeyEncoding`) hardcode Ed25519-sized bounds. AWS
   KMS and Azure Key Vault, which do not offer Ed25519, cannot back a
   `KeyProvider` today. `ALGORITHM_AGILITY_DESIGN.md` documents a
   non-breaking path to widen this (Design B: decouple `algorithm` from
   `artifactVersion`), but nothing has been implemented — this is a design
   document, not a shipped capability.
8. **Provider-side key custody.** Besa's verification layer cannot detect a
   `KeyProvider` implementation that signs the correct payload with the
   correct key but has already leaked that key on its own side — that
   artifact is cryptographically legitimate. Provider implementation
   security is the provider author's responsibility, not something the
   `KeyProvider` interface or Besa's verification can defend against.
9. **Provider retry/backoff policy.** `KeyProvider.sign()` rejecting on
   failure is the only contract. No implicit retry loop lives inside a
   provider implementation; retry/backoff/circuit-breaking is a caller or
   concrete-provider decision, not something Besa's core enforces or
   provides a default for.
10. **Key recovery.** There is no key recovery mechanism. Losing
    `.besa/key.json` and its passphrase means the operator can no longer
    sign as that identity — a deliberate simplicity trade-off for a local,
    single-operator tool.
11. **Remote/hardware key custody.** No KMS, HSM, or Vault integration is
    implemented in this repository. `KmsKeyProvider`/`HsmKeyProvider`/
    `VaultKeyProvider` are illustrative shapes in
    `KEY_PROVIDER_ARCHITECTURE.md`, not real classes. `RemoteSimulationProvider`
    simulates the async network *shape* (latency, timeout, retry) entirely
    in-process — it never talks to a real network or a real remote signer.
12. **The hosted verifier does not check trust or run admission.** `besa
    serve` answers exactly one question — "is this signature
    cryptographically valid" — the same as `besa verify` without a `--trust`
    flag. It never checks trust-store membership, never runs `admit`, never
    issues receipts, and has no authentication, rate limiting, or TLS
    termination of its own (an operator must front it with a reverse proxy
    for any of those). See `docs/HOSTED_VERIFIER.md`'s limitations table for
    the complete list.
13. **Rotation-race safety for a not-yet-built provider tier.** Today's two
    `KeyProvider` implementations (`LocalKeyProvider`,
    `RemoteSimulationProvider`) each hold one fixed key for their lifetime,
    so neither has a live rotation window to exploit. A future
    mutable-key-alias provider (a KMS "alias" pointing at a rotatable key
    version) would introduce a real window between `getKeyId()` and
    `sign()` observing different key versions; verification would catch the
    resulting mismatch after the fact (guarantee #4 above), but nothing
    prevents the race from occurring inside such a provider — no such
    provider exists in this repository to test against.
14. **An admission attestation is not a receipt and does not enforce budget
    remotely.** `POST /v1/admit` (`docs/RUNTIME_ADMISSION.md`) reads the
    meter but never consumes it, never writes `.besa/receipts/`, and does
    not prove a tool call was actually executed. A caller wanting a real,
    budget-consuming, execution-tied signed record must still use the local
    `besa receipt` flow. Enabling `--trust` on `besa serve` also means the
    server process holds decrypted signing key material for its entire
    uptime — a materially larger blast radius than the plain Hosted
    Verifier's guarantee (#11 above) that it never loads a key at all.

## Trust boundary, stated once

The trust boundary is always the trust store belonging to whichever party
runs `verify`/`admit`/`receipt` — everything on the signer's side (key
generation, custody, signing) is outside that party's control. Separately,
for the `KeyProvider` abstraction specifically, the trust boundary is the
provider implementation itself: Besa's signing/verification logic treats
every provider as untrusted input whose output must independently verify.
These are two instances of the same principle applied at two different
seams (consumer trust store; provider implementation) — Besa never extends
trust based on a self-report from either.

## Source documents

- `TRUST_MODEL.md` — identity, key lifecycle, cross-organization trust.
- `PROVIDER_THREAT_MODEL.md` — per-attacker analysis of the `KeyProvider`
  seam.
- `KEY_PROVIDER_ARCHITECTURE.md` — provider tiers, failure model, SDK
  surface decisions for the provider abstraction.
- `PHASE4_HARDENING_AUDIT.md` — what was fixed and what was deliberately
  deferred as of Phase 4.
- `REPLAY_PROTECTION_ANALYSIS.md`, `ALGORITHM_AGILITY_DESIGN.md` — Phase 5
  analyses of two of the non-guarantees above, in full depth.
- `HOSTED_VERIFIER.md` — architecture, endpoint reference, and threat model
  for `besa serve`.
- `RUNTIME_ADMISSION.md` — architecture, endpoint reference, and threat
  model for the opt-in `besa serve --trust` admission route (Phase 7).

This document will drift the moment any of the above changes. It is a
snapshot, not a live-generated artifact — re-verify against the source
documents and the current test suite before relying on it for anything
beyond a first orientation.
