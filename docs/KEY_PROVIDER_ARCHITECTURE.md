# Besa Key Provider Architecture

Architecture notes only. This document describes the shape of the
`KeyProvider` abstraction and how it extends toward remote/hardware key
custody. **No KMS, HSM, or Vault integration is implemented in this
repository.** No compliance claim, no production-readiness claim.

## Guarantees, non-guarantees, and trust boundary

**Guaranteed:** every `KeyProvider` implementation, regardless of tier,
produces signatures that verify identically through the same
`verifySignedManifest`/`verifyReceiptDetailed` path — the interface's
three methods are the *only* contract a provider must satisfy; nothing
downstream special-cases which tier signed an artifact. Confirmed by
`src/tests/provider-signing.test.ts` and `provider-security.test.ts`:
provider-signed artifacts are verify-compatible, and mismatched
identity/corrupted signatures fail closed exactly as they do for the
legacy path.

**NOT guaranteed by the interface itself:**
- That `getKeyId()` and `getPublicKey()`/`sign()` refer to the same key —
  this is why `verifySignedManifest` independently recomputes
  `publicKeyId(signed.publicKey)` and compares it to the claimed
  `publicKeyId` rather than trusting a provider's self-report (see
  `provider-security.test.ts`, "misreports its own key id"). A provider is
  not a trusted component in this sense; it is verified like any other
  input.
- That `sign()` is safe to call concurrently, or that `getKeyId()` and
  `sign()` observe the same key version if the underlying key rotates
  mid-call (`KMS_HSM_READINESS.md`, "Key rotation mid-flight") — this is a
  constraint on provider implementations, not something the interface
  enforces.
- That a provider fails safely under load, timeout, or partial outage —
  see `KMS_HSM_READINESS.md`'s failure model; `KeyProvider.sign()` rejecting
  is the only contract, retry/backoff policy is the caller's problem.

**Trust boundary:** the boundary is the `KeyProvider` implementation
itself. Besa's signing/verification logic treats every provider as
untrusted input whose output must independently verify — a compromised or
buggy provider can produce a bad signature, but cannot produce an artifact
that passes verification without actually possessing the private key
`publicKeyId` claims. A compromised provider *can* refuse to sign, sign the
wrong payload, or leak key material on its own side — none of which Besa's
verification layer can detect or prevent; that is the provider
implementation's own security responsibility.

## Provider model

Three tiers of key custody, one interface:

```typescript
export interface KeyProvider {
  getPublicKey(): Promise<string>;
  getKeyId(): Promise<string>;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}
```

| Tier | Implementation today | Where private key material lives |
|---|---|---|
| Local | `LocalKeyProvider` (`src/keys/local-provider.ts`) | Decrypted into the Besa process's memory for the duration of a `sign()` call, sourced from `.besa/key.json` (AES-256-GCM + scrypt at rest) |
| Remote / KMS | not implemented | Never in the Besa process — a cloud KMS service, reached over a network call |
| Hardware / HSM | not implemented | Never leaves a hardware security module; the module performs the Ed25519 (or provider-supported curve) operation internally |

The interface is deliberately the same regardless of tier. Every caller —
`signManifestWithProvider`, `createReceiptWithProvider` — only ever sees
`getPublicKey()` / `getKeyId()` / `sign()`. A caller cannot tell, from the
interface alone, whether it is talking to a file on disk or a hardware
module across the network. That is the point: the trust and canonicalization
logic in `src/signing.ts` is tier-agnostic by construction, not by
convention.

## Future KMS pattern

Illustrative shape only — no such class exists in this repository:

```
Besa (signManifestWithProvider / createReceiptWithProvider)
  |
  v
KeyProvider interface           <-- stable contract, defined today
  |
  v
KmsKeyProvider (hypothetical)
  |
  v
Cloud KMS API (e.g. AWS KMS Sign, Azure Key Vault sign, GCP Cloud KMS)
  |
  v
Hardware root key
  (never exported, never held in Besa's process memory)
```

A `KmsKeyProvider.sign()` would serialize the payload, call the KMS
provider's signing API (authenticated via that provider's own IAM/identity
mechanism — out of scope for Besa to reimplement), and return the raw
signature bytes. `getPublicKey()`/`getKeyId()` would either cache the KMS
key's exported public key locally or fetch it from the KMS describe/get-key
API — both are implementation details the `KeyProvider` interface hides
from every caller.

The same shape applies to `HsmKeyProvider` (PKCS#11 or a vendor SDK) and
`VaultKeyProvider` (HashiCorp Vault's Transit secrets engine) — different
transport and authentication underneath, identical interface above.

## Why the interface is async-first

`LocalKeyProvider.sign()` is synchronous under the hood (`signWithKeyPair()`
in `src/crypto.ts`, a plain `node:crypto` call) but the interface returns
`Promise<Uint8Array>` regardless. This was decided in Phase 2 and holds
through Phase 3:

- Every non-local tier is inherently a network call: KMS APIs, HSM PKCS#11
  sessions over a network-attached module, and Vault's HTTP API are all
  asynchronous by nature. There is no synchronous variant of "ask a remote
  service to sign something" in Node.js.
- An interface cannot be widened from sync to async later without breaking
  every existing implementer and caller. Committing to `Promise` now, while
  the only implementation is trivially synchronous, costs nothing (wrapping
  a sync value in `Promise.resolve()` is free) and avoids a breaking change
  the moment a second, real-network provider is built.
- This is exactly why `signManifestWithProvider`/`createReceiptWithProvider`
  are separate, new, `async` functions rather than a change to
  `signManifest`/`createReceipt` — those two stay synchronous forever
  (see "Backward compatibility" in the Phase 3 report), because making them
  `async` to call an async provider would itself be the breaking change this
  entire architecture exists to avoid.

## Failure model

None of the following is implemented as retry/backoff/circuit-breaker logic
today — `LocalKeyProvider` has no failure modes beyond "the key file is
missing or the passphrase is wrong," which the existing CLI already handles
(see `TRUST_MODEL.md` and the Phase 2 secret-hygiene work). This section
describes what a remote provider's failure surface would need to account
for, as a design constraint on any future implementation:

- **Unavailable provider** (network partition, KMS region outage): `sign()`
  rejects. A caller like `besa sign`/`besa receipt` has no meaningful
  fallback — signing must fail closed, exactly as a missing local key file
  fails closed today. No implicit retry loop belongs inside the provider
  itself; retry policy is a caller/operator decision, not something
  `KeyProvider` should hide.
- **Timeout**: same treatment as unavailable — a `sign()` that never
  resolves must eventually reject via whatever timeout mechanism the
  concrete provider chooses (e.g. an AWS SDK client's configured request
  timeout). Besa's call sites do not need bespoke timeout handling as long
  as the provider's promise always eventually settles.
- **Invalid signature returned**: cannot happen silently — every signing
  call site immediately builds the full artifact and the caller (or a
  subsequent `besa verify`) runs it through `verifySignedManifest`/
  `verifyReceiptDetailed`, which independently recomputes the canonical
  payload and checks the signature with `node:crypto`'s `verify()`. A
  provider bug that returns garbage bytes is caught by the existing
  verification path, not by new code in the provider.
- **Permission denied** (IAM policy rejects the sign call, HSM session
  lacks the right key handle): `sign()` rejects with whatever error the
  underlying SDK raises. Fail closed — no artifact is produced, no partial
  receipt is written. This mirrors the existing `keystore.ts` behavior: a
  wrong passphrase throws `"key file authentication failed"` rather than
  returning a degraded result.
- **Key rotation mid-flight**: if a provider's underlying key is rotated
  between `getKeyId()` and `sign()` within one call, the returned signature
  could correspond to a different key than the `publicKeyId` embedded in
  the artifact body. This is a correctness hazard specific to providers
  backed by mutable remote key aliases (e.g. a KMS "alias" pointing at a
  new key version). A future concrete provider must either pin the exact
  key version for the duration of one signing call, or `getKeyId()`/`sign()`
  must be guaranteed atomic by the provider's own API — Besa's call sites
  cannot detect or correct this after the fact, only `verifySignedManifest`
  after signing would catch a resulting mismatch.

## Key lifecycle (provider-agnostic)

Extends `TRUST_MODEL.md` §2 with the provider dimension:

- **Creation**: local — `generateKeyPairSync("ed25519")`. Remote/hardware —
  the provider's own key-creation API (e.g. `kms:CreateKey`); Besa would
  never generate key material on a remote tier's behalf, only reference an
  already-created key by its provider-specific identifier.
- **Activation**: unchanged from `TRUST_MODEL.md` — a key becomes trusted
  only when a consumer explicitly runs `trust add`/`trust apply`, regardless
  of which tier holds the private key.
- **Rotation**: local rotation (`besa keys rotate`) generates a new local
  key pair and a signed `KeyRotation` proof. A remote-tier rotation would
  instead point the provider at a new remote key (e.g. a new KMS key ARN)
  and produce the same `KeyRotation` proof format — signed by the *new* key
  over `{previousPublicKey, newPublicKey}` — so `trust apply` on the
  consumer side is identical regardless of which tier signed the rotation.
- **Revocation**: unchanged — a trust-store-local `"revoked"` status,
  independent of where the revoked key's private material lives.
- **Archival**: local keys are archived encrypted under `.besa/keys/`
  (`TRUST_MODEL.md` §2). A remote-tier key's "archival" is whatever the
  provider's own lifecycle policy does with a deactivated key (e.g. AWS KMS
  key deletion has a mandatory waiting period); Besa does not manage that
  lifecycle, only records the rotation proof that stops trusting it for new
  admissions.

## SDK surface decision (Phase 3, Task 6)

Analyzed and decided deliberately, not by default:

**`KeyProvider` and `LocalKeyProvider` are NOT exported through `sdk.ts`.**
They remain reachable only via their module path
(`besa/dist/keys/provider.js`, `besa/dist/keys/local-provider.js`), which is
also not currently listed in `package.json`'s `files` array — i.e. they are
source-available in this repository but not yet part of the published npm
package's supported surface.

Reasoning:

- **Stability**: the interface has exactly one implementation
  (`LocalKeyProvider`) and zero real-world non-local implementations to
  validate the three-method shape against. Freezing it into the public SDK
  surface now — where the existing `sdk-surface.test.ts` mechanism makes
  every future change to it an explicit, tracked breaking-change decision —
  would lock in a contract before a second provider has ever exercised it.
  `getPublicKey()`/`getKeyId()` returning separate promises rather than one
  combined `getIdentity()` call, for instance, is a shape that a real KMS
  provider might reveal to be awkward (two round-trips instead of one) —
  exactly the kind of thing you want to learn *before* freezing an export.
- **Breaking-change risk**: none today (it is unused by any shipped
  artifact), which is precisely why this is the right moment to leave it
  unexported — the cost of waiting is zero, the cost of exporting
  prematurely and needing to change it later is a major-version bump.
- **Future API responsibility**: exporting a type is a promise to keep
  supporting it. `KeyProvider` is infrastructure other people would build
  against; that promise should be made once, deliberately, with at least
  one additional real provider implementation in hand — not as a side
  effect of implementing the first one.

**`signManifestWithProvider`, `createReceiptWithProvider`,
`createKeyRotationWithProvider`, and `signWithKeyPair` ARE exported through
`sdk.ts`.** These are the actual Task 1 deliverable — usable functions, not
a type consumers must commit to implementing against. TypeScript's
structural typing means a consumer can already call
`signManifestWithProvider(manifest, myCustomProvider)` today, passing any
object shaped like `KeyProvider`, without ever importing the interface
itself. Exporting the functions now and the interface later (once proven)
is the minimal, clean addition Task 6 asks for when the answer is "yes, but
not the type."

**Phase 4 update:** `sdk.ts` switched from `export * from "./crypto.js"` to
an explicit named list for the same reason `KeyProvider`/`LocalKeyProvider`
were never blanket-exported: `export *` had silently leaked
`privateKeyFromDer` (an internal primitive, still used inside `crypto.ts`
and by tests importing directly from `crypto.js`, but never a deliberate
public-API decision) and `hashObject` (a domain-unseparated hash helper
with zero internal callers, since deleted as dead code). See
`PHASE4_HARDENING_AUDIT.md` for the full before/after. This does not change
the `KeyProvider`/`LocalKeyProvider`/`RemoteSimulationProvider` non-export
decision above — those remain intentionally unexported for the same
reasons, unaffected by this cleanup.
