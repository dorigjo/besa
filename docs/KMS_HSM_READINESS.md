# KMS / HSM Readiness Assessment

Assessment only. **No KMS, HSM, or cloud SDK is implemented or installed in
this repository.** This evaluates whether `KeyProvider` (`src/keys/provider.ts`)
could support each backend, not whether it does.

> **Status update:** this document's "cross-cutting readiness findings" and
> verdict below still describe the state as of Phase 3. `createKeyRotationWithProvider`
> — named below as a missing gap — now exists (Phase 4 hardening,
> see `PHASE4_HARDENING_AUDIT.md`). The original findings are left unedited
> to preserve the audit trail; treat `PHASE4_HARDENING_AUDIT.md` as current.

```typescript
export interface KeyProvider {
  getPublicKey(): Promise<string>;
  getKeyId(): Promise<string>;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}
```

## AWS KMS

**Fits.** AWS KMS's `Sign` API takes a message (or digest) and a `KeyId`,
returns raw signature bytes — maps directly to `sign(payload)`. KMS
supports `ECC_NIST_P256`/`ECC_SECG_P256K1` and RSA signing key specs, but
**does not support Ed25519** as of this assessment — Besa's entire artifact
format (`algorithm: "ed25519"` in `SignedManifest`/`Receipt`) is hard-pinned
to Ed25519 (enforced by `validateSignedManifest`/`validateReceipt`). A
literal `AwsKmsKeyProvider` implementing today's interface would need
either (a) an Ed25519-capable KMS offering, or (b) a Besa artifact-format
change to accept a second algorithm — the interface shape is not the
blocker here, the *algorithm* is. `getPublicKey()` maps to KMS's
`GetPublicKey`; `getKeyId()` can return a cached SHA-256 fingerprint of that
exported public key, computed identically to `publicKeyId()` today.

## Google Cloud KMS

**Fits, same caveat.** GCP Cloud KMS added native Ed25519 support
(`EC_SIGN_ED25519`) — so unlike AWS KMS at this assessment, a
`GcpKmsKeyProvider` could plausibly sign with the *same* algorithm Besa
already uses, with no artifact-format change. `sign()` maps to
`AsymmetricSign`; `getPublicKey()` maps to `GetPublicKey`.

## Azure Key Vault

**Fits, same AWS caveat.** Azure Key Vault's supported signing key types
(RSA, EC P-256/P-384/P-521/secp256k1) do not include Ed25519 as of this
assessment. Same conclusion as AWS KMS: the three-method shape works, the
curve does not, without a Besa artifact-format change.

## PKCS#11 HSM

**Fits, algorithm-dependent on the specific HSM.** PKCS#11 (the standard
most HSMs and smart-card tokens implement) supports Ed25519 signing
(`CKM_EDDSA` mechanism) on HSMs whose firmware implements it — not
universal across all PKCS#11 hardware, but not excluded by the standard
either. A `Pkcs11KeyProvider` would open a session, locate the key handle,
and call `C_Sign` — an inherently synchronous C API in most PKCS#11
libraries, which a Node binding would need to wrap in a `Promise` (already
what the interface expects; no mismatch).

## Cross-cutting readiness findings

- **The three-method shape (`getPublicKey`/`getKeyId`/`sign`) is sufficient
  for all four backends' core signing operation.** No backend requires a
  fourth method to perform a basic sign.
- **The blocking factor for AWS KMS and Azure Key Vault is not the
  interface — it's that Besa's artifact format is hard-pinned to Ed25519**
  and neither of those two backends offers Ed25519 signing as of this
  assessment. Supporting them would require Besa to accept a second
  `algorithm` value end-to-end (manifest/receipt validation, canonical
  signing message, verification) — a deliberate, versioned artifact-format
  change, not a `KeyProvider` change. Not proposed here; flagged as the
  real constraint.
- **`createKeyRotation()` cannot go through any of these four backends
  today** — see `PHASE3_SECURITY_AUDIT.md` §4. This is a `KeyProvider`-shape
  gap (missing `createKeyRotationWithProvider`), independent of algorithm
  support, and affects all four backends equally.
- **`getKeyId()` returning a separate round-trip from `sign()`** is a real
  cost for network-backed providers (KMS/HSM-over-network): two calls where
  one might suffice if a provider could return its key id alongside a
  signature. Not a correctness problem — `signManifestWithProvider`/
  `createReceiptWithProvider` already call `getPublicKey()`/`getKeyId()`
  once per artifact, not once per byte — but worth noting as a latency
  consideration for a future high-throughput deployment, not a blocker.

## Verdict

The `KeyProvider` interface is architecturally ready for all four backends
evaluated. It is **not** changed as part of this assessment (Task 2:
"Falls nein: NICHT sofort ändern" — and the honest answer here is closer to
"yes, with one artifact-format caveat" than "no," so there is even less
reason to touch it now). The two concrete follow-ups this assessment
surfaces for a future phase are: (1) whether/when to add a second signing
algorithm to the artifact format, and (2) `createKeyRotationWithProvider`.
Neither is built in this pass.
