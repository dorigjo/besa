# Provider Future Compatibility

> **Status update:** the "open questions" line at the end of this document's
> Verdict names `createKeyRotationWithProvider` as unaddressed. It has since
> been implemented (Phase 4 hardening, see `PHASE4_HARDENING_AUDIT.md`) —
> the algorithm-support question below remains open, the rotation question
> does not.

Assessment only — extends `KMS_HSM_READINESS.md` (Phase 3: AWS KMS, Google
Cloud KMS, Azure Key Vault, PKCS#11) with the three backends Phase 4.6 adds
to the list: HashiCorp Vault, CloudHSM, and Sigstore. Same method: does the
`KeyProvider` interface's three-method shape fit, and does the backend
actually support Ed25519 (the only algorithm Besa's artifact format
accepts today)? No backend is implemented here — no new dependency, no SDK
installed, no interface change made.

```typescript
export interface KeyProvider {
  getPublicKey(): Promise<string>;
  getKeyId(): Promise<string>;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}
```

## HashiCorp Vault (Transit secrets engine)

**Fits, and Ed25519 is supported.** Vault's Transit engine supports
`ed25519` as a key type directly (`vault write transit/keys/mykey
type=ed25519`); its `transit/sign/:name` HTTP endpoint takes a base64
payload and returns a base64 signature — maps directly to `sign(payload)`.
`transit/keys/:name` (a GET) returns the public key, covering
`getPublicKey()`; `getKeyId()` would return a SHA-256 fingerprint computed
locally from that exported key, identical to how `publicKeyId()` works
today for `LocalKeyProvider`. Of the seven backends now evaluated across
this document and `KMS_HSM_READINESS.md`, Vault is the second (after GCP
Cloud KMS) with no algorithm caveat at all.

A `VaultKeyProvider.sign()` would be an HTTP POST to Vault's API,
authenticated via a Vault token — out of scope for `KeyProvider` to define
(same as every other backend: authentication is the concrete provider's
responsibility, not the interface's).

## CloudHSM (AWS CloudHSM)

**Fits the interface shape; Ed25519 support depends on the client library
generation.** AWS CloudHSM is a dedicated single-tenant HSM (distinct from
AWS KMS, which is why it gets its own entry despite living in the same
cloud) accessed via PKCS#11, a JCE provider, or the CloudHSM Client SDK.
As a PKCS#11-compliant device, the same conclusion as `KMS_HSM_READINESS.md`'s
PKCS#11 entry applies: Ed25519 (`CKM_EDDSA`) support depends on the
specific CloudHSM firmware/client SDK version, not on the PKCS#11 standard
itself, which does permit it. `sign()` would wrap `C_Sign` through
CloudHSM's PKCS#11 library exactly as a generic `Pkcs11KeyProvider` would
— CloudHSM does not introduce a shape this interface doesn't already
accommodate; it is a specific vendor/deployment of the PKCS#11 case
already assessed, not a new category.

## Sigstore

**Different trust model — fits mechanically, but changes what "signing"
means.** Sigstore (`cosign`/`fulcio`/`rekor`) is built around short-lived
certificates issued to an OIDC identity plus a public transparency log
(Rekor), not long-lived key custody in the way KMS/HSM/Vault/local-file
all are. Mapping it onto `KeyProvider` is possible but stretches the
abstraction:

- `sign(payload)` could wrap `cosign sign-blob` (or the Sigstore Go/JS
  client libraries) to produce a signature under an ephemeral Fulcio-issued
  certificate — mechanically returns `Promise<Uint8Array>`, satisfying the
  interface.
- `getPublicKey()`/`getKeyId()` are awkward here: Sigstore's model doesn't
  have a stable long-lived public key the way the other six backends do —
  identity is proven per-signature via a short-lived cert plus OIDC token,
  not a persistent keypair. A `SigstoreKeyProvider.getPublicKey()` would
  have to either mint the ephemeral cert early and cache it for the
  duration of one Besa signing call, or return something that isn't
  really "the" public key in Besa's current sense (Besa's model assumes
  one stable key with a stable `publicKeyId` across many signatures, e.g.
  across `trust apply` and every subsequent `besa verify`).
- Sigstore's own value proposition — a public transparency log, ephemeral
  identity-bound certs instead of long-lived keys — is a genuinely
  different trust model than Besa's current "one Ed25519 keypair,
  explicitly trust-anchored per consumer" design (`TRUST_MODEL.md`).
  Adopting it as a `KeyProvider` tier would mean Besa's verification layer
  also needs to understand certificate chains and (optionally) Rekor
  inclusion proofs, not just a raw Ed25519 signature — a change to
  `verifySignedManifest`/`verifyReceipt`, not just a new provider class.

**Conclusion for Sigstore specifically: does not fit today's `KeyProvider`
interface as cleanly as the other six.** It is architecturally possible to
wrap `sign()`, but a faithful Sigstore integration is a different trust
model, not just a new implementation of the existing seam — correctly out
of scope for a minimal extension.

## Cross-cutting findings (all seven backends, this document + `KMS_HSM_READINESS.md`)

| Backend | Interface shape fits | Ed25519 support | Blocker (if any) |
|---|---|---|---|
| AWS KMS | Yes | No | Algorithm — Besa artifact format is Ed25519-only |
| Google Cloud KMS | Yes | Yes | None |
| Azure Key Vault | Yes | No | Algorithm — same as AWS KMS |
| PKCS#11 (generic HSM) | Yes | Depends on firmware | Not universal, but not excluded |
| HashiCorp Vault (Transit) | Yes | Yes | None |
| AWS CloudHSM | Yes | Depends on client SDK/firmware | Same class of caveat as generic PKCS#11 |
| Sigstore | Partial — stretches the model | N/A (different trust model) | Trust model mismatch, not algorithm |

Six of seven backends fit the existing three-method shape without any
interface change. The recurring blocker across AWS KMS/Azure Key
Vault/PKCS#11/CloudHSM is Ed25519 algorithm availability, not
`KeyProvider`'s shape — consistent with `KMS_HSM_READINESS.md`'s original
finding. Sigstore is the one genuine outlier, and it's an outlier in trust
model, not interface plumbing.

## Verdict

**No change to `KeyProvider` is made or proposed as a result of this
assessment.** Per the task's own conditional ("erweitere nur minimal falls
wirklich nötig") — nothing here rises to "truly necessary": every backend
that fits (five of seven, plus PKCS#11/CloudHSM conditionally) fits the
interface exactly as it stands today, and the one backend that doesn't fit
well (Sigstore) would require a *trust-model* change to
`verifySignedManifest`/`verifyReceipt`, not a `KeyProvider` interface
change — extending the interface wouldn't fix that gap anyway, so
extending it now would be speculative work against a backend that isn't
being built. This reinforces, rather than revises, `KMS_HSM_READINESS.md`'s
original verdict: the interface is ready; the open questions are algorithm
support (artifact format) and `createKeyRotationWithProvider`, both
already named there and neither addressed in this pass.
