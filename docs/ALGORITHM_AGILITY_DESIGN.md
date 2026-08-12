# Algorithm Agility Design

Design only — no implementation, no new algorithm added, no code changed as
a result of this document. Answers: what does the current Ed25519-only
format prevent, what would a second algorithm require, and how is a
breaking change avoided.

## Current state, precisely

`algorithm: "ed25519"` is a TypeScript **literal type** (not `string`) in
`SignedManifest`, `Receipt`, and `KeyRotation` (`src/types.ts:29,54,95`),
enforced redundantly by four separate validators
(`validateSignedManifest`, `validateReceipt`, `verifyKeyRotation`, plus the
early-exit checks in `verifySignedManifest`/`verifyReceiptDetailed`). Two
further places hardcode Ed25519 specifically, not just the literal type:

- `isSignature()` (`signing.ts:92`) requires exactly 88 base64 characters
  (a fixed 64-byte Ed25519 signature) — this would reject an RSA-2048
  signature (256 bytes) or a PQC signature (often several KB) outright,
  independent of the `algorithm` field check.
- `isPublicKeyEncoding()` (`signing.ts:101`) caps public keys at 128 base64
  characters (~96 bytes) — enough for an Ed25519 SPKI DER key (44 bytes),
  far too small for an RSA-2048 public key (~294 bytes DER) or a PQC key
  (often 1-2 KB).
- `publicKeyFromDer`/`privateKeyFromDer` (`crypto.ts:144,158`) call
  `createPublicKey`/`createPrivateKey` and then explicitly throw unless
  `key.asymmetricKeyType === "ed25519"`.

**What is already algorithm-agnostic, correctly, and needs no change:**

- `canonicalize()` — pure JSON canonicalization, has no notion of
  cryptography at all.
- `signatureMessage(domain, value)` — builds the byte string that gets
  signed; algorithm-independent by construction (it produces bytes, not a
  signature).
- The `KeyProvider` interface (`src/keys/provider.ts`) — `getPublicKey()`/
  `getKeyId()` return opaque strings, `sign()` takes and returns
  `Uint8Array`. Nothing in the interface assumes Ed25519, key length, or
  signature length. A future `RsaKmsKeyProvider` could implement this
  interface today, unchanged, and would only fail downstream at the
  fixed-length validators listed above — this is genuinely good news: the
  provider abstraction does not need to change for algorithm agility, only
  the artifact validators and crypto primitives do.

## What a future artifactVersion 2 would need to look like

### Decision point: does a new algorithm require a new `artifactVersion`?

Two designs are possible. Recommending one, but naming both honestly:

**Design A — couple algorithm to artifactVersion.** Every new algorithm is
its own `artifactVersion` (v2 = "adds ECDSA," v3 = "adds RSA," ...).
Simple to reason about, but proliferates version numbers for what is really
one kind of change (a new accepted algorithm), and conflates two unrelated
concerns: artifact *shape* (field names, structure) and *algorithm*
(crypto primitive). A future field addition unrelated to algorithms (e.g. a
new optional metadata field) would then compete for the same version
number space as algorithm additions, making it unclear what "v3" actually
changed without reading a changelog.

**Design B — decouple algorithm from shape (recommended).** Keep
`artifactVersion` tracking the JSON *shape* only (field names, structure,
required-vs-optional). Widen `algorithm` from a single literal type to a
closed union validated against a per-algorithm profile registry:

```typescript
// Illustrative only — not implemented.
type SignatureAlgorithm = "ed25519" | "ecdsa-p256" | "rsa-pss-2048";

interface AlgorithmProfile {
  keyObjectType: string;        // matches node:crypto's asymmetricKeyType
  publicKeyMaxBytes: number;    // DER-encoded SPKI upper bound
  signatureMinBytes: number;
  signatureMaxBytes: number;    // some algorithms (ECDSA DER) are variable-length
}

const ALGORITHM_PROFILES: Record<SignatureAlgorithm, AlgorithmProfile> = {
  "ed25519": { keyObjectType: "ed25519", publicKeyMaxBytes: 44, signatureMinBytes: 64, signatureMaxBytes: 64 },
  "ecdsa-p256": { keyObjectType: "ec", publicKeyMaxBytes: 91, signatureMinBytes: 70, signatureMaxBytes: 72 },
  "rsa-pss-2048": { keyObjectType: "rsa", publicKeyMaxBytes: 294, signatureMinBytes: 256, signatureMaxBytes: 256 },
};
```

`isSignature()`/`isPublicKeyEncoding()` become parameterized by the
artifact's own `algorithm` field (looked up in the registry) instead of one
hardcoded constant. The JSON *shape* of `SignedManifest`/`Receipt` does not
change at all — same field names, same structure — so this does **not**
require a new `artifactVersion` under Design B. A new `artifactVersion`
would only be needed the day an actual *shape* change is needed (a new
required field, a restructured envelope) — a materially different, rarer
kind of change than "we now also accept ECDSA."

**Recommendation: Design B.** It keeps `artifactVersion` meaningful (shape
changes only), avoids version-number proliferation for what is really an
allowlist widening, and requires the smallest actual code change: a
registry lookup replacing two hardcoded constants, not a parallel
`buildManifestBodyV2`/`verifySignedManifestV2` universe.

### Signature domain separation must still change per algorithm addition

`signatureMessage(domain, value)` (`crypto.ts:196`) hardcodes the literal
string `"v1"` into every signed byte string:
`` besa:${domain}:v1\0${canonicalize(value)} ``. This is **not** the same
"v1" as `artifactVersion` — it is a separate, independent version marker
baked directly into the signed bytes, whose entire purpose is domain
separation (preventing a signature over one artifact type/version from
being replayable as a signature over a different one). Adding a new
algorithm under Design B does **not** require changing this string, because
the *domain* (what is being signed — `"signed-manifest"`, `"receipt"`,
`"key-rotation"`) and the *algorithm* (how it's signed) are orthogonal — the
same domain string remains correct regardless of which algorithm produced
the signature. This string only needs to change if the *shape* being signed
changes (an actual `artifactVersion` bump), which is exactly why Design B
keeps it stable for algorithm-only additions and consistent with the
shape-only meaning of `artifactVersion`.

## How breaking changes are avoided

1. **Every existing Ed25519 artifact keeps verifying, unmodified, forever.**
   `algorithm: "ed25519"` stays a valid, permanently-supported member of the
   widened union — nothing about existing artifacts, existing signatures,
   or existing `LocalKeyProvider`/`RemoteSimulationProvider` behavior
   changes. This is not a promise that needs to be kept carefully — it
   falls out structurally from widening a union rather than replacing a
   literal type.
2. **Old verifiers reject new-algorithm artifacts safely, not silently.**
   An algorithm value outside `ALGORITHM_PROFILES` is already rejected
   today by the existing `algorithm !== "ed25519"` check's spirit (adapted
   to `!(algorithm in ALGORITHM_PROFILES)`) — this is the same fail-closed
   behavior already proven by `verifySignedManifest fails on unsupported
   algorithm` (existing test, `besa.test.ts`). A Besa installation that
   hasn't upgraded to recognize `"ecdsa-p256"` rejects such an artifact with
   `E_ALGORITHM_UNSUPPORTED`, exactly as it does today for any unrecognized
   value — no new failure mode, no crash, no silent downgrade.
3. **`KeyProvider` interface: zero changes required.** As established above,
   the interface is already algorithm-agnostic. A future `RsaKeyProvider`
   or `EcdsaKeyProvider` implements the same three methods `LocalKeyProvider`
   does today. `signManifestWithProvider`/`createReceiptWithProvider`/
   `createKeyRotationWithProvider` need zero changes — they already only
   call the three interface methods and never assume signature/key length.
4. **`signWithKeyPair`/`validateKeyPair` (the legacy `KeyPair` path) would
   need an algorithm parameter or a second algorithm-aware variant** — these
   two functions are the ones that hardcode the Ed25519 check via
   `publicKeyFromDer`/`privateKeyFromDer`. Under Design B, the minimal
   change is parameterizing `validateKeyPair`'s internal key-type check by
   the profile registry rather than a hardcoded `"ed25519"` string —
   additive, not breaking, since existing callers passing Ed25519 keys see
   identical behavior.

## Post-quantum cryptography (PQC) — same design, different numbers

Nothing above assumes Ed25519-family curves specifically. A PQC scheme
(e.g. ML-DSA/Dilithium) fits the same `AlgorithmProfile` shape — larger
`publicKeyMaxBytes`/signature bounds (Dilithium3 public keys are ~1952
bytes, signatures ~3293 bytes), and `node:crypto`'s `asymmetricKeyType`
would need to actually support the scheme (as of this document, Node's
built-in `crypto` module does not implement PQC signature algorithms — a
PQC `KeyProvider` would need to wrap an external library for the signing
operation itself, which the `KeyProvider.sign()` interface already
accommodates without modification, exactly as `RemoteSimulationProvider`
proves for a structurally different provider today). The one number worth
naming: `MAX_CANONICAL_BYTES` (1 MB, `crypto.ts:18`) has ample headroom for
PQC key/signature sizes (low KB range), so no canonicalization limit needs
to change for PQC specifically.

## What this document does not do

No algorithm was added. No validator was changed. No `artifactVersion 2`
exists. This is the design that a future, separately-scoped implementation
task would follow — writing it down now is what lets that future task be a
small, reviewable diff instead of a from-scratch design exercise done under
time pressure when a real customer requirement (e.g. "we require RSA per
our HSM's supported key types") forces the question.
