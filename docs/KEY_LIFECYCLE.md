# Key Lifecycle — Data Model

Data model only. **No hosted key lifecycle system is implemented.** This
document defines the technical shape of a key's lifecycle states and
transitions, and contrasts it explicitly with what `src/types.ts` already
implements today, so the gap is visible rather than implied.

## What exists today (`src/types.ts`)

```typescript
interface TrustAnchor {
  publicKeyId: string;
  publicKey: string;
  status: "active" | "retired" | "revoked";
  addedAt: string;
  retiredAt?: string;
  revokedAt?: string;
}

interface KeyRotation {
  artifactVersion: 1;
  algorithm: "ed25519";
  previousPublicKey: string;
  previousPublicKeyId: string;
  newPublicKey: string;
  newPublicKeyId: string;
  rotatedAt: string;
  signature: string;
}
```

`TrustAnchor` is scoped to *trust store* state — it records when a
*consumer* decided to trust/retire/revoke a key, not when the key itself
was created or by whom. There is no `createdAt` (key creation time, as
opposed to `addedAt`, trust-time), no `algorithm` field on `TrustAnchor`
itself, and no expiration concept at all today.

## Proposed unified record: Key Identity

Illustrative target shape — not implemented. This is the record a future
key-lifecycle system (local or hosted) would need to represent a key's own
lifecycle, independent of any one consumer's trust store:

```typescript
interface KeyIdentity {
  keyId: string;              // SHA-256 fingerprint, same as publicKeyId today
  publicKey: string;          // canonical base64 SPKI DER
  algorithm: "ed25519";       // extend to a union if/when a second algorithm ships
  createdAt: string;          // when the key was generated, by its own provider
  status: KeyStatus;
  rotatedFrom?: string;       // keyId of the predecessor, if this key exists due to rotation
  expiresAt?: string;         // absent = does not expire (today's default, see below)
  providerTier: "local" | "kms" | "hsm";  // which KeyProvider tier holds this key
}

type KeyStatus =
  | "pending"    // created but not yet activated (see "activation" below)
  | "active"
  | "retired"    // rotated out; historical signatures still verify
  | "revoked"    // untrusted unconditionally, including historically
  | "expired";   // past expiresAt; treated the same as retired for verification purposes
```

The distinction from `TrustAnchor`: a `KeyIdentity` is a statement the *key
holder* could make about their own key ("I created this key at time T, it
is rotated from key X, it expires at time Y"), while `TrustAnchor` is a
statement a *consumer* makes ("I trust this key, as of when I added it").
Both are needed; they answer different questions. Nothing today unifies
them into one record — this is the gap this document names.

## Creation

Today: `generateKeyPair()` (`crypto.ts`), immediately encrypted at rest by
`sealKeyPair()` (`keystore.ts`). No `createdAt` timestamp is persisted
anywhere in the stored key file today — `.besa/key.json`'s `StoredKeyPair`
shape carries `version`, `publicKeyDer`, and the encryption envelope, but
not a creation time. A `KeyIdentity.createdAt` would need to be added to
that stored shape (or derived from filesystem metadata, which is not
tamper-evident) if this model were adopted.

## Activation

Today: implicit — a key becomes usable for signing the moment it's
generated (`besa keys`), and becomes *trusted by a consumer* only via
`trust add`/`trust apply` (`TrustAnchor.status = "active"`). There is no
`"pending"` state today: a freshly generated key is immediately signing-
capable. The `KeyIdentity.status = "pending"` value above is proposed for
a scenario this codebase does not have yet — e.g. a key generated inside
an HSM that requires a separate operator approval step before its first
use. Not needed for `LocalKeyProvider`.

## Rotation

Today: `createKeyRotation(previous, next)` (`trust.ts`) produces a
`KeyRotation` proof signed by the previous key over
`{previousPublicKey, newPublicKey}`. `KeyIdentity.rotatedFrom` above is the
natural generalization — a stable pointer from the new key's own record
back to its predecessor's `keyId`, independent of any consumer's trust
store having applied the rotation yet.

**Known gap** (also noted in `PHASE2_FINAL_SECURITY_AUDIT.md`): rotation
signing is `KeyPair`-only; there is no `createKeyRotationWithProvider()`.

## Revocation

Today: `revokeTrustAnchor()` sets `TrustAnchor.status = "revoked"`,
per-trust-store, unconditional (even historical signatures stop verifying —
`checkTrustedKey()`). A `KeyIdentity.status = "revoked"` would be the
key-holder's own declaration of revocation (e.g. "we know this key was
compromised"), which is a different fact than "this consumer stopped
trusting it" — today conflated because only the consumer-side fact is
modeled at all.

## Expiration

**Not implemented today in any form.** `TrustAnchor` has no `expiresAt`,
and no code path checks a key's age against any threshold. This is the
single largest gap this document surfaces relative to "what would an
enterprise key-lifecycle system need": today, a Besa key is valid
indefinitely until manually rotated or revoked. `KeyIdentity.expiresAt`
above is proposed as the field that would carry this, with `status =
"expired"` treated identically to `"retired"` by any future verification
logic (historical artifacts still verify; new admissions do not).

## Recovery

Today: none, by design (`TRUST_MODEL.md` §2, "Recovery"). Losing
`.besa/key.json` and its passphrase ends that identity permanently. This
document does not propose a recovery mechanism — key escrow, threshold
signing (Shamir/multi-party), or HSM-backed recovery are all real options
for a future phase, but choosing one is a security-posture decision with
real tradeoffs (an escrow mechanism is also a new attack surface), not
something to default into. Recorded here as explicitly open, not
implicitly solved by anything above.
