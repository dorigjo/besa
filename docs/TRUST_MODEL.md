# Besa Trust Model

This document describes Besa's trust architecture: what identifies an agent
or a tool publisher, how keys move through their lifecycle, and how two
independent parties establish trust in each other's signed artifacts.

It describes architecture only. No compliance claim, no certification claim,
and no statement about production readiness is made or implied by this
document. Besa today is a local, single-operator early-access tool — this
document describes the trust primitives it is built on and how they extend.

## Guarantees, non-guarantees, and trust boundary

**Guaranteed:**
- A signature that verifies (`verifySignedManifest`/`verifyReceiptDetailed`
  returning `valid: true`) means the exact canonical bytes of that artifact
  were signed by the holder of the private key matching `publicKeyId`, and
  have not been altered since. This is a cryptographic guarantee (Ed25519),
  not a heuristic.
- A trust store (`TrustStore`) only ever contains keys a consumer
  explicitly added — there is no ambient or implicit trust of any key.
- `checkTrustedKey()` rejects a revoked key unconditionally, including for
  historical artifacts; it accepts a retired key only for artifacts signed
  before retirement, never for new admissions.

**NOT guaranteed:**
- That the entity holding a trusted key is who it claims to be
  (`serverName`, `agentId`) — Besa verifies *cryptographic continuity*
  (same key signs same identity over time), not *real-world identity*.
  Binding a key to a real organization is an out-of-band act (however the
  consumer chose to first trust that key), not something `trust add` or
  `verifySignedManifest` establishes on their own.
- That `agentId` on a receipt reflects a verified caller — see §1: it is a
  caller-supplied label recorded as evidence, not an authenticated claim.
- That a key that has never been revoked is safe to trust — Besa has no
  mechanism to detect compromise; revocation is only ever a manual,
  local-to-one-trust-store action (§3).
- Anything about the tool's behavior or the correctness of its output —
  Besa attests to *who published this manifest* and *what decision was
  made*, never to what the tool itself actually does when called.

**Trust boundary:** the boundary is the trust store
(`.besa/trust.json` or a `--trust`-specified file) belonging to whichever
party runs `verify`/`admit`/`receipt`. Everything on the signer's side (key
generation, custody, signing) is outside that party's control and outside
what Besa can enforce — Besa can only tell them whether an artifact came
from a key they already decided to trust. There is no boundary Besa
enforces *between* two consumers; each trust store is independent.

## 1. What identifies a Besa key

A Besa **identity anchor** is an Ed25519 public key, addressed by its
SHA-256 fingerprint (`publicKeyId`, computed by `publicKeyId()` in
`src/crypto.ts`):

```
Identity anchor
=
Ed25519 public key (SPKI DER, base64)
+
publicKeyId = sha256(publicKeyDer)
```

This is deliberately minimal. Besa does not currently attach organization
metadata, agent names, or lifecycle state to the key itself — that
composition happens one layer up, in the artifacts the key signs:

- A **signed manifest** (`SignedManifest`, `src/types.ts`) binds a
  `publicKey`/`publicKeyId` to a `Manifest` describing a *tool publisher*:
  server name, version, URL, and the tools it exposes.
- A **receipt** (`Receipt`) binds a `publicKeyId` to a tool-call decision,
  optionally carrying an `agentId` — a caller-supplied string identifying
  *which agent* requested the call. Besa does not mint or verify agent
  identity today; `agentId` is evidence recorded alongside the decision, not
  an authenticated claim.

So today: **a key identifies a publisher of signed artifacts.** Agent
identity is a label attached to admission decisions and receipts, not yet a
cryptographically verified principal. Extending `agentId` to a proper
per-agent key (agents sign their own requests, and receipts carry that
signature too) is a natural next step but is explicitly out of scope for
this document — it is architecture to grow into, not something implemented.

## 2. Key lifecycle

Implemented today (`src/trust.ts`, `keys rotate` / `trust apply` / `trust
revoke` in `src/index.ts`):

### Creation
`besa keys` generates an Ed25519 key pair (`generateKeyPair()`), encrypts
the private key at rest with AES-256-GCM under a scrypt-derived key
(`sealKeyPair()`, `src/keystore.ts`), and stores it under `.besa/key.json`
(or a caller-chosen path via `--key-file`). The public key is not trusted by
anyone until it is anchored.

### Anchoring (trust)
`besa trust add <signed-manifest>` or the trust-anchoring step of `besa
sign` adds a key to a `TrustStore` (`src/types.ts`) with status `"active"`.
A trust store is local, per-consumer state — there is no shared or hosted
registry. Two consumers can trust different keys, or the same key added at
different times; nothing here is implicitly global.

### Rotation
`besa keys rotate` generates a new key pair, produces a signed
`KeyRotation` proof (`createKeyRotation()` — the new key's Ed25519 signature
over `{previousPublicKey, newPublicKey}`), archives the old encrypted key
under `.besa/keys/<oldId>.json`, and writes the new key to the active key
path. `besa trust apply <rotation>` lets a *different* trust store holder
retire the old key and trust the new one, using the rotation proof as
evidence rather than requiring the operator's word.

Rotation retires the old key (status `"retired"`) rather than deleting it:
`checkTrustedKey()` still accepts a retired key's signature on artifacts
signed *before* the retirement, but rejects a retired key for new
admission decisions (`verifyTrustedSignedManifest(..., "admit")` treats
retired specially). This is what lets historical receipts stay verifiable
after rotation without allowing a rotated-out key to keep authorizing new
tool calls.

### Revocation
`besa trust revoke <keyId>` marks a key `"revoked"` in a trust store.
Unlike retirement, revocation is unconditional: `checkTrustedKey()` rejects
a revoked key even for historical verification. Revocation is local to a
trust store — it is a statement "I no longer trust artifacts under this
key," not a signed, distributable proof the way rotation is. There is
intentionally no notion of a global revocation list; that is exactly the
kind of hosted registry the MVP scope excludes (see the project's founder
constraints document).

### Recovery
There is no key recovery. Losing `.besa/key.json` and its passphrase means
the operator can no longer sign as that identity; anyone who trusted that
key sees signatures simply stop verifying against new artifacts. This is a
deliberate simplicity trade-off for a local, single-operator tool — a
future KMS/HSM-backed `KeyProvider` (see below) changes the recovery story
by moving custody off the local filesystem entirely.

## 3. Cross-organization trust

Scenario: Company A publishes a tool manifest and signs it with its own
key. Company B wants to call that tool from its own agent and needs to
decide whether to admit the call.

```
Company A                          Company B
----------                         ----------
besa sign manifest.yaml
  -> manifest.signed.json    -->   besa trust add manifest.signed.json
                                     (B now trusts A's publicKeyId)

                                    besa verify manifest.signed.json
                                     (checks signature + B's trust store)

                                    besa admit manifest.signed.json <tool>
                                     (checks trust, budget, and B's own
                                      grants for the calling agent)
```

The decision "can this agent use this tool" is always made by the party
running `admit`/`receipt` (B), against B's own local trust store and
grants. A never gains any authority over B's runtime; A's signature only
proves "this manifest, as published, came from the holder of this key and
has not been altered." Trust anchoring (`trust add`) is an explicit,
one-time act — there is no ambient trust, and no key is trusted merely by
appearing in a signed artifact B receives.

If A rotates its key, A distributes the resulting `KeyRotation` proof out
of band (however A and B already exchange files today); B applies it with
`trust apply` to keep verifying A's artifacts without a new manual
trust-add. If A's key is compromised, A can only ask B (and every other
consumer) to run `trust revoke` — there is no mechanism today for A to
push a revocation to consumers it does not control. That gap is the
natural argument for a future hosted transparency log, but building one is
explicitly out of MVP scope.

## 4. Where KeyProvider fits

`src/keys/provider.ts` defines:

```typescript
export interface KeyProvider {
  getPublicKey(): Promise<string>;
  getKeyId(): Promise<string>;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}
```

`src/keys/local-provider.ts`'s `LocalKeyProvider` wraps an already-decrypted
`KeyPair` and signs with the same `node:crypto` Ed25519 path `signManifest`/
`createReceipt` use today — byte-identical signatures, no new algorithm, no
new dependency (see `src/tests/keys.test.ts`).

The identity model above does not change when a future `KmsKeyProvider` or
`HsmKeyProvider` implements the same interface: `getKeyId()` still returns a
`publicKeyId`, trust stores still anchor on that fingerprint, rotation and
revocation proofs are still signatures over public keys. What changes is
custody — `sign()` becomes a network call to a service that never exposes
`privateKeyDer` to the Besa process at all. This document intentionally
does not commit to a specific KMS/HSM integration; it commits to the
identity and trust primitives staying stable underneath one.
