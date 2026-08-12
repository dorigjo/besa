# Provider Threat Model

Facts only — no compliance language, no marketing language. Analyzes the
`KeyProvider` abstraction (`src/keys/provider.ts`) and its two current
implementations (`LocalKeyProvider`, `RemoteSimulationProvider`) per
attacker. Scope is the signing/provider boundary specifically — the
broader trust model (key anchoring, revocation, agent identity) is covered
in `TRUST_MODEL.md` and out of scope here except where a provider-layer
attack interacts with it.

Format per attacker: **Assets** (what they're after) · **Trust Boundary**
(where they sit relative to Besa's process) · **Attack** (what they do) ·
**Detection** (what would reveal it, if anything) · **Mitigation** (what
exists today) · **Residual Risk** (what remains unmitigated).

## Attacker 1: Local filesystem attacker (reads `.besa/key.json`)

- **Assets:** the encrypted local private key file, the passphrase if
  cached or logged anywhere.
- **Trust Boundary:** outside the Besa process, but with read access to
  the local filesystem — e.g. another local user, a compromised sibling
  process, a backup that gets exfiltrated.
- **Attack:** copy `.besa/key.json` and attempt offline decryption.
- **Detection:** none built in — Besa does not monitor file access. This
  is an OS-level concern (file permissions, disk encryption), not
  something the application layer detects.
- **Mitigation:** the key file is AES-256-GCM + scrypt encrypted at rest
  (`keystore.ts`); a stolen file without the passphrase does not yield the
  private key. Passphrase is never logged, only accepted via
  `--passphrase-file`/stdin/`BESA_KEY_PASSPHRASE` (Phase 2 secret-hygiene
  work), reducing where it could leak from Besa's own process.
- **Residual Risk:** scrypt-protected files are still crackable given a
  weak passphrase and enough offline compute. `RemoteSimulationProvider`
  and a real KMS/HSM tier eliminate this attacker's target entirely — the
  private key never touches local disk in the first place — but that tier
  is not implemented today; `LocalKeyProvider` is the only tier actually
  in use.

## Attacker 2: Malicious or compromised `KeyProvider` implementation

- **Assets:** the ability to produce signatures under Besa's identity, or
  to leak key material the provider itself holds.
- **Trust Boundary:** *inside* the abstraction seam — a `KeyProvider` is
  code the application calls directly, not a network peer Besa
  authenticates. Anyone who can get their implementation constructed and
  passed to `signManifestWithProvider`/`createReceiptWithProvider`
  controls what `getPublicKey()`/`getKeyId()`/`sign()` return.
- **Attack:** implement a `KeyProvider` that signs attacker-chosen payloads
  with a real key, or that lies about which key it used
  (`getKeyId()`/`getPublicKey()` don't match what `sign()` actually used).
- **Detection:** `verifySignedManifest`/`verifyReceipt` independently
  recompute `publicKeyId(publicKey)` and verify the signature via
  `node:crypto`'s `verify()` against the exact canonical payload — a
  provider's self-report is never trusted. Demonstrated by the
  `mismatchedIdentityProvider`/`mismatchedPublicKeyProvider` test doubles
  in `provider-security.test.ts` and `provider-contract.test.ts`.
- **Mitigation:** the trust boundary is treated as the provider
  implementation itself, not the interface — every artifact a provider
  produces is verified as untrusted input before it is trusted anywhere
  else (`KEY_PROVIDER_ARCHITECTURE.md`, "Trust boundary" section).
- **Residual Risk:** a provider that signs the *correct* payload with the
  *correct* key, but has already leaked that key on its own side, is
  invisible to Besa's verification layer — that provider's output is
  cryptographically legitimate. This is a supply-chain risk in whatever
  code implements `KeyProvider`, not something the interface can defend
  against.

## Attacker 3: Network attacker between Besa and a future remote provider

- **Assets:** signatures in transit, the ability to tamper with a
  provider's response before it reaches Besa.
- **Trust Boundary:** on the network path between the Besa process and a
  remote signing service — relevant only once a real network-backed
  provider exists (`RemoteSimulationProvider` has no real network to
  attack; this is forward-looking).
- **Attack:** intercept and corrupt the bytes returned by `sign()` in
  transit (bit-flip, truncate, substitute a different signature).
- **Detection:** any corruption is caught by verification, not by the
  transport layer — `verifySignedManifest`/`verifyReceipt` reject a
  corrupted signature deterministically. Demonstrated directly by
  `RemoteSimulationProvider`'s `invalid-signature` failure mode and its
  corresponding test (`a manifest signed with an invalid-signature-
  injecting provider fails closed on verify`), which simulates exactly
  this class of transit corruption without a real network.
- **Mitigation:** Ed25519 signature verification is deterministic — there
  is no partial-match acceptance. A real remote provider is still expected
  to use TLS for its own transport (out of scope for `KeyProvider` itself
  to enforce, since that's the concrete provider implementation's
  responsibility, not the interface's).
- **Residual Risk:** a network attacker who can fully replace a
  `sign()` response with a signature from a *different, attacker-
  controlled* key that Besa's verification would still accept only if that
  key were independently trust-anchored (`trust apply`) by the consumer —
  this is the same risk any key-substitution attack carries and is
  unrelated to the provider abstraction specifically.

## Attacker 4: Attacker who replays a previously valid signed artifact

- **Assets:** the ability to reuse an old, still-cryptographically-valid
  receipt or signed manifest outside its original context.
- **Trust Boundary:** anyone who obtained a copy of a real, previously
  issued artifact — no compromise of the provider or the key is required.
- **Attack:** resubmit an old signed manifest or receipt as if it were
  freshly produced.
- **Detection:** none today. `verifySignedManifest`/`verifyReceipt` check
  "is this signature valid for this artifact," not "was this artifact
  already used." See `PROVIDER_FAILURE_MODEL.md` §6 (Replay) for the full
  treatment — this is a verification-layer gap, not something any
  `KeyProvider` implementation (local, simulated, or real remote) could
  fix, since replay defenses (nonces, nonce ledgers, timestamp windows)
  live above the signing seam.
- **Mitigation:** none implemented.
- **Residual Risk:** full — this is a known, open gap, stated plainly here
  rather than omitted.

## Attacker 5: Attacker who exploits a rotation race

- **Assets:** the ability to have a signature accepted under a stale or
  unintended key identity during a key rotation window.
- **Trust Boundary:** requires access to the rotation process itself
  (able to trigger or observe a rotation in progress) — a narrower
  position than the other attackers here.
- **Attack:** cause or exploit a race where a provider's underlying key
  changes between `getKeyId()` and `sign()` within one signing call (see
  `PROVIDER_FAILURE_MODEL.md` §8).
- **Detection:** any resulting key/signature mismatch is caught the same
  way as Attacker 2's identity-lying case — `verifySignedManifest` rejects
  a `publicKeyId` that doesn't match the recomputed fingerprint.
- **Mitigation:** `LocalKeyProvider` and `RemoteSimulationProvider` both
  hold one fixed key for their lifetime, so neither has a rotation window
  to exploit today.
- **Residual Risk:** entirely forward-looking — only a future
  mutable-key-alias provider (a KMS "alias" pointing at a rotatable key
  version) would have this window at all; no such provider exists in this
  repository.

## Status update (Phase 4 hardening)

Attacker 5 (rotation race) noted that `createKeyRotation` was `KeyPair`-only
at the time this document was written, meaning a provider-held key could not
be rotated without exporting its private material. `createKeyRotationWithProvider`
now exists (see `PHASE4_HARDENING_AUDIT.md`) — the analysis above is
otherwise unchanged: it still describes the rotation-race threat correctly,
it just no longer needs to note the rotation gap as a reason that threat was
purely forward-looking.

## What this document does not cover

Key-anchoring trust decisions (`trust add`/`trust apply`/`trust revoke`),
agent-identity spoofing, and admission-policy bypass are separate threat
surfaces already addressed by `TRUST_MODEL.md` and `MCP_TRUST_MODEL.md`.
This document is scoped to the `KeyProvider` seam specifically, per Phase
4.5's own framing.
