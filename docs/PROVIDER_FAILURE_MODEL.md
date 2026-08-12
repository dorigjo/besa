# Provider Failure Model

Architecture only. Describes how each failure mode should behave for any
`KeyProvider` implementation — local, simulated, or a real future
KMS/HSM/Vault backend. Where a failure mode is already exercised by code in
this repository (`RemoteSimulationProvider`,
`src/tests/provider-contract.test.ts`, `provider-security.test.ts`), that is
called out explicitly. Where it is architecture-only, that is stated
explicitly too — no implementation is claimed that does not exist.

The governing rule for all eight modes: **`KeyProvider.sign()` either
resolves with a signature that independently verifies, or it rejects.**
There is no third outcome. `verifySignedManifest`/`verifyReceiptDetailed`
never trust a provider's self-report — every one of these failure modes is
ultimately caught by the same two functions, not by bespoke per-mode
handling.

## 1. Timeout

A provider's `sign()`/`getPublicKey()`/`getKeyId()` never resolves within a
reasonable window (a hung network call, a stalled KMS request).

- **Contract:** the provider's own promise must eventually reject — Besa's
  call sites do not add a second timeout layer on top of the interface.
- **Demonstrated:** `RemoteSimulationProvider` implements this via a real
  `setTimeout` race (`src/keys/remote-simulation-provider.ts`,
  `#roundTrip`) — a timeout timer competes with the simulated network
  delay, and whichever fires first decides the outcome. Covered by
  `RemoteSimulationProvider.sign rejects on simulated timeout (fails
  closed)` in `provider-contract.test.ts`, including verifying the retry
  budget is exhausted (not silently downgraded to "succeeded on some
  attempt").
- **Fails closed:** yes — no artifact is produced, `besa sign`/`besa
  receipt` exits non-zero.

## 2. Network Partition

The provider is entirely unreachable (DNS failure, connection refused, a
KMS region outage) rather than merely slow.

- **Contract:** identical to Timeout from the caller's point of view —
  `sign()` rejects. Besa's signing code has no way to distinguish "slow"
  from "unreachable," and does not need to; both are terminal failures for
  that call.
- **Not implemented:** `RemoteSimulationProvider` does not model a distinct
  partition state (no real network exists to partition). A real
  `KmsKeyProvider`/`VaultKeyProvider` would surface this as its own SDK's
  connection error, propagated as a rejected promise — architecture only.
- **Fails closed:** yes.

## 3. Compromised Provider

The provider implementation itself is malicious or has been tampered with
— it might sign arbitrary attacker-chosen payloads, refuse to sign
legitimate ones, or attempt to leak key material through its own side
channels.

- **Contract:** `KeyProvider` is *not* a trusted component. Besa's
  verification layer treats every provider's output as untrusted input
  that must independently satisfy `publicKeyId = SHA-256(publicKey)` and a
  valid Ed25519 signature over the exact canonical payload — see
  `KEY_PROVIDER_ARCHITECTURE.md`'s "Trust boundary" section. A compromised
  provider can produce a bad signature or a self-serving lie about its own
  identity, but it cannot produce an artifact that verifies without
  actually possessing the private key `publicKeyId` claims.
- **Demonstrated:** the `mismatchedIdentityProvider`/
  `mismatchedPublicKeyProvider` test doubles in `provider-security.test.ts`
  and `provider-contract.test.ts` are exactly this scenario — a provider
  that lies about its own key id or public key. Both fail closed
  (`E_PUBLIC_KEY_ID_MISMATCH`, or a generic invalid result for a swapped
  public key).
- **What Besa cannot detect:** a compromised provider that signs the
  *correct* payload with the *correct* key but has, on its own side,
  leaked that key to an attacker. That is the provider implementation's
  own security responsibility (documented in `KEY_PROVIDER_ARCHITECTURE.md`
  as an explicit non-guarantee), not something the `KeyProvider` interface
  or Besa's verification layer can observe.
- **Fails closed:** yes, for every case Besa's verification layer can see.

## 4. Wrong Key

`sign()` returns a signature produced by a *different* key than the one
`getPublicKey()` reported for this call.

- **Contract:** verification recomputes and checks the signature against
  the manifest/receipt's own recorded `publicKey`. A wrong-key signature
  fails `node:crypto`'s `verify()` deterministically — there is no
  approximate match.
- **Demonstrated:** `verifySignedManifest fails closed against the wrong
  public key` / `verifyReceipt fails closed when checked against the wrong
  public key` (`provider-security.test.ts`), plus the equivalent
  `RemoteSimulationProvider`-backed cases in `provider-contract.test.ts`.
- **Fails closed:** yes.

## 5. Wrong KeyId

`getKeyId()` returns a fingerprint that does not match `SHA-256(publicKey)`
for the key `getPublicKey()`/`sign()` actually used — the identity label
and the cryptographic material disagree.

- **Contract:** `signManifestWithProvider`/`createReceiptWithProvider`
  never trust `getKeyId()`'s return value on faith; `verifySignedManifest`
  independently recomputes `publicKeyId(signed.publicKey)` and compares it
  to the artifact's recorded `publicKeyId`, rejecting with
  `E_PUBLIC_KEY_ID_MISMATCH` on any disagreement.
- **Demonstrated:** `signManifestWithProvider fails closed when the
  provider misreports its own key id` (`provider-security.test.ts`) and
  its `RemoteSimulationProvider` counterpart in `provider-contract.test.ts`
  — both assert the exact `E_PUBLIC_KEY_ID_MISMATCH` reason code.
- **Fails closed:** yes.

## 6. Replay

A previously valid signed artifact (manifest or receipt) is resubmitted
later, outside its original context, as if freshly produced.

- **Contract today:** signed manifests carry `signedAt`; receipts carry a
  unique `receiptId` and `timestamp`. Neither field is currently checked
  for freshness or uniqueness by `verifySignedManifest`/`verifyReceipt` —
  those functions answer "is this signature valid for this exact
  artifact," not "was this artifact seen before." A structurally identical
  re-submission of an old, still-validly-signed receipt would still
  verify.
- **Not implemented:** replay *rejection* (nonce tracking, timestamp
  windows, a seen-receipts ledger) is out of scope for this MVP and not
  built — this is a known, named gap, not a claimed guarantee. It applies
  identically regardless of which `KeyProvider` tier signed the artifact;
  it is a property of the verification layer, not the signing layer, so no
  `KeyProvider` change could fix it.
- **Fails closed:** no — this is the one mode in this document that is
  *not* fail-closed today, stated plainly rather than glossed over.

## 7. Partial Failure

A multi-step provider operation fails partway — e.g. a hypothetical batch
or multi-key operation where some signatures succeed and others don't, or
a provider that succeeds at `getPublicKey()`/`getKeyId()` but fails at
`sign()` (or the reverse).

- **Contract:** `KeyProvider`'s three methods are independent Promises with
  no shared transaction — `signManifestWithProvider`/
  `createReceiptWithProvider` call `getPublicKey()`, `getKeyId()`, then
  `sign()` sequentially and propagate the first rejection immediately, so
  a caller never receives a signed artifact where only some of the
  provider calls succeeded. There is no artifact "half-signed" state —
  either all three calls resolve and a complete, verifiable artifact is
  built, or the whole call chain rejects and nothing is written.
- **Not implemented:** batch signing (multiple artifacts per provider
  call) does not exist in this codebase — each `sign()` call is for
  exactly one payload. Partial failure across a batch is therefore not a
  real scenario today, only a design constraint a future batch-signing
  feature would need to honor.
- **Fails closed:** yes, for the single-artifact case that exists today.

## 8. Rotation During Request

The provider's underlying key is rotated between `getKeyId()` and
`sign()` within the same logical signing call (e.g. a KMS alias that
starts pointing at a new key version mid-request).

- **Contract:** already documented in `KEY_PROVIDER_ARCHITECTURE.md`'s
  failure model — a provider implementation must either pin the exact key
  version for the duration of one signing call, or guarantee
  `getKeyId()`/`sign()` atomicity itself. Besa's call sites cannot detect
  or correct this mid-flight.
- **What catches it after the fact:** if a provider does return a
  signature from a *different* key version than the `publicKeyId` recorded
  in the artifact body, that is structurally identical to failure mode 4
  (Wrong Key) from verification's point of view — `verifySignedManifest`
  rejects it the same way, whether the mismatch came from a lying provider
  or an innocent rotation race.
- **Not implemented:** `LocalKeyProvider` and `RemoteSimulationProvider`
  both hold one fixed `KeyPair` for their entire lifetime — neither can
  rotate mid-call, so this scenario has no code to exercise it today. It
  remains a documented constraint on any future mutable-key-alias provider
  (KMS, Vault), not a gap in the current two implementations.
- **Fails closed:** yes, via the Wrong Key path — but only after the fact,
  not preventively.

## Summary

| Mode | Fails closed today | Demonstrated in code | Provider-tier-specific? |
|---|---|---|---|
| Timeout | Yes | `RemoteSimulationProvider` + contract tests | No — any async provider |
| Network Partition | Yes (same path as Timeout) | Not modeled (no real network) | No |
| Compromised Provider | Yes, for detectable cases | Identity-lying test doubles | No |
| Wrong Key | Yes | `provider-security.test.ts` + contract tests | No |
| Wrong KeyId | Yes | `provider-security.test.ts` + contract tests | No |
| Replay | **No** — known gap | N/A | No — verification-layer gap |
| Partial Failure | Yes (single-artifact case) | Implicit in call sequencing | No |
| Rotation During Request | Yes, via Wrong Key path, reactively | Not modeled (fixed keys only) | Yes — only mutable-key-alias tiers |

No new dependency, no new algorithm, and no change to the `KeyProvider`
interface was needed to write this document — every fail-closed guarantee
above already follows from `verifySignedManifest`/`verifyReceipt`
independently recomputing identity and signature validity, not from any
per-failure-mode special case.
