# Provider Validation

Verifies whether `signManifestWithProvider`/`createReceiptWithProvider`
(the only two functions in the codebase that accept a `KeyProvider`)
contain any implicit assumption that `KeyProvider == LocalKeyProvider`.
Method: full-text grep across `src/**/*.ts` for `instanceof`,
`privateKeyDer`, `KeyPair`, `validateKeyPair`, direct `node:crypto` calls,
and manual line-by-line review of both provider-native functions.

## Result: no coupling found

**`instanceof` checks:** zero matches for `instanceof LocalKeyProvider` or
`instanceof KeyProvider` anywhere in `src/`. No code path narrows a
`KeyProvider` to a specific implementation.

**`signManifestWithProvider`/`createReceiptWithProvider`
(`src/signing.ts:355-384`, `:548-577`):** read in full for this audit. Each
calls exactly three things on `provider`: `getPublicKey()`, `getKeyId()`,
`sign()` — the complete `KeyProvider` interface, nothing more. Neither
function references `privateKeyDer`, `KeyPair`, `validateKeyPair`, or any
`node:crypto` function directly. `Buffer.from(signature)` operates on the
`Uint8Array` the interface promises, generically — it does not assume
anything about how that `Uint8Array` was produced.

**Grep sweep for `privateKeyDer`/`createPrivateKey`/`ed25519Sign`/
`validateKeyPair`/`: KeyPair` across all of `src/`:** every match is in one
of four legitimate categories, none of which is the provider-native path:

| Category | Files | Why legitimate |
|---|---|---|
| Crypto primitives | `crypto.ts` | The one module allowed to touch these |
| Legacy `KeyPair`-based API | `signing.ts` (`signManifest`/`createReceipt`), `trust.ts` (`createKeyRotation`), `index.ts` (CLI) | Explicitly synchronous, `KeyPair`-only by design (see `PHASE2_FINAL_SECURITY_AUDIT.md` §3, "accepted tradeoff") |
| At-rest encryption | `keystore.ts` | Sealing/opening the local key file — a different concern from signing |
| Test fixtures | `*.test.ts` (`keys.test.ts`, `besa.test.ts`, `security.test.ts`, `provider-security.test.ts`, `sdk-surface.test.ts`) | Constructing test keys, or (in `keys.test.ts`) one intentional manual re-implementation of the legacy sign call to prove byte-identity |

**`sign(null, ...)` / `ed25519Sign(...)` call sites, narrowed grep:**
exactly two matches in `src/*.ts`:
- `src/crypto.ts:217` — `signWithKeyPair`, the sole production Ed25519
  signing primitive.
- `src/tests/keys.test.ts:33` — an intentional, test-only manual
  re-implementation of the same call, used to assert byte-identical output
  against `LocalKeyProvider.sign()`. Not production code, not a second
  pipeline consumers can reach.

No third pipeline exists.

## Conclusion

No implicit `KeyProvider == LocalKeyProvider` assumption was found anywhere
in `src/`. Per the task's own conditional ("falls gefunden: minimal
beheben") — nothing was found, so nothing was changed. The architecture
already treats every `KeyProvider` as opaque by construction: verification
never trusts a provider's self-reported identity (`verifySignedManifest`
independently recomputes `publicKeyId` rather than accepting the provider's
claim, per `KEY_PROVIDER_ARCHITECTURE.md`'s trust-boundary section), and the
two provider-native functions touch nothing beyond the three interface
methods.

Phase 4.2's `RemoteSimulationProvider` is the next, stronger proof: a
second, structurally different `KeyProvider` implementation actually
exercised through `signManifestWithProvider`/`createReceiptWithProvider`,
rather than static code review alone.
