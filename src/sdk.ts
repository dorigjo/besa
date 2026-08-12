export * from "./types.js";
// Explicit re-export, not `export *`: crypto.ts contains internal primitives
// that must stay importable within src/ but were never deliberately decided
// as public SDK surface. `KeyProvider`/`LocalKeyProvider` got a written
// export decision (KEY_PROVIDER_ARCHITECTURE.md); this list is the same
// discipline applied to crypto.ts's flat function set.
//
// Deliberately NOT re-exported (Phase 5 SDK surface hardening):
// - privateKeyFromDer: internal signing/validation primitive, no consumer
//   use case that isn't already served by signWithKeyPair/validateKeyPair.
// - publicKeyFromDer: returns a raw node:crypto KeyObject; every documented
//   verification workflow is already covered by verifySignedManifest/
//   verifyReceipt/verifyKeyRotation/checkTrustedKey, so there is no
//   consumer scenario that needs a bare KeyObject.
// - isCanonicalBase64: a generic parsing predicate with no distinct
//   consumer use case beyond what the higher-level exports already cover.
// - sha256Hex: a generic, non-domain-separated hash primitive. Keeping it
//   public alongside hashManifest/hashRequest (which ARE domain-separated)
//   invited exactly the confusion that got hashObject deleted last phase —
//   a consumer could plausibly call sha256Hex(canonicalize(x)) expecting
//   it to reproduce manifestHash/requestHash; it would not, silently.
export {
  canonicalize,
  generateKeyPair,
  publicKeyId,
  signWithKeyPair,
  signatureMessage,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
export * from "./manifest.js";
export * from "./signing.js";
export * from "./admit.js";
export * from "./grant.js";
export * from "./trust.js";
export * from "./keystore.js";
export * from "./evidence.js";
