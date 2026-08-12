/**
 * KeyProvider is the seam between "something that needs an Ed25519 signature"
 * and "something that holds the private key material." Every call site that
 * signs today (signManifest, createReceipt) takes a raw KeyPair and calls
 * node:crypto directly — the private key is decrypted into process memory at
 * every signing call. A KeyProvider lets that seam move: LocalKeyProvider
 * keeps today's behavior, a future KMS/HSM-backed provider would sign
 * without ever exposing privateKeyDer to the caller.
 *
 * async-first by design, even though LocalKeyProvider is synchronous under
 * the hood: KMS/HSM/cloud signers are inherently network calls, and an
 * async contract cannot be retrofitted onto callers without breaking them.
 */
export interface KeyProvider {
  /** Returns the canonical base64 SPKI DER-encoded Ed25519 public key. */
  getPublicKey(): Promise<string>;

  /** Returns the SHA-256 fingerprint (publicKeyId) of the public key. */
  getKeyId(): Promise<string>;

  /** Signs an already-canonicalized payload and returns the raw 64-byte Ed25519 signature. */
  sign(payload: Uint8Array): Promise<Uint8Array>;
}
