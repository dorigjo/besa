import {
  publicKeyId,
  signWithKeyPair,
  validateKeyPair,
  type KeyPair,
} from "../crypto.js";
import type { KeyProvider } from "./provider.js";

/**
 * Wraps an already-decrypted local KeyPair behind the KeyProvider interface.
 * Uses the same node:crypto Ed25519 signing path as signManifest/createReceipt
 * today — no new algorithm, no new key format, no new dependency. This is the
 * adapter between the existing synchronous KeyPair API and the async
 * KeyProvider contract that a future KMS/HSM provider would also implement.
 */
export class LocalKeyProvider implements KeyProvider {
  readonly #keypair: KeyPair;

  constructor(keypair: KeyPair) {
    if (!validateKeyPair(keypair)) {
      throw new Error("invalid or mismatched Ed25519 key pair");
    }
    this.#keypair = keypair;
  }

  getPublicKey(): Promise<string> {
    return Promise.resolve(this.#keypair.publicKeyDer);
  }

  getKeyId(): Promise<string> {
    return Promise.resolve(publicKeyId(this.#keypair.publicKeyDer));
  }

  sign(payload: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(signWithKeyPair(payload, this.#keypair));
  }
}
