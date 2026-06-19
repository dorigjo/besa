import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { canonicalize, isCanonicalBase64, validateKeyPair, type KeyPair } from "./crypto.js";

const SCRYPT_N = 32_768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAX_MEMORY = 64 * 1024 * 1024;

export interface StoredKeyPair {
  version: 1;
  publicKeyDer: string;
  protection: {
    kdf: "scrypt";
    cipher: "aes-256-gcm";
    salt: string;
    iv: string;
    authTag: string;
    ciphertext: string;
  };
}

function assertPassphrase(passphrase: string): void {
  const length = Buffer.byteLength(passphrase, "utf8");
  if (length < 16 || length > 1_024) {
    throw new Error("key passphrase must contain 16-1024 UTF-8 bytes");
  }
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAX_MEMORY,
  });
}

function additionalData(publicKeyDer: string): Buffer {
  return Buffer.from(
    canonicalize({
      version: 1,
      publicKeyDer,
      kdf: "scrypt",
      cipher: "aes-256-gcm",
      parameters: { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
    }),
    "utf8",
  );
}

export function sealKeyPair(
  keypair: KeyPair,
  passphrase: string,
): StoredKeyPair {
  if (!validateKeyPair(keypair)) {
    throw new Error("cannot seal an invalid Ed25519 key pair");
  }
  assertPassphrase(passphrase);

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv(
    "aes-256-gcm",
    deriveKey(passphrase, salt),
    iv,
    { authTagLength: 16 },
  );
  cipher.setAAD(additionalData(keypair.publicKeyDer));
  const ciphertext = Buffer.concat([
    cipher.update(keypair.privateKeyDer, "utf8"),
    cipher.final(),
  ]);

  return {
    version: 1,
    publicKeyDer: keypair.publicKeyDer,
    protection: {
      kdf: "scrypt",
      cipher: "aes-256-gcm",
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    },
  };
}

export function isStoredKeyPair(value: unknown): value is StoredKeyPair {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  if (
    candidate.version !== 1 ||
    typeof candidate.publicKeyDer !== "string" ||
    !candidate.protection ||
    typeof candidate.protection !== "object" ||
    Array.isArray(candidate.protection)
  ) {
    return false;
  }

  if (
    Object.keys(candidate).some(
      (field) => field !== "version" && field !== "publicKeyDer" && field !== "protection",
    )
  ) {
    return false;
  }

  const protection = candidate.protection as Record<string, unknown>;
  const allowed = new Set([
    "kdf",
    "cipher",
    "salt",
    "iv",
    "authTag",
    "ciphertext",
  ]);

  return (
    Object.keys(protection).every((field) => allowed.has(field)) &&
    protection.kdf === "scrypt" &&
    protection.cipher === "aes-256-gcm" &&
    typeof protection.salt === "string" &&
    protection.salt.length === 24 &&
    isCanonicalBase64(protection.salt) &&
    typeof protection.iv === "string" &&
    protection.iv.length === 16 &&
    isCanonicalBase64(protection.iv) &&
    typeof protection.authTag === "string" &&
    protection.authTag.length === 24 &&
    isCanonicalBase64(protection.authTag) &&
    typeof protection.ciphertext === "string" &&
    protection.ciphertext.length <= 16_384 &&
    isCanonicalBase64(protection.ciphertext)
  );
}

export function openKeyPair(
  stored: unknown,
  passphrase: string,
): KeyPair {
  assertPassphrase(passphrase);
  if (!isStoredKeyPair(stored)) {
    throw new Error("encrypted key file is malformed or unsupported");
  }

  try {
    const protection = stored.protection;
    const decipher = createDecipheriv(
      "aes-256-gcm",
      deriveKey(passphrase, Buffer.from(protection.salt, "base64")),
      Buffer.from(protection.iv, "base64"),
      { authTagLength: 16 },
    );
    decipher.setAAD(additionalData(stored.publicKeyDer));
    decipher.setAuthTag(Buffer.from(protection.authTag, "base64"));
    const privateKeyDer = Buffer.concat([
      decipher.update(Buffer.from(protection.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8");
    const keypair = { publicKeyDer: stored.publicKeyDer, privateKeyDer };

    if (!validateKeyPair(keypair)) throw new Error("key pair mismatch");
    return keypair;
  } catch {
    throw new Error("key file authentication failed");
  }
}
