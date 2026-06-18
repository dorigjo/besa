import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";

export interface KeyPair {
  publicKeyDer: string;
  privateKeyDer: string;
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }

  if (value !== null && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};

    for (const key of Object.keys(input).sort()) {
      output[key] = sortValue(input[key]);
    }

    return output;
  }

  return value;
}

export function canonicalize(value: unknown): string {
  const canonical = JSON.stringify(sortValue(value));

  if (canonical === undefined) {
    throw new TypeError("value cannot be canonicalized");
  }

  return canonical;
}

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

export function hashObject(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  return {
    publicKeyDer: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64"),
    privateKeyDer: privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64"),
  };
}

export function publicKeyFromDer(publicKeyDer: string): KeyObject {
  return createPublicKey({
    key: Buffer.from(publicKeyDer, "base64"),
    type: "spki",
    format: "der",
  });
}

export function privateKeyFromDer(privateKeyDer: string): KeyObject {
  return createPrivateKey({
    key: Buffer.from(privateKeyDer, "base64"),
    type: "pkcs8",
    format: "der",
  });
}

export function publicKeyId(publicKeyDer: string): string {
  return sha256Hex(publicKeyDer).slice(0, 16);
}

export function validateKeyPair(value: unknown): value is KeyPair {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const candidate = value as Record<string, unknown>;

  if (
    typeof candidate.publicKeyDer !== "string" ||
    typeof candidate.privateKeyDer !== "string"
  ) {
    return false;
  }

  try {
    const privateKey = privateKeyFromDer(candidate.privateKeyDer);
    const derivedPublicKey = createPublicKey(privateKey)
      .export({ type: "spki", format: "der" })
      .toString("base64");

    publicKeyFromDer(candidate.publicKeyDer);
    return derivedPublicKey === candidate.publicKeyDer;
  } catch {
    return false;
  }
}
