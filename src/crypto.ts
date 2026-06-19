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

function sortValue(
  value: unknown,
  path: string,
  seen: WeakSet<object>,
): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${path} must be a finite JSON number`);
    }
    return value;
  }

  if (typeof value !== "object") {
    throw new TypeError(`${path} contains a non-JSON value`);
  }

  if (seen.has(value)) {
    throw new TypeError(`${path} contains a circular reference`);
  }

  seen.add(value);

  try {
    if (Array.isArray(value)) {
      return value.map((item, index) =>
        sortValue(item, `${path}[${String(index)}]`, seen),
      );
    }

    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must contain only plain JSON objects`);
    }

    const input = value as Record<string, unknown>;
    const output = Object.create(null) as Record<string, unknown>;

    for (const key of Object.keys(input).sort()) {
      output[key] = sortValue(input[key], `${path}.${key}`, seen);
    }

    return output;
  } finally {
    seen.delete(value);
  }
}

export function canonicalize(value: unknown): string {
  const canonical = JSON.stringify(
    sortValue(value, "$", new WeakSet<object>()),
  );

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
  const key = createPublicKey({
    key: Buffer.from(publicKeyDer, "base64"),
    type: "spki",
    format: "der",
  });

  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError("public key must be Ed25519");
  }

  return key;
}

export function privateKeyFromDer(privateKeyDer: string): KeyObject {
  const key = createPrivateKey({
    key: Buffer.from(privateKeyDer, "base64"),
    type: "pkcs8",
    format: "der",
  });

  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError("private key must be Ed25519");
  }

  return key;
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
