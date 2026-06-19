import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

export interface KeyPair {
  publicKeyDer: string;
  privateKeyDer: string;
}

const MAX_CANONICAL_DEPTH = 64;
const MAX_CANONICAL_NODES = 100_000;
const MAX_CANONICAL_BYTES = 1_048_576;

interface CanonicalState {
  nodes: number;
  seen: WeakSet<object>;
}

function sortValue(
  value: unknown,
  path: string,
  depth: number,
  state: CanonicalState,
): unknown {
  state.nodes += 1;

  if (state.nodes > MAX_CANONICAL_NODES) {
    throw new TypeError("value exceeds the canonical JSON node limit");
  }

  if (depth > MAX_CANONICAL_DEPTH) {
    throw new TypeError(`${path} exceeds the canonical JSON depth limit`);
  }

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

  if (state.seen.has(value)) {
    throw new TypeError(`${path} contains a circular reference`);
  }

  state.seen.add(value);

  try {
    if (Array.isArray(value)) {
      return value.map((item, index) =>
        sortValue(item, `${path}[${String(index)}]`, depth + 1, state),
      );
    }

    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must contain only plain JSON objects`);
    }

    const input = value as Record<string, unknown>;
    const output = Object.create(null) as Record<string, unknown>;

    for (const key of Object.keys(input).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !("value" in descriptor)) {
        throw new TypeError(`${path}.${key} must be a JSON data property`);
      }

      output[key] = sortValue(
        descriptor.value,
        `${path}.${key.slice(0, 64)}`,
        depth + 1,
        state,
      );
    }

    return output;
  } finally {
    state.seen.delete(value);
  }
}

export function canonicalize(value: unknown): string {
  const canonical = JSON.stringify(
    sortValue(value, "$", 0, {
      nodes: 0,
      seen: new WeakSet<object>(),
    }),
  );

  if (canonical === undefined) {
    throw new TypeError("value cannot be canonicalized");
  }

  if (Buffer.byteLength(canonical, "utf8") > MAX_CANONICAL_BYTES) {
    throw new TypeError("value exceeds the canonical JSON byte limit");
  }

  return canonical;
}

export function sha256Hex(data: string | Uint8Array): string {
  const hash = createHash("sha256");
  return typeof data === "string"
    ? hash.update(data, "utf8").digest("hex")
    : hash.update(data).digest("hex");
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
    key: decodeCanonicalBase64(publicKeyDer, "public key"),
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
    key: decodeCanonicalBase64(privateKeyDer, "private key"),
    type: "pkcs8",
    format: "der",
  });

  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError("private key must be Ed25519");
  }

  return key;
}

export function publicKeyId(publicKeyDer: string): string {
  return sha256Hex(decodeCanonicalBase64(publicKeyDer, "public key"));
}

export function isCanonicalBase64(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }

  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}

function decodeCanonicalBase64(value: string, label: string): Buffer {
  if (!isCanonicalBase64(value)) {
    throw new TypeError(`${label} must be canonical base64`);
  }

  return Buffer.from(value, "base64");
}

export function signatureMessage(domain: string, value: unknown): Buffer {
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(domain)) {
    throw new TypeError("signature domain is invalid");
  }

  return Buffer.from(
    `besa:${domain}:v1\0${canonicalize(value)}`,
    "utf8",
  );
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
    const derivedPublicKeyDer = createPublicKey(privateKey)
      .export({ type: "spki", format: "der" }) as Buffer;

    publicKeyFromDer(candidate.publicKeyDer);
    const storedPublicKeyDer = Buffer.from(candidate.publicKeyDer, "base64");

    return (
      derivedPublicKeyDer.length === storedPublicKeyDer.length &&
      timingSafeEqual(derivedPublicKeyDer, storedPublicKeyDer)
    );
  } catch {
    return false;
  }
}
