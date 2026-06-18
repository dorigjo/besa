import {
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import type {
  KeyRotation,
  SignedManifest,
  TrustAnchor,
  TrustStore,
} from "./types.js";
import {
  canonicalize,
  privateKeyFromDer,
  publicKeyFromDer,
  publicKeyId,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import { verifySignedManifest, type VerifyResult } from "./signing.js";

const KEY_ID = /^[a-f0-9]{16}$/;

export interface TrustStoreValidationResult {
  ok: boolean;
  trustStore?: TrustStore;
  errors: string[];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isIsoDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isCanonicalBase64(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    Buffer.from(value, "base64").toString("base64") === value
  );
}

function validateAnchor(value: unknown, index: number): string[] {
  if (!isObject(value)) {
    return [`keys[${index}] must be an object`];
  }

  const errors: string[] = [];

  if (typeof value.publicKeyId !== "string" || !KEY_ID.test(value.publicKeyId)) {
    errors.push(`keys[${index}].publicKeyId must be a 16-character lowercase hex string`);
  }

  if (!isCanonicalBase64(value.publicKey)) {
    errors.push(`keys[${index}].publicKey must be canonical base64`);
  } else {
    try {
      publicKeyFromDer(value.publicKey);
      if (publicKeyId(value.publicKey) !== value.publicKeyId) {
        errors.push(`keys[${index}].publicKeyId does not match publicKey`);
      }
    } catch {
      errors.push(`keys[${index}].publicKey must be a valid Ed25519 public key`);
    }
  }

  if (
    value.status !== "active" &&
    value.status !== "retired" &&
    value.status !== "revoked"
  ) {
    errors.push(`keys[${index}].status must be active, retired, or revoked`);
  }

  if (!isIsoDate(value.addedAt)) {
    errors.push(`keys[${index}].addedAt must be a canonical ISO-8601 timestamp`);
  }

  if (value.status === "retired" && !isIsoDate(value.retiredAt)) {
    errors.push(`keys[${index}].retiredAt is required for a retired key`);
  } else if (
    isIsoDate(value.retiredAt) &&
    isIsoDate(value.addedAt) &&
    Date.parse(value.retiredAt) < Date.parse(value.addedAt)
  ) {
    errors.push(`keys[${index}].retiredAt must not be before addedAt`);
  }

  if (value.status === "revoked" && !isIsoDate(value.revokedAt)) {
    errors.push(`keys[${index}].revokedAt is required for a revoked key`);
  } else if (
    isIsoDate(value.revokedAt) &&
    isIsoDate(value.addedAt) &&
    Date.parse(value.revokedAt) < Date.parse(value.addedAt)
  ) {
    errors.push(`keys[${index}].revokedAt must not be before addedAt`);
  }

  return errors;
}

export function validateTrustStore(value: unknown): TrustStoreValidationResult {
  if (!isObject(value)) {
    return { ok: false, errors: ["trust store must be an object"] };
  }

  const errors: string[] = [];

  if (value.version !== 1) {
    errors.push("version must be 1");
  }

  if (!Array.isArray(value.keys)) {
    errors.push("keys must be an array");
  } else {
    value.keys.forEach((key, index) => errors.push(...validateAnchor(key, index)));

    const ids = value.keys
      .filter(isObject)
      .map((key) => key.publicKeyId)
      .filter((id): id is string => typeof id === "string");

    if (new Set(ids).size !== ids.length) {
      errors.push("keys must not contain duplicate publicKeyId values");
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    trustStore: value as unknown as TrustStore,
    errors: [],
  };
}

export function emptyTrustStore(): TrustStore {
  return { version: 1, keys: [] };
}

export function addTrustAnchor(
  store: TrustStore,
  publicKey: string,
  addedAt = new Date().toISOString(),
): TrustStore {
  if (!isIsoDate(addedAt)) {
    throw new Error("addedAt must be a canonical ISO-8601 timestamp");
  }

  publicKeyFromDer(publicKey);
  const id = publicKeyId(publicKey);
  const existing = store.keys.find((key) => key.publicKeyId === id);

  if (existing) {
    if (existing.publicKey !== publicKey) {
      throw new Error(`public key id collision for ${id}`);
    }
    return store;
  }

  return {
    version: 1,
    keys: [
      ...store.keys,
      {
        publicKeyId: id,
        publicKey,
        status: "active",
        addedAt,
      },
    ],
  };
}

export function revokeTrustAnchor(
  store: TrustStore,
  keyId: string,
  revokedAt = new Date().toISOString(),
): TrustStore {
  if (!isIsoDate(revokedAt)) {
    throw new Error("revokedAt must be a canonical ISO-8601 timestamp");
  }

  const existing = store.keys.find((key) => key.publicKeyId === keyId);

  if (!existing) {
    throw new Error(`trusted key '${keyId}' was not found`);
  }

  return {
    version: 1,
    keys: store.keys.map((key) =>
      key.publicKeyId === keyId
        ? {
            publicKeyId: key.publicKeyId,
            publicKey: key.publicKey,
            status: "revoked",
            addedAt: key.addedAt,
            revokedAt,
          }
        : key,
    ),
  };
}

type RotationBody = Omit<KeyRotation, "signature">;

export function createKeyRotation(
  previous: KeyPair,
  next: KeyPair,
  rotatedAt = new Date().toISOString(),
): KeyRotation {
  if (!validateKeyPair(previous) || !validateKeyPair(next)) {
    throw new Error("key rotation requires valid Ed25519 key pairs");
  }

  if (!isIsoDate(rotatedAt)) {
    throw new Error("rotatedAt must be a canonical ISO-8601 timestamp");
  }

  if (previous.publicKeyDer === next.publicKeyDer) {
    throw new Error("key rotation requires a different new key");
  }

  const body: RotationBody = {
    algorithm: "ed25519",
    previousPublicKey: previous.publicKeyDer,
    previousPublicKeyId: publicKeyId(previous.publicKeyDer),
    newPublicKey: next.publicKeyDer,
    newPublicKeyId: publicKeyId(next.publicKeyDer),
    rotatedAt,
  };
  const signature = ed25519Sign(
    null,
    Buffer.from(canonicalize(body), "utf8"),
    privateKeyFromDer(previous.privateKeyDer),
  );

  return { ...body, signature: signature.toString("base64") };
}

export function verifyKeyRotation(value: unknown): VerifyResult {
  if (!isObject(value)) {
    return {
      valid: false,
      reasonCode: "E_ROTATION_INVALID",
      detail: "key rotation must be an object",
    };
  }

  if (value.algorithm !== "ed25519") {
    return {
      valid: false,
      reasonCode: "E_ALGORITHM_UNSUPPORTED",
      detail: "only ed25519 key rotations are supported",
    };
  }

  if (
    !isCanonicalBase64(value.previousPublicKey) ||
    !isCanonicalBase64(value.newPublicKey) ||
    typeof value.previousPublicKeyId !== "string" ||
    typeof value.newPublicKeyId !== "string" ||
    !KEY_ID.test(value.previousPublicKeyId) ||
    !KEY_ID.test(value.newPublicKeyId) ||
    !isIsoDate(value.rotatedAt) ||
    !isCanonicalBase64(value.signature)
  ) {
    return {
      valid: false,
      reasonCode: "E_ROTATION_INVALID",
      detail: "key rotation fields are invalid",
    };
  }

  if (
    publicKeyId(value.previousPublicKey) !== value.previousPublicKeyId ||
    publicKeyId(value.newPublicKey) !== value.newPublicKeyId
  ) {
    return {
      valid: false,
      reasonCode: "E_PUBLIC_KEY_ID_MISMATCH",
      detail: "key rotation publicKeyId does not match its public key",
    };
  }

  if (value.previousPublicKeyId === value.newPublicKeyId) {
    return {
      valid: false,
      reasonCode: "E_ROTATION_INVALID",
      detail: "key rotation must introduce a different public key",
    };
  }

  try {
    publicKeyFromDer(value.previousPublicKey);
    publicKeyFromDer(value.newPublicKey);
  } catch {
    return {
      valid: false,
      reasonCode: "E_ROTATION_INVALID",
      detail: "key rotation must contain valid Ed25519 public keys",
    };
  }

  const rotation = value as unknown as KeyRotation;
  const { signature, ...body } = rotation;

  try {
    const valid = ed25519Verify(
      null,
      Buffer.from(canonicalize(body), "utf8"),
      publicKeyFromDer(rotation.previousPublicKey),
      Buffer.from(signature, "base64"),
    );

    return valid
      ? { valid: true, reasonCode: "OK", detail: "key rotation is valid" }
      : {
          valid: false,
          reasonCode: "E_SIGNATURE_INVALID",
          detail: "key rotation signature is invalid",
        };
  } catch {
    return {
      valid: false,
      reasonCode: "E_SIGNATURE_CHECK_FAILED",
      detail: "key rotation signature verification failed",
    };
  }
}

export function applyKeyRotation(
  store: TrustStore,
  rotation: KeyRotation,
): TrustStore {
  const verification = verifyKeyRotation(rotation);

  if (!verification.valid) {
    throw new Error(`${verification.reasonCode}: ${verification.detail}`);
  }

  const previous = store.keys.find(
    (key) => key.publicKeyId === rotation.previousPublicKeyId,
  );

  if (!previous || previous.publicKey !== rotation.previousPublicKey) {
    throw new Error("rotation previous key is not a trust anchor");
  }

  const next = store.keys.find(
    (key) => key.publicKeyId === rotation.newPublicKeyId,
  );

  if (previous.status === "retired" && next?.status === "active") {
    if (
      previous.retiredAt === rotation.rotatedAt &&
      next.publicKey === rotation.newPublicKey
    ) {
      return store;
    }
  }

  if (previous.status !== "active") {
    throw new Error(`rotation previous key is ${previous.status}, not active`);
  }

  if (Date.parse(rotation.rotatedAt) < Date.parse(previous.addedAt)) {
    throw new Error("rotation timestamp is before the previous key was added");
  }

  if (next && next.status !== "active") {
    throw new Error(`rotation new key is already ${next.status}`);
  }

  if (next && next.publicKey !== rotation.newPublicKey) {
    throw new Error(`public key id collision for ${rotation.newPublicKeyId}`);
  }

  const retired: TrustAnchor = {
    publicKeyId: previous.publicKeyId,
    publicKey: previous.publicKey,
    status: "retired",
    addedAt: previous.addedAt,
    retiredAt: rotation.rotatedAt,
  };
  const active: TrustAnchor = next ?? {
    publicKeyId: rotation.newPublicKeyId,
    publicKey: rotation.newPublicKey,
    status: "active",
    addedAt: rotation.rotatedAt,
  };

  return {
    version: 1,
    keys: [
      ...store.keys.filter(
        (key) =>
          key.publicKeyId !== rotation.previousPublicKeyId &&
          key.publicKeyId !== rotation.newPublicKeyId,
      ),
      retired,
      { ...active, status: "active" },
    ],
  };
}

export function checkTrustedKey(
  store: TrustStore,
  publicKey: string,
  artifactTimestamp: string,
  purpose: "verify" | "admit" = "verify",
): VerifyResult {
  if (!isIsoDate(artifactTimestamp)) {
    return {
      valid: false,
      reasonCode: "E_ARTIFACT_TIMESTAMP_INVALID",
      detail: "artifact timestamp must be canonical ISO-8601",
    };
  }

  const id = publicKeyId(publicKey);
  const anchor = store.keys.find((key) => key.publicKeyId === id);

  if (!anchor) {
    return {
      valid: false,
      reasonCode: "E_KEY_UNTRUSTED",
      detail: `public key ${id} is not in the trust store`,
    };
  }

  if (anchor.publicKey !== publicKey) {
    return {
      valid: false,
      reasonCode: "E_TRUST_ANCHOR_MISMATCH",
      detail: `trust anchor ${id} does not match the artifact public key`,
    };
  }

  if (anchor.status === "revoked") {
    return {
      valid: false,
      reasonCode: "E_KEY_REVOKED",
      detail: `public key ${id} is revoked`,
    };
  }

  if (anchor.status === "retired") {
    if (purpose === "admit") {
      return {
        valid: false,
        reasonCode: "E_KEY_RETIRED",
        detail: `public key ${id} is retired for new admissions`,
      };
    }

    if (
      !anchor.retiredAt ||
      Date.parse(artifactTimestamp) > Date.parse(anchor.retiredAt)
    ) {
      return {
        valid: false,
        reasonCode: "E_KEY_RETIRED",
        detail: `artifact was signed after public key ${id} was retired`,
      };
    }
  }

  return {
    valid: true,
    reasonCode: "OK",
    detail: `public key ${id} is trusted`,
  };
}

export function verifyTrustedSignedManifest(
  value: unknown,
  store: TrustStore,
  purpose: "verify" | "admit" = "verify",
): VerifyResult {
  const signature = verifySignedManifest(value);

  if (!signature.valid) {
    return signature;
  }

  const signed = value as SignedManifest;
  return checkTrustedKey(store, signed.publicKey, signed.signedAt, purpose);
}
