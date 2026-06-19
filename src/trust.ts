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
  isCanonicalBase64,
  privateKeyFromDer,
  publicKeyFromDer,
  publicKeyId,
  signatureMessage,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import { verifySignedManifest, type VerifyResult } from "./signing.js";

const KEY_ID = /^[a-f0-9]{64}$/;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1_000;
const MAX_TRUST_KEYS = 4_096;

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
    value.length <= 35 &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function validateAnchor(value: unknown, index: number): string[] {
  if (!isObject(value)) {
    return [`keys[${index}] must be an object`];
  }

  const errors: string[] = [];
  const allowedFields = new Set([
    "publicKeyId",
    "publicKey",
    "status",
    "addedAt",
    "retiredAt",
    "revokedAt",
  ]);

  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      errors.push(`unexpected keys[${index}] field '${field}'`);
    }
  }

  if (typeof value.publicKeyId !== "string" || !KEY_ID.test(value.publicKeyId)) {
    errors.push(`keys[${index}].publicKeyId must be a 64-character lowercase SHA-256 fingerprint`);
  }

  if (
    typeof value.publicKey !== "string" ||
    value.publicKey.length > 128 ||
    !isCanonicalBase64(value.publicKey)
  ) {
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

  if (
    value.status === "active" &&
    (value.retiredAt !== undefined || value.revokedAt !== undefined)
  ) {
    errors.push(`keys[${index}] active keys must not have lifecycle end fields`);
  }

  if (value.status === "retired" && value.revokedAt !== undefined) {
    errors.push(`keys[${index}] retired keys must not have revokedAt`);
  }

  if (value.status === "revoked" && value.retiredAt !== undefined) {
    errors.push(`keys[${index}] revoked keys must not have retiredAt`);
  }

  return errors;
}

export function validateTrustStore(value: unknown): TrustStoreValidationResult {
  if (!isObject(value)) {
    return { ok: false, errors: ["trust store must be an object"] };
  }

  const errors: string[] = [];
  const allowedFields = new Set(["version", "keys"]);

  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      errors.push(`unexpected trust store field '${field}'`);
    }
  }

  if (value.version !== 1) {
    errors.push("version must be 1");
  }

  if (!Array.isArray(value.keys)) {
    errors.push("keys must be an array");
  } else if (value.keys.length > MAX_TRUST_KEYS) {
    errors.push(`keys must contain at most ${String(MAX_TRUST_KEYS)} entries`);
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

  try {
    canonicalize(value);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push(`trust store exceeds the JSON safety limits: ${message}`);
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

function assertValidTrustStore(store: TrustStore): void {
  const validation = validateTrustStore(store);

  if (!validation.ok) {
    throw new Error(`invalid trust store: ${validation.errors.join("; ")}`);
  }
}

export function addTrustAnchor(
  store: TrustStore,
  publicKey: string,
  addedAt = new Date().toISOString(),
): TrustStore {
  assertValidTrustStore(store);

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
  assertValidTrustStore(store);

  if (!isIsoDate(revokedAt)) {
    throw new Error("revokedAt must be a canonical ISO-8601 timestamp");
  }

  const existing = store.keys.find((key) => key.publicKeyId === keyId);

  if (!existing) {
    throw new Error(`trusted key '${keyId}' was not found`);
  }

  if (Date.parse(revokedAt) < Date.parse(existing.addedAt)) {
    throw new Error("revokedAt must not be before the key was added");
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
    artifactVersion: 1,
    algorithm: "ed25519",
    previousPublicKey: previous.publicKeyDer,
    previousPublicKeyId: publicKeyId(previous.publicKeyDer),
    newPublicKey: next.publicKeyDer,
    newPublicKeyId: publicKeyId(next.publicKeyDer),
    rotatedAt,
  };
  const signature = ed25519Sign(
    null,
    signatureMessage("key-rotation", body),
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

  const allowedFields = new Set([
    "artifactVersion",
    "algorithm",
    "previousPublicKey",
    "previousPublicKeyId",
    "newPublicKey",
    "newPublicKeyId",
    "rotatedAt",
    "signature",
  ]);

  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      return {
        valid: false,
        reasonCode: "E_ROTATION_INVALID",
        detail: `unexpected key rotation field '${field}'`,
      };
    }
  }

  if (value.artifactVersion !== 1) {
    return {
      valid: false,
      reasonCode: "E_ARTIFACT_VERSION_UNSUPPORTED",
      detail: "only key rotation artifactVersion 1 is supported",
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
    typeof value.previousPublicKey !== "string" ||
    value.previousPublicKey.length > 128 ||
    !isCanonicalBase64(value.previousPublicKey) ||
    typeof value.newPublicKey !== "string" ||
    value.newPublicKey.length > 128 ||
    !isCanonicalBase64(value.newPublicKey) ||
    typeof value.previousPublicKeyId !== "string" ||
    typeof value.newPublicKeyId !== "string" ||
    !KEY_ID.test(value.previousPublicKeyId) ||
    !KEY_ID.test(value.newPublicKeyId) ||
    !isIsoDate(value.rotatedAt) ||
    typeof value.signature !== "string" ||
    value.signature.length !== 88 ||
    !isCanonicalBase64(value.signature) ||
    Buffer.from(value.signature, "base64").length !== 64
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
      signatureMessage("key-rotation", body),
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
  assertValidTrustStore(store);

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
  now = new Date(),
): VerifyResult {
  const storeValidation = validateTrustStore(store);
  if (!storeValidation.ok) {
    return {
      valid: false,
      reasonCode: "E_TRUST_STORE_INVALID",
      detail: storeValidation.errors.join("; "),
    };
  }

  if (!isIsoDate(artifactTimestamp)) {
    return {
      valid: false,
      reasonCode: "E_ARTIFACT_TIMESTAMP_INVALID",
      detail: "artifact timestamp must be canonical ISO-8601",
    };
  }

  if (
    !Number.isFinite(now.getTime()) ||
    Date.parse(artifactTimestamp) > now.getTime() + MAX_CLOCK_SKEW_MS
  ) {
    return {
      valid: false,
      reasonCode: "E_ARTIFACT_TIMESTAMP_FUTURE",
      detail: "artifact timestamp is beyond the allowed clock skew",
    };
  }

  let id: string;
  try {
    publicKeyFromDer(publicKey);
    id = publicKeyId(publicKey);
  } catch {
    return {
      valid: false,
      reasonCode: "E_PUBLIC_KEY_INVALID",
      detail: "artifact public key is not valid Ed25519 key material",
    };
  }
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
