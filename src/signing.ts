import {
  randomUUID,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import type { Decision, Manifest, Receipt, SignedManifest } from "./types.js";
import {
  canonicalize,
  hashObject,
  privateKeyFromDer,
  publicKeyFromDer,
  publicKeyId,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import { validateManifest } from "./manifest.js";

const SHA256_HEX = /^[a-f0-9]{64}$/;
const KEY_ID = /^[a-f0-9]{16}$/;

export interface VerifyResult {
  valid: boolean;
  reasonCode: string;
  detail: string;
}

export interface SignedManifestValidationResult {
  ok: boolean;
  signedManifest?: SignedManifest;
  errors: string[];
}

export interface ReceiptValidationResult {
  ok: boolean;
  receipt?: Receipt;
  errors: string[];
}

export interface ReceiptInput {
  manifestHash: string;
  toolName: string;
  decision: Decision;
  reasonCode: string;
  request: unknown;
  agentId?: string;
  grantReasonCode?: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isIsoDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isBase64(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }

  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}

export function validateSignedManifest(
  value: unknown,
): SignedManifestValidationResult {
  if (!isObject(value)) {
    return {
      ok: false,
      errors: ["signed manifest must be an object"],
    };
  }

  const errors: string[] = [];
  const manifestResult = validateManifest(value.manifest);

  if (!manifestResult.ok) {
    errors.push(
      ...manifestResult.errors.map((error) => `manifest.${error}`),
    );
  }

  if (typeof value.manifestHash !== "string" || !SHA256_HEX.test(value.manifestHash)) {
    errors.push("manifestHash must be a lowercase SHA-256 hex digest");
  }

  if (value.algorithm !== "ed25519") {
    errors.push("algorithm must be ed25519");
  }

  if (!isBase64(value.publicKey)) {
    errors.push("publicKey must be canonical base64");
  }

  if (typeof value.publicKeyId !== "string" || !KEY_ID.test(value.publicKeyId)) {
    errors.push("publicKeyId must be a 16-character lowercase hex string");
  }

  if (!isBase64(value.signature)) {
    errors.push("signature must be canonical base64");
  }

  if (!isIsoDate(value.signedAt)) {
    errors.push("signedAt must be a canonical ISO-8601 timestamp");
  }

  if (errors.length > 0 || !manifestResult.manifest) {
    return {
      ok: false,
      errors,
    };
  }

  return {
    ok: true,
    signedManifest: value as unknown as SignedManifest,
    errors: [],
  };
}

export function validateReceipt(value: unknown): ReceiptValidationResult {
  if (!isObject(value)) {
    return {
      ok: false,
      errors: ["receipt must be an object"],
    };
  }

  const errors: string[] = [];

  if (!isNonEmptyString(value.receiptId) || !value.receiptId.startsWith("rcpt_")) {
    errors.push("receiptId must start with rcpt_");
  }

  if (typeof value.manifestHash !== "string" || !SHA256_HEX.test(value.manifestHash)) {
    errors.push("manifestHash must be a lowercase SHA-256 hex digest");
  }

  if (!isNonEmptyString(value.toolName)) {
    errors.push("toolName must be a non-empty string");
  }

  if (value.decision !== "allow" && value.decision !== "deny") {
    errors.push("decision must be allow or deny");
  }

  if (!isNonEmptyString(value.reasonCode)) {
    errors.push("reasonCode must be a non-empty string");
  }

  if (!isIsoDate(value.timestamp)) {
    errors.push("timestamp must be a canonical ISO-8601 timestamp");
  }

  if (typeof value.requestHash !== "string" || !SHA256_HEX.test(value.requestHash)) {
    errors.push("requestHash must be a lowercase SHA-256 hex digest");
  }

  if (typeof value.publicKeyId !== "string" || !KEY_ID.test(value.publicKeyId)) {
    errors.push("publicKeyId must be a 16-character lowercase hex string");
  }

  if (value.algorithm !== "ed25519") {
    errors.push("algorithm must be ed25519");
  }

  if (value.agentId !== undefined && !isNonEmptyString(value.agentId)) {
    errors.push("agentId must be a non-empty string when present");
  }

  if (
    value.grantReasonCode !== undefined &&
    !isNonEmptyString(value.grantReasonCode)
  ) {
    errors.push("grantReasonCode must be a non-empty string when present");
  }

  if (!isBase64(value.signature)) {
    errors.push("signature must be canonical base64");
  }

  if (errors.length > 0) {
    return {
      ok: false,
      errors,
    };
  }

  return {
    ok: true,
    receipt: value as unknown as Receipt,
    errors: [],
  };
}

export function hashManifest(manifest: Manifest): string {
  return hashObject(manifest);
}

export function signManifest(manifest: Manifest, keypair: KeyPair): SignedManifest {
  const validation = validateManifest(manifest);

  if (!validation.ok || !validation.manifest) {
    throw new Error(`Invalid manifest:\n  - ${validation.errors.join("\n  - ")}`);
  }

  if (!validateKeyPair(keypair)) {
    throw new Error("invalid or mismatched Ed25519 key pair");
  }

  const canonical = canonicalize(validation.manifest);
  const signature = ed25519Sign(
    null,
    Buffer.from(canonical, "utf8"),
    privateKeyFromDer(keypair.privateKeyDer),
  );

  return {
    manifest: validation.manifest,
    manifestHash: hashManifest(validation.manifest),
    algorithm: "ed25519",
    publicKey: keypair.publicKeyDer,
    publicKeyId: publicKeyId(keypair.publicKeyDer),
    signature: signature.toString("base64"),
    signedAt: new Date().toISOString(),
  };
}

export function verifySignedManifest(value: unknown): VerifyResult {
  if (
    isObject(value) &&
    typeof value.algorithm === "string" &&
    value.algorithm !== "ed25519"
  ) {
    return {
      valid: false,
      reasonCode: "E_ALGORITHM_UNSUPPORTED",
      detail: "only ed25519 signed manifests are supported",
    };
  }

  const validation = validateSignedManifest(value);

  if (!validation.ok || !validation.signedManifest) {
    return {
      valid: false,
      reasonCode: "E_SIGNED_MANIFEST_INVALID",
      detail: validation.errors.join("; "),
    };
  }

  const signed = validation.signedManifest;
  const canonical = canonicalize(signed.manifest);
  const expectedHash = hashManifest(signed.manifest);

  if (expectedHash !== signed.manifestHash) {
    return {
      valid: false,
      reasonCode: "E_MANIFEST_HASH_MISMATCH",
      detail: "manifest content does not match stored hash",
    };
  }

  if (publicKeyId(signed.publicKey) !== signed.publicKeyId) {
    return {
      valid: false,
      reasonCode: "E_PUBLIC_KEY_ID_MISMATCH",
      detail: "publicKeyId does not match publicKey",
    };
  }

  try {
    const valid = ed25519Verify(
      null,
      Buffer.from(canonical, "utf8"),
      publicKeyFromDer(signed.publicKey),
      Buffer.from(signed.signature, "base64"),
    );

    if (!valid) {
      return {
        valid: false,
        reasonCode: "E_SIGNATURE_INVALID",
        detail: "signature does not verify against the public key",
      };
    }

    return {
      valid: true,
      reasonCode: "OK",
      detail: "manifest signature is valid",
    };
  } catch {
    return {
      valid: false,
      reasonCode: "E_SIGNATURE_CHECK_FAILED",
      detail: "signature verification failed",
    };
  }
}

export function createReceipt(input: ReceiptInput, keypair: KeyPair): Receipt {
  if (!SHA256_HEX.test(input.manifestHash)) {
    throw new Error("manifestHash must be a lowercase SHA-256 hex digest");
  }

  if (!isNonEmptyString(input.toolName)) {
    throw new Error("toolName must be a non-empty string");
  }

  if (!isNonEmptyString(input.reasonCode)) {
    throw new Error("reasonCode must be a non-empty string");
  }

  if (!validateKeyPair(keypair)) {
    throw new Error("invalid or mismatched Ed25519 key pair");
  }

  const body: Omit<Receipt, "signature"> = {
    receiptId: "rcpt_" + randomUUID(),
    manifestHash: input.manifestHash,
    toolName: input.toolName,
    decision: input.decision,
    reasonCode: input.reasonCode,
    timestamp: new Date().toISOString(),
    requestHash: hashObject(input.request ?? {}),
    agentId: input.agentId,
    grantReasonCode: input.grantReasonCode,
    publicKeyId: publicKeyId(keypair.publicKeyDer),
    algorithm: "ed25519",
  };

  const signature = ed25519Sign(
    null,
    Buffer.from(canonicalize(body), "utf8"),
    privateKeyFromDer(keypair.privateKeyDer),
  );

  return {
    ...body,
    signature: signature.toString("base64"),
  };
}

export function verifyReceiptDetailed(
  value: unknown,
  publicKeyDer: string,
): VerifyResult {
  if (
    isObject(value) &&
    typeof value.algorithm === "string" &&
    value.algorithm !== "ed25519"
  ) {
    return {
      valid: false,
      reasonCode: "E_ALGORITHM_UNSUPPORTED",
      detail: "only ed25519 receipts are supported",
    };
  }

  const validation = validateReceipt(value);

  if (!validation.ok || !validation.receipt) {
    return {
      valid: false,
      reasonCode: "E_RECEIPT_INVALID",
      detail: validation.errors.join("; "),
    };
  }

  const receipt = validation.receipt;

  if (publicKeyId(publicKeyDer) !== receipt.publicKeyId) {
    return {
      valid: false,
      reasonCode: "E_PUBLIC_KEY_ID_MISMATCH",
      detail: "receipt publicKeyId does not match public key",
    };
  }

  const { signature, ...body } = receipt;

  try {
    const valid = ed25519Verify(
      null,
      Buffer.from(canonicalize(body), "utf8"),
      publicKeyFromDer(publicKeyDer),
      Buffer.from(signature, "base64"),
    );

    return valid
      ? {
          valid: true,
          reasonCode: "OK",
          detail: "receipt signature is valid",
        }
      : {
          valid: false,
          reasonCode: "E_SIGNATURE_INVALID",
          detail: "receipt signature does not verify against the public key",
        };
  } catch {
    return {
      valid: false,
      reasonCode: "E_SIGNATURE_CHECK_FAILED",
      detail: "receipt signature verification failed",
    };
  }
}

export function verifyReceipt(receipt: unknown, publicKeyDer: string): boolean {
  return verifyReceiptDetailed(receipt, publicKeyDer).valid;
}
