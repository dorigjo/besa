import {
  randomUUID,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import type { Decision, Manifest, Receipt, SignedManifest } from "./types.js";
import {
  canonicalize,
  isCanonicalBase64,
  privateKeyFromDer,
  publicKeyFromDer,
  publicKeyId,
  sha256Hex,
  signatureMessage,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import { validateManifest } from "./manifest.js";

const SHA256_HEX = /^[a-f0-9]{64}$/;
const KEY_ID = /^[a-f0-9]{64}$/;
const RECEIPT_ID = /^rcpt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const MAX_IDENTIFIER_LENGTH = 256;

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

type ManifestSignaturePayload = Omit<SignedManifest, "signature">;

function manifestSignaturePayload(
  signed: Omit<SignedManifest, "signature">,
): ManifestSignaturePayload {
  return {
    artifactVersion: signed.artifactVersion,
    manifest: signed.manifest,
    manifestHash: signed.manifestHash,
    algorithm: signed.algorithm,
    publicKey: signed.publicKey,
    publicKeyId: signed.publicKeyId,
    signedAt: signed.signedAt,
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(
  value: unknown,
  maximumLength = MAX_IDENTIFIER_LENGTH,
): value is string {
  return (
    typeof value === "string" &&
    value.length <= maximumLength &&
    value.trim().length > 0
  );
}

function isIsoDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 35 &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isSignature(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length === 88 &&
    isCanonicalBase64(value) &&
    Buffer.from(value, "base64").length === 64
  );
}

function isPublicKeyEncoding(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 128 &&
    isCanonicalBase64(value)
  );
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
  const allowedFields = new Set([
    "artifactVersion",
    "manifest",
    "manifestHash",
    "algorithm",
    "publicKey",
    "publicKeyId",
    "signature",
    "signedAt",
  ]);

  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      errors.push(`unexpected signed manifest field '${field}'`);
    }
  }

  if (value.artifactVersion !== 1) {
    errors.push("artifactVersion must be 1");
  }

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

  if (!isPublicKeyEncoding(value.publicKey)) {
    errors.push("publicKey must be canonical base64");
  }

  if (typeof value.publicKeyId !== "string" || !KEY_ID.test(value.publicKeyId)) {
    errors.push("publicKeyId must be a 64-character lowercase SHA-256 fingerprint");
  }

  if (!isSignature(value.signature)) {
    errors.push("signature must be a canonical base64 Ed25519 signature");
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
  const allowedFields = new Set([
    "artifactVersion",
    "receiptId",
    "manifestHash",
    "toolName",
    "decision",
    "reasonCode",
    "timestamp",
    "requestHash",
    "publicKeyId",
    "algorithm",
    "agentId",
    "grantReasonCode",
    "signature",
  ]);

  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      errors.push(`unexpected receipt field '${field}'`);
    }
  }

  if (value.artifactVersion !== 1) {
    errors.push("artifactVersion must be 1");
  }

  if (typeof value.receiptId !== "string" || !RECEIPT_ID.test(value.receiptId)) {
    errors.push("receiptId must be rcpt_ followed by a canonical UUIDv4");
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

  if (typeof value.reasonCode !== "string" || !REASON_CODE.test(value.reasonCode)) {
    errors.push("reasonCode must be an uppercase machine-readable code");
  }

  if (!isIsoDate(value.timestamp)) {
    errors.push("timestamp must be a canonical ISO-8601 timestamp");
  }

  if (typeof value.requestHash !== "string" || !SHA256_HEX.test(value.requestHash)) {
    errors.push("requestHash must be a lowercase SHA-256 hex digest");
  }

  if (typeof value.publicKeyId !== "string" || !KEY_ID.test(value.publicKeyId)) {
    errors.push("publicKeyId must be a 64-character lowercase SHA-256 fingerprint");
  }

  if (value.algorithm !== "ed25519") {
    errors.push("algorithm must be ed25519");
  }

  if (value.agentId !== undefined && !isNonEmptyString(value.agentId)) {
    errors.push("agentId must be a non-empty string when present");
  }

  if (
    value.grantReasonCode !== undefined &&
    (typeof value.grantReasonCode !== "string" ||
      !REASON_CODE.test(value.grantReasonCode))
  ) {
    errors.push("grantReasonCode must be a non-empty string when present");
  }

  if (!isSignature(value.signature)) {
    errors.push("signature must be a canonical base64 Ed25519 signature");
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
  return sha256Hex(`besa:manifest:v1\0${canonicalize(manifest)}`);
}

export function hashRequest(request: unknown): string {
  return sha256Hex(`besa:request:v1\0${canonicalize(request)}`);
}

export function signManifest(manifest: Manifest, keypair: KeyPair): SignedManifest {
  const validation = validateManifest(manifest);

  if (!validation.ok || !validation.manifest) {
    throw new Error(`Invalid manifest:\n  - ${validation.errors.join("\n  - ")}`);
  }

  if (!validateKeyPair(keypair)) {
    throw new Error("invalid or mismatched Ed25519 key pair");
  }

  const body = {
    artifactVersion: 1 as const,
    manifest: validation.manifest,
    manifestHash: hashManifest(validation.manifest),
    algorithm: "ed25519" as const,
    publicKey: keypair.publicKeyDer,
    publicKeyId: publicKeyId(keypair.publicKeyDer),
    signedAt: new Date().toISOString(),
  };
  const signature = ed25519Sign(
    null,
    signatureMessage("signed-manifest", manifestSignaturePayload(body)),
    privateKeyFromDer(keypair.privateKeyDer),
  );

  return {
    ...body,
    signature: signature.toString("base64"),
  };
}

export function verifySignedManifest(value: unknown): VerifyResult {
  if (
    isObject(value) &&
    value.artifactVersion !== undefined &&
    value.artifactVersion !== 1
  ) {
    return {
      valid: false,
      reasonCode: "E_ARTIFACT_VERSION_UNSUPPORTED",
      detail: "only signed manifest artifactVersion 1 is supported",
    };
  }

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
      signatureMessage("signed-manifest", manifestSignaturePayload(signed)),
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

  if (!REASON_CODE.test(input.reasonCode)) {
    throw new Error("reasonCode must be an uppercase machine-readable code");
  }

  if (input.decision !== "allow" && input.decision !== "deny") {
    throw new Error("decision must be allow or deny");
  }

  if (input.agentId !== undefined && !isNonEmptyString(input.agentId)) {
    throw new Error("agentId must be a non-empty string when present");
  }

  if (
    input.grantReasonCode !== undefined &&
    !REASON_CODE.test(input.grantReasonCode)
  ) {
    throw new Error("grantReasonCode must be a non-empty string when present");
  }

  if (!validateKeyPair(keypair)) {
    throw new Error("invalid or mismatched Ed25519 key pair");
  }

  const body: Omit<Receipt, "signature"> = {
    artifactVersion: 1,
    receiptId: "rcpt_" + randomUUID(),
    manifestHash: input.manifestHash,
    toolName: input.toolName,
    decision: input.decision,
    reasonCode: input.reasonCode,
    timestamp: new Date().toISOString(),
    requestHash: hashRequest(input.request === undefined ? {} : input.request),
    ...(input.agentId === undefined ? {} : { agentId: input.agentId }),
    ...(input.grantReasonCode === undefined
      ? {}
      : { grantReasonCode: input.grantReasonCode }),
    publicKeyId: publicKeyId(keypair.publicKeyDer),
    algorithm: "ed25519",
  };

  const signature = ed25519Sign(
    null,
    signatureMessage("receipt", body),
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
    value.artifactVersion !== undefined &&
    value.artifactVersion !== 1
  ) {
    return {
      valid: false,
      reasonCode: "E_ARTIFACT_VERSION_UNSUPPORTED",
      detail: "only receipt artifactVersion 1 is supported",
    };
  }

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
      signatureMessage("receipt", body),
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
