import { randomUUID, verify as ed25519Verify } from "node:crypto";
import type { AdmissionAttestation, Decision } from "./types.js";
import {
  isCanonicalBase64,
  publicKeyFromDer,
  publicKeyId,
  signWithKeyPair,
  signatureMessage,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import type { VerifyResult } from "./signing.js";

const SHA256_HEX = /^[a-f0-9]{64}$/;
const KEY_ID = /^[a-f0-9]{64}$/;
const ATTESTATION_ID =
  /^att_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const TOOL_NAME = /^[a-zA-Z0-9._-]{1,256}$/;
const MAX_DETAIL_LENGTH = 512;

export interface AdmissionAttestationInput {
  manifestHash: string;
  toolName: string;
  decision: Decision;
  reasonCode: string;
  detail: string;
  meterCountAtCheck: number;
}

export interface AdmissionAttestationValidationResult {
  ok: boolean;
  attestation?: AdmissionAttestation;
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

function isSignature(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length === 88 &&
    isCanonicalBase64(value) &&
    Buffer.from(value, "base64").length === 64
  );
}

function isNonEmptyDetail(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_DETAIL_LENGTH
  );
}

function validateAttestationInput(input: AdmissionAttestationInput): void {
  if (!SHA256_HEX.test(input.manifestHash)) {
    throw new Error("manifestHash must be a lowercase SHA-256 hex digest");
  }

  if (typeof input.toolName !== "string" || !TOOL_NAME.test(input.toolName)) {
    throw new Error(
      "toolName must match /^[a-zA-Z0-9._-]{1,256}$/ (ASCII, no whitespace or control characters)",
    );
  }

  if (input.decision !== "allow" && input.decision !== "deny") {
    throw new Error("decision must be allow or deny");
  }

  if (!REASON_CODE.test(input.reasonCode)) {
    throw new Error("reasonCode must be an uppercase machine-readable code");
  }

  if (input.decision === "allow" && input.reasonCode !== "ALLOWED") {
    throw new Error("allow attestations must carry reasonCode ALLOWED");
  }

  if (input.decision === "deny" && input.reasonCode === "ALLOWED") {
    throw new Error("deny attestations must not carry reasonCode ALLOWED");
  }

  if (!isNonEmptyDetail(input.detail)) {
    throw new Error(`detail must be a non-empty string up to ${String(MAX_DETAIL_LENGTH)} characters`);
  }

  if (
    !Number.isSafeInteger(input.meterCountAtCheck) ||
    input.meterCountAtCheck < 0
  ) {
    throw new Error("meterCountAtCheck must be a safe non-negative integer");
  }
}

// Shape-only validation, mirroring validateReceipt()/validateSignedManifest()
// in src/signing.ts: field presence, format, and cross-field consistency.
// Does not verify the signature — see verifyAdmissionAttestationDetailed().
export function validateAdmissionAttestation(
  value: unknown,
): AdmissionAttestationValidationResult {
  if (!isObject(value)) {
    return { ok: false, errors: ["admission attestation must be an object"] };
  }

  const errors: string[] = [];
  const allowedFields = new Set([
    "artifactVersion",
    "attestationId",
    "manifestHash",
    "toolName",
    "decision",
    "reasonCode",
    "detail",
    "meterCountAtCheck",
    "timestamp",
    "publicKeyId",
    "algorithm",
    "signature",
  ]);

  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      errors.push(`unexpected admission attestation field '${field}'`);
    }
  }

  if (value.artifactVersion !== 1) {
    errors.push("artifactVersion must be 1");
  }

  if (typeof value.attestationId !== "string" || !ATTESTATION_ID.test(value.attestationId)) {
    errors.push("attestationId must be att_ followed by a canonical UUIDv4");
  }

  if (typeof value.manifestHash !== "string" || !SHA256_HEX.test(value.manifestHash)) {
    errors.push("manifestHash must be a lowercase SHA-256 hex digest");
  }

  if (typeof value.toolName !== "string" || !TOOL_NAME.test(value.toolName)) {
    errors.push(
      "toolName must match /^[a-zA-Z0-9._-]{1,256}$/ (ASCII, no whitespace or control characters)",
    );
  }

  if (value.decision !== "allow" && value.decision !== "deny") {
    errors.push("decision must be allow or deny");
  }

  if (typeof value.reasonCode !== "string" || !REASON_CODE.test(value.reasonCode)) {
    errors.push("reasonCode must be an uppercase machine-readable code");
  }

  if (!isNonEmptyDetail(value.detail)) {
    errors.push(`detail must be a non-empty string up to ${String(MAX_DETAIL_LENGTH)} characters`);
  }

  if (
    typeof value.meterCountAtCheck !== "number" ||
    !Number.isSafeInteger(value.meterCountAtCheck) ||
    value.meterCountAtCheck < 0
  ) {
    errors.push("meterCountAtCheck must be a safe non-negative integer");
  }

  if (!isIsoDate(value.timestamp)) {
    errors.push("timestamp must be a canonical ISO-8601 timestamp");
  }

  if (typeof value.publicKeyId !== "string" || !KEY_ID.test(value.publicKeyId)) {
    errors.push("publicKeyId must be a 64-character lowercase SHA-256 fingerprint");
  }

  if (value.algorithm !== "ed25519") {
    errors.push("algorithm must be ed25519");
  }

  if (value.decision === "allow" && value.reasonCode !== "ALLOWED") {
    errors.push("allow attestations must carry reasonCode ALLOWED");
  }

  if (value.decision === "deny" && value.reasonCode === "ALLOWED") {
    errors.push("deny attestations must not carry reasonCode ALLOWED");
  }

  if (!isSignature(value.signature)) {
    errors.push("signature must be a canonical base64 Ed25519 signature");
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    attestation: value as unknown as AdmissionAttestation,
    errors: [],
  };
}

function buildAttestationBody(
  input: AdmissionAttestationInput,
  publicKeyIdValue: string,
): Omit<AdmissionAttestation, "signature"> {
  validateAttestationInput(input);

  return {
    artifactVersion: 1,
    attestationId: "att_" + randomUUID(),
    manifestHash: input.manifestHash,
    toolName: input.toolName,
    decision: input.decision,
    reasonCode: input.reasonCode,
    detail: input.detail,
    meterCountAtCheck: input.meterCountAtCheck,
    timestamp: new Date().toISOString(),
    publicKeyId: publicKeyIdValue,
    algorithm: "ed25519",
  };
}

// Signs a non-consuming admission decision snapshot with the same Ed25519
// primitive (signWithKeyPair) that signManifest()/createReceipt() already
// use. This is NOT a Receipt: it never touches the meter's write path (no
// lock is acquired, no budget is consumed) and does not constitute evidence
// that a tool call was executed. It proves only: "at this timestamp, given
// this meter snapshot, this decision would have been made." See
// docs/RUNTIME_ADMISSION.md for the full guarantee/non-guarantee statement.
export function createAdmissionAttestation(
  input: AdmissionAttestationInput,
  keypair: KeyPair,
): AdmissionAttestation {
  if (!validateKeyPair(keypair)) {
    throw new Error("invalid or mismatched Ed25519 key pair");
  }

  const body = buildAttestationBody(input, publicKeyId(keypair.publicKeyDer));
  const signature = signWithKeyPair(
    signatureMessage("admission-attestation", body),
    keypair,
  );

  return {
    ...body,
    signature: signature.toString("base64"),
  };
}

export function verifyAdmissionAttestationDetailed(
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
      detail: "only admission attestation artifactVersion 1 is supported",
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
      detail: "only ed25519 admission attestations are supported",
    };
  }

  const validation = validateAdmissionAttestation(value);

  if (!validation.ok || !validation.attestation) {
    return {
      valid: false,
      reasonCode: "E_ATTESTATION_INVALID",
      detail: validation.errors.join("; "),
    };
  }

  const attestation = validation.attestation;

  if (publicKeyId(publicKeyDer) !== attestation.publicKeyId) {
    return {
      valid: false,
      reasonCode: "E_PUBLIC_KEY_ID_MISMATCH",
      detail: "attestation publicKeyId does not match public key",
    };
  }

  const { signature, ...body } = attestation;

  try {
    const valid = ed25519Verify(
      null,
      signatureMessage("admission-attestation", body),
      publicKeyFromDer(publicKeyDer),
      Buffer.from(signature, "base64"),
    );

    return valid
      ? {
          valid: true,
          reasonCode: "OK",
          detail: "admission attestation signature is valid",
        }
      : {
          valid: false,
          reasonCode: "E_SIGNATURE_INVALID",
          detail: "attestation signature does not verify against the public key",
        };
  } catch {
    return {
      valid: false,
      reasonCode: "E_SIGNATURE_CHECK_FAILED",
      detail: "attestation signature verification failed",
    };
  }
}
