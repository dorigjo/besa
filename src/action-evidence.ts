import { randomUUID, verify as ed25519Verify } from "node:crypto";
import {
  canonicalize,
  isCanonicalBase64,
  publicKeyFromDer,
  publicKeyId,
  sha256Hex,
  signWithKeyPair,
  signatureMessage,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import {
  hashActionEnvelope,
  validateActionEnvelope,
  type ActionEnvelopeV1,
} from "./action.js";
import {
  hashActionCapability,
  validateActionCapability,
  verifyActionCapability,
  type ActionCapabilityV1,
} from "./action-capability.js";
import { checkTrustedKey } from "./trust.js";
import type { TrustStore } from "./types.js";

export type ActionOutcome = "succeeded" | "failed";

export interface ActionEvidenceV1 {
  artifactVersion: 1;
  evidenceId: string;
  actionHash: string;
  capabilityHash: string;
  delegationChainHash: string | null;
  receiptHash: string | null;
  resultHash: string;
  outcome: ActionOutcome;
  executorId: string;
  startedAt: string;
  completedAt: string;
  recorderId: string;
  recorderPublicKey: string;
  recorderPublicKeyId: string;
  recordedAt: string;
  algorithm: "ed25519";
  signature: string;
}

export interface CreateActionEvidenceInput {
  evidenceId?: string;
  action: ActionEnvelopeV1;
  capability: ActionCapabilityV1;
  result: unknown;
  outcome: ActionOutcome;
  executorId: string;
  recorderId: string;
  receiptHash: string | null;
  startedAt: string;
  completedAt: string;
  recordedAt: string;
}

export interface VerifyActionEvidenceInput {
  action: unknown;
  capability: unknown;
  result: unknown;
  trustStore: TrustStore;
  receiptHash?: string | null;
}

export interface ActionEvidenceValidationResult {
  ok: boolean;
  evidence?: ActionEvidenceV1;
  errors: string[];
}

export interface ActionEvidenceVerificationResult {
  valid: boolean;
  reasonCode: string;
  detail: string;
  evidence?: ActionEvidenceV1;
}

export const EVIDENCE_REASON = {
  VALID: "EVIDENCE_VALID",
  INVALID: "SCHEMA_EVIDENCE_INVALID",
  SIGNATURE_INVALID: "SIGNATURE_EVIDENCE_INVALID",
  RECORDER_UNTRUSTED: "TRUST_EVIDENCE_RECORDER_UNTRUSTED",
  NOT_ACTIVE: "EXPIRY_EVIDENCE_TIME_INVALID",
  LINK_MISMATCH: "EVIDENCE_LINK_MISMATCH",
  CAPABILITY_INVALID: "EVIDENCE_CAPABILITY_INVALID",
} as const;

const MAX_EVIDENCE_BYTES = 131_072;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const ID_PATTERN =
  /^evd_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const ALLOWED_FIELDS = new Set([
  "artifactVersion",
  "evidenceId",
  "actionHash",
  "capabilityHash",
  "delegationChainHash",
  "receiptHash",
  "resultHash",
  "outcome",
  "executorId",
  "startedAt",
  "completedAt",
  "recorderId",
  "recorderPublicKey",
  "recorderPublicKeyId",
  "recordedAt",
  "algorithm",
  "signature",
]);

type EvidenceBody = Omit<ActionEvidenceV1, "signature">;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isBoundedText(value: unknown, maxLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength &&
    value === value.trim() &&
    value === value.normalize("NFC") &&
    !CONTROL_PATTERN.test(value)
  );
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function canonicalCopy(value: unknown): unknown {
  const canonical = canonicalize(value);
  if (Buffer.byteLength(canonical, "utf8") > MAX_EVIDENCE_BYTES) {
    throw new TypeError("action evidence exceeds the 131072 byte limit");
  }
  return JSON.parse(canonical) as unknown;
}

export function hashExecutionResult(result: unknown): string {
  return sha256Hex(`besa:execution-result:v1\0${canonicalize(result)}`);
}

export function validateActionEvidence(
  value: unknown,
): ActionEvidenceValidationResult {
  let candidate: unknown;
  try {
    candidate = canonicalCopy(value);
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : "invalid action evidence"],
    };
  }

  if (!isObject(candidate)) {
    return { ok: false, errors: ["action evidence must be an object"] };
  }

  const errors: string[] = [];
  for (const field of Object.keys(candidate)) {
    if (!ALLOWED_FIELDS.has(field)) {
      errors.push(`unexpected action evidence field '${field}'`);
    }
  }

  if (candidate.artifactVersion !== 1) errors.push("artifactVersion must be 1");
  if (typeof candidate.evidenceId !== "string" || !ID_PATTERN.test(candidate.evidenceId)) {
    errors.push("evidenceId must be an evd_ UUID");
  }
  for (const field of ["actionHash", "capabilityHash", "resultHash"] as const) {
    if (typeof candidate[field] !== "string" || !HASH_PATTERN.test(candidate[field])) {
      errors.push(`${field} must be 64 lowercase hexadecimal characters`);
    }
  }
  for (const field of ["delegationChainHash", "receiptHash"] as const) {
    if (
      candidate[field] !== null &&
      (typeof candidate[field] !== "string" || !HASH_PATTERN.test(candidate[field]))
    ) {
      errors.push(`${field} must be null or a SHA-256 hash`);
    }
  }
  if (candidate.outcome !== "succeeded" && candidate.outcome !== "failed") {
    errors.push("outcome must be succeeded or failed");
  }
  for (const field of ["executorId", "recorderId"] as const) {
    if (!isBoundedText(candidate[field], 512)) {
      errors.push(`${field} must be bounded NFC text without controls`);
    }
  }
  for (const field of ["startedAt", "completedAt", "recordedAt"] as const) {
    if (!isCanonicalTimestamp(candidate[field])) {
      errors.push(`${field} must be a canonical UTC timestamp`);
    }
  }
  if (
    isCanonicalTimestamp(candidate.startedAt) &&
    isCanonicalTimestamp(candidate.completedAt) &&
    isCanonicalTimestamp(candidate.recordedAt) &&
    (Date.parse(candidate.startedAt) > Date.parse(candidate.completedAt) ||
      Date.parse(candidate.completedAt) > Date.parse(candidate.recordedAt))
  ) {
    errors.push("evidence timestamps must satisfy startedAt <= completedAt <= recordedAt");
  }

  if (
    typeof candidate.recorderPublicKey !== "string" ||
    typeof candidate.recorderPublicKeyId !== "string"
  ) {
    errors.push("recorder public key fields must be strings");
  } else {
    try {
      publicKeyFromDer(candidate.recorderPublicKey);
      if (publicKeyId(candidate.recorderPublicKey) !== candidate.recorderPublicKeyId) {
        errors.push("recorderPublicKeyId does not match recorderPublicKey");
      }
    } catch {
      errors.push("recorderPublicKey must be a canonical Ed25519 public key");
    }
  }
  if (candidate.algorithm !== "ed25519") errors.push("algorithm must be ed25519");
  if (
    typeof candidate.signature !== "string" ||
    !isCanonicalBase64(candidate.signature) ||
    Buffer.from(candidate.signature, "base64").length !== 64
  ) {
    errors.push("signature must be a canonical Ed25519 signature");
  }

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    evidence: candidate as unknown as ActionEvidenceV1,
    errors: [],
  };
}

export function createActionEvidence(
  input: CreateActionEvidenceInput,
  recorderKeyPair: KeyPair,
): ActionEvidenceV1 {
  if (!validateKeyPair(recorderKeyPair)) {
    throw new TypeError("invalid or mismatched evidence recorder key pair");
  }
  const actionValidation = validateActionEnvelope(input.action);
  const capabilityValidation = validateActionCapability(input.capability);
  if (!actionValidation.ok || !actionValidation.action) {
    throw new TypeError(`Invalid action envelope: ${actionValidation.errors.join("; ")}`);
  }
  if (!capabilityValidation.ok || !capabilityValidation.capability) {
    throw new TypeError(`Invalid action capability: ${capabilityValidation.errors.join("; ")}`);
  }
  const action = actionValidation.action;
  const capability = capabilityValidation.capability;
  if (
    capability.decision !== "allow" ||
    capability.actionHash !== hashActionEnvelope(action)
  ) {
    throw new TypeError("action evidence requires an ALLOW capability for the exact action");
  }
  if (
    !isCanonicalTimestamp(input.startedAt) ||
    !isCanonicalTimestamp(input.completedAt) ||
    !isCanonicalTimestamp(input.recordedAt) ||
    Date.parse(input.startedAt) < Date.parse(capability.issuedAt) ||
    Date.parse(input.startedAt) >= Date.parse(capability.expiresAt) ||
    Date.parse(input.startedAt) > Date.parse(input.completedAt) ||
    Date.parse(input.completedAt) > Date.parse(input.recordedAt)
  ) {
    throw new TypeError("action evidence timestamps are outside the authorization interval");
  }

  const body: EvidenceBody = {
    artifactVersion: 1,
    evidenceId: input.evidenceId ?? `evd_${randomUUID()}`,
    actionHash: hashActionEnvelope(action),
    capabilityHash: hashActionCapability(capability),
    delegationChainHash: capability.delegationChainHash,
    receiptHash: input.receiptHash,
    resultHash: hashExecutionResult(input.result),
    outcome: input.outcome,
    executorId: input.executorId,
    startedAt: input.startedAt,
    completedAt: input.completedAt,
    recorderId: input.recorderId,
    recorderPublicKey: recorderKeyPair.publicKeyDer,
    recorderPublicKeyId: publicKeyId(recorderKeyPair.publicKeyDer),
    recordedAt: input.recordedAt,
    algorithm: "ed25519",
  };
  const evidence: ActionEvidenceV1 = {
    ...body,
    signature: signWithKeyPair(
      signatureMessage("action-evidence", body),
      recorderKeyPair,
    ).toString("base64"),
  };
  const validation = validateActionEvidence(evidence);
  if (!validation.ok || !validation.evidence) {
    throw new TypeError(`Invalid action evidence: ${validation.errors.join("; ")}`);
  }
  return validation.evidence;
}

export function hashActionEvidence(value: ActionEvidenceV1): string {
  const validation = validateActionEvidence(value);
  if (!validation.ok || !validation.evidence) {
    throw new TypeError(`Invalid action evidence: ${validation.errors.join("; ")}`);
  }
  return sha256Hex(
    `besa:action-evidence-artifact:v1\0${canonicalize(validation.evidence)}`,
  );
}

export function verifyActionEvidence(
  value: unknown,
  input: VerifyActionEvidenceInput,
  at = new Date(),
): ActionEvidenceVerificationResult {
  const validation = validateActionEvidence(value);
  if (!validation.ok || !validation.evidence) {
    return {
      valid: false,
      reasonCode: EVIDENCE_REASON.INVALID,
      detail: validation.errors.join("; "),
    };
  }
  const evidence = validation.evidence;
  const { signature, ...body } = evidence;
  try {
    if (
      !ed25519Verify(
        null,
        signatureMessage("action-evidence", body),
        publicKeyFromDer(evidence.recorderPublicKey),
        Buffer.from(signature, "base64"),
      )
    ) {
      return {
        valid: false,
        reasonCode: EVIDENCE_REASON.SIGNATURE_INVALID,
        detail: "action evidence signature is invalid",
      };
    }
  } catch {
    return {
      valid: false,
      reasonCode: EVIDENCE_REASON.SIGNATURE_INVALID,
      detail: "action evidence signature verification failed",
    };
  }

  const trust = checkTrustedKey(
    input.trustStore,
    evidence.recorderPublicKey,
    evidence.recordedAt,
    "verify",
    at,
  );
  if (!trust.valid) {
    return {
      valid: false,
      reasonCode: EVIDENCE_REASON.RECORDER_UNTRUSTED,
      detail: `evidence recorder is not trusted: ${trust.reasonCode}`,
    };
  }
  if (!Number.isFinite(at.getTime()) || Date.parse(evidence.recordedAt) > at.getTime()) {
    return {
      valid: false,
      reasonCode: EVIDENCE_REASON.NOT_ACTIVE,
      detail: "evidence was recorded after the verification time",
    };
  }

  const actionValidation = validateActionEnvelope(input.action);
  const capabilityValidation = validateActionCapability(input.capability);
  if (
    !actionValidation.ok ||
    !actionValidation.action ||
    !capabilityValidation.ok ||
    !capabilityValidation.capability
  ) {
    return {
      valid: false,
      reasonCode: EVIDENCE_REASON.LINK_MISMATCH,
      detail: "supplied action or capability is invalid",
    };
  }
  const action = actionValidation.action;
  const capability = capabilityValidation.capability;
  if (
    evidence.actionHash !== hashActionEnvelope(action) ||
    evidence.capabilityHash !== hashActionCapability(capability) ||
    evidence.delegationChainHash !== capability.delegationChainHash ||
    evidence.resultHash !== hashExecutionResult(input.result) ||
    (input.receiptHash !== undefined && evidence.receiptHash !== input.receiptHash)
  ) {
    return {
      valid: false,
      reasonCode: EVIDENCE_REASON.LINK_MISMATCH,
      detail: "action evidence does not match the supplied artifacts or result",
    };
  }

  const capabilityCheck = verifyActionCapability(
    capability,
    action,
    input.trustStore,
    new Date(evidence.startedAt),
  );
  if (!capabilityCheck.valid || !capabilityCheck.authorized) {
    return {
      valid: false,
      reasonCode: EVIDENCE_REASON.CAPABILITY_INVALID,
      detail: `linked capability did not authorize execution: ${capabilityCheck.reasonCode}`,
    };
  }

  return {
    valid: true,
    reasonCode: EVIDENCE_REASON.VALID,
    detail: "action evidence signature and supplied artifact links are valid",
    evidence,
  };
}
