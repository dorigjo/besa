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
  checkActionEnvelope,
  hashActionEnvelope,
  validateActionEnvelope,
  type ActionEnvelopeV1,
  type JsonObject,
} from "./action.js";
import { checkTrustedKey } from "./trust.js";
import type { Decision, TrustStore } from "./types.js";

export interface ActionCapabilityV1 {
  artifactVersion: 1;
  capabilityId: string;
  actionHash: string;
  principalId: string;
  agentId: string;
  authority: string;
  tool: string;
  operation: string;
  resource: string;
  constraintsHash: string;
  expiresAt: string;
  nonce: string;
  policyId: string;
  delegationChainHash: string | null;
  decision: Decision;
  reasonCode: string;
  issuerId: string;
  issuerPublicKey: string;
  issuerPublicKeyId: string;
  issuedAt: string;
  algorithm: "ed25519";
  signature: string;
}

export interface CreateActionCapabilityInput {
  capabilityId?: string;
  action: ActionEnvelopeV1;
  policyId: string;
  delegationChainHash: string | null;
  decision: Decision;
  reasonCode: string;
  issuerId: string;
  issuedAt: string;
}

export interface ActionCapabilityValidationResult {
  ok: boolean;
  capability?: ActionCapabilityV1;
  errors: string[];
}

export interface ActionCapabilityVerificationResult {
  valid: boolean;
  authorized: boolean;
  reasonCode: string;
  detail: string;
  capability?: ActionCapabilityV1;
}

export const CAPABILITY_REASON = {
  VALID: "CAPABILITY_VALID",
  INVALID: "SCHEMA_CAPABILITY_INVALID",
  SIGNATURE_INVALID: "SIGNATURE_CAPABILITY_INVALID",
  ISSUER_UNTRUSTED: "TRUST_CAPABILITY_ISSUER_UNTRUSTED",
  NOT_ACTIVE: "EXPIRY_CAPABILITY_NOT_ACTIVE",
  ACTION_MISMATCH: "ACTION_CAPABILITY_MISMATCH",
} as const;

const MAX_CAPABILITY_BYTES = 131_072;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/;
const ID_PATTERN =
  /^cap_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const ALLOWED_FIELDS = new Set([
  "artifactVersion",
  "capabilityId",
  "actionHash",
  "principalId",
  "agentId",
  "authority",
  "tool",
  "operation",
  "resource",
  "constraintsHash",
  "expiresAt",
  "nonce",
  "policyId",
  "delegationChainHash",
  "decision",
  "reasonCode",
  "issuerId",
  "issuerPublicKey",
  "issuerPublicKeyId",
  "issuedAt",
  "algorithm",
  "signature",
]);

type CapabilityBody = Omit<ActionCapabilityV1, "signature">;

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
  if (Buffer.byteLength(canonical, "utf8") > MAX_CAPABILITY_BYTES) {
    throw new TypeError("action capability exceeds the 131072 byte limit");
  }
  return JSON.parse(canonical) as unknown;
}

export function hashActionConstraints(constraints: JsonObject): string {
  return sha256Hex(
    `besa:action-constraints:v1\0${canonicalize(constraints)}`,
  );
}

export function validateActionCapability(
  value: unknown,
): ActionCapabilityValidationResult {
  let candidate: unknown;
  try {
    candidate = canonicalCopy(value);
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : "invalid action capability"],
    };
  }

  if (!isObject(candidate)) {
    return { ok: false, errors: ["action capability must be an object"] };
  }

  const errors: string[] = [];
  for (const field of Object.keys(candidate)) {
    if (!ALLOWED_FIELDS.has(field)) {
      errors.push(`unexpected action capability field '${field}'`);
    }
  }

  if (candidate.artifactVersion !== 1) errors.push("artifactVersion must be 1");
  if (typeof candidate.capabilityId !== "string" || !ID_PATTERN.test(candidate.capabilityId)) {
    errors.push("capabilityId must be a cap_ UUID");
  }

  for (const field of ["actionHash", "constraintsHash"] as const) {
    if (typeof candidate[field] !== "string" || !HASH_PATTERN.test(candidate[field])) {
      errors.push(`${field} must be 64 lowercase hexadecimal characters`);
    }
  }

  for (const field of ["principalId", "agentId", "authority", "policyId", "issuerId"] as const) {
    if (!isBoundedText(candidate[field], 512)) {
      errors.push(`${field} must be bounded NFC text without controls`);
    }
  }

  for (const field of ["tool", "operation"] as const) {
    if (typeof candidate[field] !== "string" || !NAME_PATTERN.test(candidate[field])) {
      errors.push(`${field} must be a stable machine-readable name`);
    }
  }

  if (!isBoundedText(candidate.resource, 2_048)) {
    errors.push("resource must be bounded NFC text without controls");
  }
  if (typeof candidate.nonce !== "string" || !NONCE_PATTERN.test(candidate.nonce)) {
    errors.push("nonce must be 16-128 base64url characters");
  }
  if (!isCanonicalTimestamp(candidate.issuedAt)) {
    errors.push("issuedAt must be a canonical UTC timestamp");
  }
  if (!isCanonicalTimestamp(candidate.expiresAt)) {
    errors.push("expiresAt must be a canonical UTC timestamp");
  }
  if (
    isCanonicalTimestamp(candidate.issuedAt) &&
    isCanonicalTimestamp(candidate.expiresAt) &&
    Date.parse(candidate.issuedAt) >= Date.parse(candidate.expiresAt)
  ) {
    errors.push("issuedAt must be before expiresAt");
  }

  if (
    candidate.delegationChainHash !== null &&
    (typeof candidate.delegationChainHash !== "string" ||
      !HASH_PATTERN.test(candidate.delegationChainHash))
  ) {
    errors.push("delegationChainHash must be null or a SHA-256 hash");
  }
  if (candidate.decision !== "allow" && candidate.decision !== "deny") {
    errors.push("decision must be allow or deny");
  }
  if (typeof candidate.reasonCode !== "string" || !REASON_PATTERN.test(candidate.reasonCode)) {
    errors.push("reasonCode must be a stable uppercase machine-readable code");
  }
  if (candidate.decision === "allow" && candidate.reasonCode !== "ACTION_ALLOWED") {
    errors.push("allow capabilities must carry reasonCode ACTION_ALLOWED");
  }
  if (candidate.decision === "deny" && candidate.reasonCode === "ACTION_ALLOWED") {
    errors.push("deny capabilities must not carry reasonCode ACTION_ALLOWED");
  }

  if (
    typeof candidate.issuerPublicKey !== "string" ||
    typeof candidate.issuerPublicKeyId !== "string"
  ) {
    errors.push("issuer public key fields must be strings");
  } else {
    try {
      publicKeyFromDer(candidate.issuerPublicKey);
      if (publicKeyId(candidate.issuerPublicKey) !== candidate.issuerPublicKeyId) {
        errors.push("issuerPublicKeyId does not match issuerPublicKey");
      }
    } catch {
      errors.push("issuerPublicKey must be a canonical Ed25519 public key");
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
    capability: candidate as unknown as ActionCapabilityV1,
    errors: [],
  };
}

export function createActionCapability(
  input: CreateActionCapabilityInput,
  issuerKeyPair: KeyPair,
): ActionCapabilityV1 {
  if (!validateKeyPair(issuerKeyPair)) {
    throw new TypeError("invalid or mismatched capability issuer key pair");
  }
  const actionValidation = validateActionEnvelope(input.action);
  if (!actionValidation.ok || !actionValidation.action) {
    throw new TypeError(`Invalid action envelope: ${actionValidation.errors.join("; ")}`);
  }
  const action = actionValidation.action;
  const body: CapabilityBody = {
    artifactVersion: 1,
    capabilityId: input.capabilityId ?? `cap_${randomUUID()}`,
    actionHash: hashActionEnvelope(action),
    principalId: action.principalId,
    agentId: action.agentId,
    authority: action.authority,
    tool: action.tool,
    operation: action.operation,
    resource: action.resource,
    constraintsHash: hashActionConstraints(action.constraints),
    expiresAt: action.expiresAt,
    nonce: action.nonce,
    policyId: input.policyId,
    delegationChainHash: input.delegationChainHash,
    decision: input.decision,
    reasonCode: input.reasonCode,
    issuerId: input.issuerId,
    issuerPublicKey: issuerKeyPair.publicKeyDer,
    issuerPublicKeyId: publicKeyId(issuerKeyPair.publicKeyDer),
    issuedAt: input.issuedAt,
    algorithm: "ed25519",
  };
  const capability: ActionCapabilityV1 = {
    ...body,
    signature: signWithKeyPair(
      signatureMessage("action-capability", body),
      issuerKeyPair,
    ).toString("base64"),
  };
  const validation = validateActionCapability(capability);
  if (!validation.ok || !validation.capability) {
    throw new TypeError(`Invalid action capability: ${validation.errors.join("; ")}`);
  }
  return validation.capability;
}

export function hashActionCapability(value: ActionCapabilityV1): string {
  const validation = validateActionCapability(value);
  if (!validation.ok || !validation.capability) {
    throw new TypeError(`Invalid action capability: ${validation.errors.join("; ")}`);
  }
  return sha256Hex(
    `besa:action-capability-artifact:v1\0${canonicalize(validation.capability)}`,
  );
}

export function verifyActionCapability(
  value: unknown,
  actionValue: unknown,
  trustStore: TrustStore,
  at = new Date(),
): ActionCapabilityVerificationResult {
  const validation = validateActionCapability(value);
  if (!validation.ok || !validation.capability) {
    return {
      valid: false,
      authorized: false,
      reasonCode: CAPABILITY_REASON.INVALID,
      detail: validation.errors.join("; "),
    };
  }
  const capability = validation.capability;
  const { signature, ...body } = capability;

  try {
    if (
      !ed25519Verify(
        null,
        signatureMessage("action-capability", body),
        publicKeyFromDer(capability.issuerPublicKey),
        Buffer.from(signature, "base64"),
      )
    ) {
      return {
        valid: false,
        authorized: false,
        reasonCode: CAPABILITY_REASON.SIGNATURE_INVALID,
        detail: "action capability signature is invalid",
      };
    }
  } catch {
    return {
      valid: false,
      authorized: false,
      reasonCode: CAPABILITY_REASON.SIGNATURE_INVALID,
      detail: "action capability signature verification failed",
    };
  }

  const trust = checkTrustedKey(
    trustStore,
    capability.issuerPublicKey,
    capability.issuedAt,
    "verify",
    at,
  );
  if (!trust.valid) {
    return {
      valid: false,
      authorized: false,
      reasonCode: CAPABILITY_REASON.ISSUER_UNTRUSTED,
      detail: `capability issuer is not trusted: ${trust.reasonCode}`,
    };
  }

  const time = at.getTime();
  if (
    !Number.isFinite(time) ||
    Date.parse(capability.issuedAt) > time ||
    Date.parse(capability.expiresAt) <= time
  ) {
    return {
      valid: false,
      authorized: false,
      reasonCode: CAPABILITY_REASON.NOT_ACTIVE,
      detail: "action capability is not active at the verification time",
    };
  }

  const actionCheck = checkActionEnvelope(actionValue, at);
  if (!actionCheck.valid || !actionCheck.action || !actionCheck.actionHash) {
    return {
      valid: false,
      authorized: false,
      reasonCode: CAPABILITY_REASON.ACTION_MISMATCH,
      detail: `action envelope is not executable: ${actionCheck.reasonCode}`,
    };
  }
  const action = actionCheck.action;
  if (
    capability.actionHash !== actionCheck.actionHash ||
    capability.principalId !== action.principalId ||
    capability.agentId !== action.agentId ||
    capability.authority !== action.authority ||
    capability.tool !== action.tool ||
    capability.operation !== action.operation ||
    capability.resource !== action.resource ||
    capability.constraintsHash !== hashActionConstraints(action.constraints) ||
    capability.expiresAt !== action.expiresAt ||
    capability.nonce !== action.nonce
  ) {
    return {
      valid: false,
      authorized: false,
      reasonCode: CAPABILITY_REASON.ACTION_MISMATCH,
      detail: "action capability does not bind the supplied exact action",
    };
  }

  return {
    valid: true,
    authorized: capability.decision === "allow",
    reasonCode: CAPABILITY_REASON.VALID,
    detail:
      capability.decision === "allow"
        ? "action capability is valid and authorizes execution"
        : `action capability is valid and denies execution: ${capability.reasonCode}`,
    capability,
  };
}
