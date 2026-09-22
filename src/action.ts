import { canonicalize, sha256Hex } from "./crypto.js";
import type { RiskLevel } from "./types.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface ActionEnvelopeV1 {
  artifactVersion: 1;
  principalId: string;
  agentId: string;
  authority: string;
  tool: string;
  operation: string;
  resource: string;
  requestHash: string;
  scopes: string[];
  constraints: JsonObject;
  expiresAt: string;
  nonce: string;
  riskClass: RiskLevel;
  contextHash?: string;
}

export interface ActionEnvelopeValidationResult {
  ok: boolean;
  action?: ActionEnvelopeV1;
  errors: string[];
}

export interface ActionEnvelopeCheckResult {
  valid: boolean;
  reasonCode: string;
  detail: string;
  action?: ActionEnvelopeV1;
  actionHash?: string;
}

export const ACTION_REASON = {
  VALID: "ACTION_VALID",
  INVALID: "SCHEMA_ACTION_INVALID",
  EXPIRED: "EXPIRY_ACTION_EXPIRED",
} as const;

const MAX_ACTION_BYTES = 65_536;
const MAX_CONSTRAINT_STRING_LENGTH = 16_384;
const MAX_CONSTRAINT_KEY_LENGTH = 256;
const MAX_SCOPES = 64;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const ALLOWED_FIELDS = new Set([
  "artifactVersion",
  "principalId",
  "agentId",
  "authority",
  "tool",
  "operation",
  "resource",
  "requestHash",
  "scopes",
  "constraints",
  "expiresAt",
  "nonce",
  "riskClass",
  "contextHash",
]);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
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

function validateJsonText(
  value: JsonValue,
  path: string,
  errors: string[],
): void {
  if (typeof value === "string") {
    if (!isBoundedText(value, MAX_CONSTRAINT_STRING_LENGTH)) {
      errors.push(`${path} must contain bounded NFC text without controls`);
    }
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      validateJsonText(item, `${path}[${String(index)}]`, errors),
    );
    return;
  }

  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (!isBoundedText(key, MAX_CONSTRAINT_KEY_LENGTH)) {
        errors.push(`${path} contains an invalid key`);
      }
      validateJsonText(item, `${path}.${key.slice(0, 64)}`, errors);
    }
  }
}

function canonicalCopy(value: unknown): unknown {
  const canonical = canonicalize(value);
  if (Buffer.byteLength(canonical, "utf8") > MAX_ACTION_BYTES) {
    throw new TypeError("action envelope exceeds the 65536 byte limit");
  }
  return JSON.parse(canonical) as unknown;
}

export function validateActionEnvelope(
  value: unknown,
): ActionEnvelopeValidationResult {
  let candidate: unknown;

  try {
    candidate = canonicalCopy(value);
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : "invalid action envelope"],
    };
  }

  if (!isObject(candidate)) {
    return { ok: false, errors: ["action envelope must be an object"] };
  }

  const errors: string[] = [];

  for (const field of Object.keys(candidate)) {
    if (!ALLOWED_FIELDS.has(field)) {
      errors.push(`unexpected action envelope field '${field}'`);
    }
  }

  if (candidate.artifactVersion !== 1) {
    errors.push("artifactVersion must be 1");
  }

  for (const field of ["principalId", "agentId", "authority"] as const) {
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

  if (typeof candidate.requestHash !== "string" || !HASH_PATTERN.test(candidate.requestHash)) {
    errors.push("requestHash must be 64 lowercase hexadecimal characters");
  }

  if (!Array.isArray(candidate.scopes) || candidate.scopes.length > MAX_SCOPES) {
    errors.push("scopes must be an array with at most 64 entries");
  } else {
    const scopes = candidate.scopes;
    if (!scopes.every((scope) => isBoundedText(scope, 256))) {
      errors.push("scopes must contain bounded NFC strings");
    }
    if (new Set(scopes).size !== scopes.length) {
      errors.push("scopes must not contain duplicates");
    }
    const sorted = [...scopes].sort();
    if (scopes.some((scope, index) => scope !== sorted[index])) {
      errors.push("scopes must be sorted lexicographically");
    }
  }

  if (!isObject(candidate.constraints)) {
    errors.push("constraints must be an object");
  } else {
    validateJsonText(candidate.constraints as JsonObject, "constraints", errors);
  }

  if (!isCanonicalTimestamp(candidate.expiresAt)) {
    errors.push("expiresAt must be a canonical UTC timestamp");
  }

  if (typeof candidate.nonce !== "string" || !NONCE_PATTERN.test(candidate.nonce)) {
    errors.push("nonce must be 16-128 base64url characters");
  }

  if (!(["low", "medium", "high"] as unknown[]).includes(candidate.riskClass)) {
    errors.push("riskClass must be low, medium, or high");
  }

  if (
    candidate.contextHash !== undefined &&
    (typeof candidate.contextHash !== "string" || !HASH_PATTERN.test(candidate.contextHash))
  ) {
    errors.push("contextHash must be 64 lowercase hexadecimal characters");
  }

  if (errors.length > 0) return { ok: false, errors };

  return {
    ok: true,
    action: candidate as unknown as ActionEnvelopeV1,
    errors: [],
  };
}

export function hashActionEnvelope(value: ActionEnvelopeV1): string {
  const validation = validateActionEnvelope(value);
  if (!validation.ok || !validation.action) {
    throw new TypeError(`Invalid action envelope: ${validation.errors.join("; ")}`);
  }

  return sha256Hex(
    `besa:action-envelope:v1\0${canonicalize(validation.action)}`,
  );
}

export function checkActionEnvelope(
  value: unknown,
  now = new Date(),
): ActionEnvelopeCheckResult {
  const validation = validateActionEnvelope(value);
  if (!validation.ok || !validation.action) {
    return {
      valid: false,
      reasonCode: ACTION_REASON.INVALID,
      detail: validation.errors.join("; "),
    };
  }

  if (!Number.isFinite(now.getTime())) {
    return {
      valid: false,
      reasonCode: ACTION_REASON.INVALID,
      detail: "verification time must be valid",
    };
  }

  if (Date.parse(validation.action.expiresAt) <= now.getTime()) {
    return {
      valid: false,
      reasonCode: ACTION_REASON.EXPIRED,
      detail: "action envelope has expired",
      action: validation.action,
    };
  }

  return {
    valid: true,
    reasonCode: ACTION_REASON.VALID,
    detail: "action envelope is valid",
    action: validation.action,
    actionHash: hashActionEnvelope(validation.action),
  };
}
