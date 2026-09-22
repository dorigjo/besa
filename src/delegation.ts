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
import { checkTrustedKey } from "./trust.js";
import {
  checkActionEnvelope,
  type ActionEnvelopeV1,
  type JsonObject,
  type JsonValue,
} from "./action.js";
import type { TrustStore } from "./types.js";

export interface DelegationConstraintsV1 {
  exact: JsonObject;
  maximums: Record<string, number>;
}

export interface DelegationV1 {
  artifactVersion: 1;
  delegationId: string;
  issuerId: string;
  issuerPublicKey: string;
  issuerPublicKeyId: string;
  subjectId: string;
  subjectPublicKey: string;
  subjectPublicKeyId: string;
  allowedOperations: string[];
  allowedResources: string[];
  scopes: string[];
  constraints: DelegationConstraintsV1;
  issuedAt: string;
  notBefore: string;
  expiresAt: string;
  parentDelegationHash: string | null;
  algorithm: "ed25519";
  signature: string;
}

export interface CreateDelegationInput {
  delegationId?: string;
  issuerId: string;
  subjectId: string;
  subjectPublicKey: string;
  allowedOperations: string[];
  allowedResources: string[];
  scopes: string[];
  constraints: DelegationConstraintsV1;
  issuedAt: string;
  notBefore: string;
  expiresAt: string;
  parentDelegationHash: string | null;
}

export interface DelegationValidationResult {
  ok: boolean;
  delegation?: DelegationV1;
  errors: string[];
}

export interface DelegationVerificationResult {
  valid: boolean;
  reasonCode: string;
  detail: string;
  leaf?: DelegationV1;
  chainHash?: string;
}

export const DELEGATION_REASON = {
  VALID: "DELEGATION_VALID",
  EMPTY: "DELEGATION_EMPTY_CHAIN",
  INVALID: "SCHEMA_DELEGATION_INVALID",
  SIGNATURE_INVALID: "SIGNATURE_DELEGATION_INVALID",
  ROOT_UNTRUSTED: "TRUST_DELEGATION_ROOT_UNTRUSTED",
  NOT_ACTIVE: "EXPIRY_DELEGATION_NOT_ACTIVE",
  PARENT_MISMATCH: "DELEGATION_PARENT_MISMATCH",
  WIDENING: "DELEGATION_WIDENING",
  ACTION_NOT_GRANTED: "DELEGATION_ACTION_NOT_GRANTED",
} as const;

const MAX_DELEGATION_BYTES = 131_072;
const MAX_DELEGATION_CHAIN_LENGTH = 64;
const MAX_LIST_ENTRIES = 128;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const ID_PATTERN =
  /^dlg_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const ALLOWED_FIELDS = new Set([
  "artifactVersion",
  "delegationId",
  "issuerId",
  "issuerPublicKey",
  "issuerPublicKeyId",
  "subjectId",
  "subjectPublicKey",
  "subjectPublicKeyId",
  "allowedOperations",
  "allowedResources",
  "scopes",
  "constraints",
  "issuedAt",
  "notBefore",
  "expiresAt",
  "parentDelegationHash",
  "algorithm",
  "signature",
]);

type DelegationBody = Omit<DelegationV1, "signature">;

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
  if (Buffer.byteLength(canonical, "utf8") > MAX_DELEGATION_BYTES) {
    throw new TypeError("delegation exceeds the 131072 byte limit");
  }
  return JSON.parse(canonical) as unknown;
}

function validateSortedList(
  value: unknown,
  field: string,
  pattern: RegExp | null,
  errors: string[],
): void {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_LIST_ENTRIES) {
    errors.push(`${field} must contain 1-${String(MAX_LIST_ENTRIES)} entries`);
    return;
  }

  if (
    !value.every(
      (entry) =>
        isBoundedText(entry, 2_048) && (pattern === null || pattern.test(entry)),
    )
  ) {
    errors.push(`${field} contains an invalid entry`);
  }

  if (new Set(value).size !== value.length) {
    errors.push(`${field} must not contain duplicates`);
  }

  const sorted = [...value].sort();
  if (value.some((entry, index) => entry !== sorted[index])) {
    errors.push(`${field} must be sorted lexicographically`);
  }
}

function validateJsonText(value: JsonValue, path: string, errors: string[]): void {
  if (typeof value === "string") {
    if (!isBoundedText(value, 16_384)) {
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
      if (!isBoundedText(key, 256)) errors.push(`${path} contains an invalid key`);
      validateJsonText(item, `${path}.${key.slice(0, 64)}`, errors);
    }
  }
}

function validateConstraints(value: unknown, errors: string[]): void {
  if (!isObject(value)) {
    errors.push("constraints must be an object");
    return;
  }

  for (const field of Object.keys(value)) {
    if (field !== "exact" && field !== "maximums") {
      errors.push(`unexpected constraints field '${field}'`);
    }
  }

  if (!isObject(value.exact)) {
    errors.push("constraints.exact must be an object");
  } else {
    validateJsonText(value.exact as JsonObject, "constraints.exact", errors);
  }

  if (!isObject(value.maximums)) {
    errors.push("constraints.maximums must be an object");
  } else {
    for (const [key, maximum] of Object.entries(value.maximums)) {
      if (!isBoundedText(key, 256)) {
        errors.push("constraints.maximums contains an invalid key");
      }
      if (typeof maximum !== "number" || !Number.isFinite(maximum) || maximum < 0) {
        errors.push(`constraints.maximums.${key.slice(0, 64)} must be non-negative`);
      }
    }
  }
}

export function validateDelegation(value: unknown): DelegationValidationResult {
  let candidate: unknown;

  try {
    candidate = canonicalCopy(value);
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : "invalid delegation"],
    };
  }

  if (!isObject(candidate)) {
    return { ok: false, errors: ["delegation must be an object"] };
  }

  const errors: string[] = [];
  for (const field of Object.keys(candidate)) {
    if (!ALLOWED_FIELDS.has(field)) errors.push(`unexpected delegation field '${field}'`);
  }

  if (candidate.artifactVersion !== 1) errors.push("artifactVersion must be 1");
  if (typeof candidate.delegationId !== "string" || !ID_PATTERN.test(candidate.delegationId)) {
    errors.push("delegationId must be a dlg_ UUID");
  }

  for (const field of ["issuerId", "subjectId"] as const) {
    if (!isBoundedText(candidate[field], 512)) {
      errors.push(`${field} must be bounded NFC text without controls`);
    }
  }

  for (const prefix of ["issuer", "subject"] as const) {
    const keyField = `${prefix}PublicKey` as const;
    const idField = `${prefix}PublicKeyId` as const;
    if (typeof candidate[keyField] !== "string" || typeof candidate[idField] !== "string") {
      errors.push(`${prefix} public key fields must be strings`);
      continue;
    }
    try {
      publicKeyFromDer(candidate[keyField]);
      if (publicKeyId(candidate[keyField]) !== candidate[idField]) {
        errors.push(`${idField} does not match ${keyField}`);
      }
    } catch {
      errors.push(`${keyField} must be a canonical Ed25519 public key`);
    }
  }

  validateSortedList(candidate.allowedOperations, "allowedOperations", NAME_PATTERN, errors);
  validateSortedList(candidate.allowedResources, "allowedResources", null, errors);
  validateSortedList(candidate.scopes, "scopes", null, errors);
  validateConstraints(candidate.constraints, errors);

  for (const field of ["issuedAt", "notBefore", "expiresAt"] as const) {
    if (!isCanonicalTimestamp(candidate[field])) {
      errors.push(`${field} must be a canonical UTC timestamp`);
    }
  }

  if (
    isCanonicalTimestamp(candidate.issuedAt) &&
    isCanonicalTimestamp(candidate.notBefore) &&
    isCanonicalTimestamp(candidate.expiresAt) &&
    (Date.parse(candidate.issuedAt) > Date.parse(candidate.expiresAt) ||
      Date.parse(candidate.notBefore) >= Date.parse(candidate.expiresAt))
  ) {
    errors.push("delegation timestamps do not form a valid interval");
  }

  if (
    candidate.parentDelegationHash !== null &&
    (typeof candidate.parentDelegationHash !== "string" ||
      !HASH_PATTERN.test(candidate.parentDelegationHash))
  ) {
    errors.push("parentDelegationHash must be null or a SHA-256 hash");
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
    delegation: candidate as unknown as DelegationV1,
    errors: [],
  };
}

export function createDelegation(
  input: CreateDelegationInput,
  issuerKeyPair: KeyPair,
): DelegationV1 {
  if (!validateKeyPair(issuerKeyPair)) {
    throw new TypeError("invalid or mismatched issuer Ed25519 key pair");
  }

  let subjectPublicKeyId: string;
  try {
    publicKeyFromDer(input.subjectPublicKey);
    subjectPublicKeyId = publicKeyId(input.subjectPublicKey);
  } catch {
    throw new TypeError("subjectPublicKey must be a canonical Ed25519 public key");
  }

  const body: DelegationBody = {
    artifactVersion: 1,
    delegationId: input.delegationId ?? `dlg_${randomUUID()}`,
    issuerId: input.issuerId,
    issuerPublicKey: issuerKeyPair.publicKeyDer,
    issuerPublicKeyId: publicKeyId(issuerKeyPair.publicKeyDer),
    subjectId: input.subjectId,
    subjectPublicKey: input.subjectPublicKey,
    subjectPublicKeyId,
    allowedOperations: [...input.allowedOperations],
    allowedResources: [...input.allowedResources],
    scopes: [...input.scopes],
    constraints: input.constraints,
    issuedAt: input.issuedAt,
    notBefore: input.notBefore,
    expiresAt: input.expiresAt,
    parentDelegationHash: input.parentDelegationHash,
    algorithm: "ed25519",
  };
  const delegation: DelegationV1 = {
    ...body,
    signature: signWithKeyPair(
      signatureMessage("delegation", body),
      issuerKeyPair,
    ).toString("base64"),
  };
  const validation = validateDelegation(delegation);
  if (!validation.ok || !validation.delegation) {
    throw new TypeError(`Invalid delegation: ${validation.errors.join("; ")}`);
  }
  return validation.delegation;
}

export function hashDelegation(value: DelegationV1): string {
  const validation = validateDelegation(value);
  if (!validation.ok || !validation.delegation) {
    throw new TypeError(`Invalid delegation: ${validation.errors.join("; ")}`);
  }
  return sha256Hex(
    `besa:delegation-artifact:v1\0${canonicalize(validation.delegation)}`,
  );
}

function verifyOne(
  value: unknown,
  now: Date,
): DelegationVerificationResult & { delegation?: DelegationV1 } {
  const validation = validateDelegation(value);
  if (!validation.ok || !validation.delegation) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.INVALID,
      detail: validation.errors.join("; "),
    };
  }
  const delegation = validation.delegation;
  const { signature, ...body } = delegation;

  try {
    const validSignature = ed25519Verify(
      null,
      signatureMessage("delegation", body),
      publicKeyFromDer(delegation.issuerPublicKey),
      Buffer.from(signature, "base64"),
    );
    if (!validSignature) {
      return {
        valid: false,
        reasonCode: DELEGATION_REASON.SIGNATURE_INVALID,
        detail: "delegation signature is invalid",
      };
    }
  } catch {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.SIGNATURE_INVALID,
      detail: "delegation signature verification failed",
    };
  }

  const nowMs = now.getTime();
  if (
    !Number.isFinite(nowMs) ||
    Date.parse(delegation.notBefore) > nowMs ||
    Date.parse(delegation.expiresAt) <= nowMs
  ) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.NOT_ACTIVE,
      detail: "delegation is not active at the verification time",
    };
  }

  return {
    valid: true,
    reasonCode: DELEGATION_REASON.VALID,
    detail: "delegation is valid",
    delegation,
  };
}

function isSubset(child: string[], parent: string[]): boolean {
  const parentValues = new Set(parent);
  return child.every((value) => parentValues.has(value));
}

function constraintsNarrow(parent: DelegationV1, child: DelegationV1): boolean {
  const parentExact = parent.constraints.exact;
  const childExact = child.constraints.exact;
  for (const [key, value] of Object.entries(parentExact)) {
    if (!(key in childExact) || canonicalize(childExact[key]) !== canonicalize(value)) {
      return false;
    }
  }

  for (const [key, maximum] of Object.entries(parent.constraints.maximums)) {
    const childMaximum = child.constraints.maximums[key];
    if (typeof childMaximum !== "number" || childMaximum > maximum) return false;
  }
  return true;
}

function isNarrower(parent: DelegationV1, child: DelegationV1): boolean {
  return (
    isSubset(child.allowedOperations, parent.allowedOperations) &&
    isSubset(child.allowedResources, parent.allowedResources) &&
    isSubset(child.scopes, parent.scopes) &&
    constraintsNarrow(parent, child) &&
    Date.parse(child.notBefore) >= Date.parse(parent.notBefore) &&
    Date.parse(child.expiresAt) <= Date.parse(parent.expiresAt)
  );
}

export function verifyDelegationChain(
  values: unknown[],
  trustStore: TrustStore,
  now = new Date(),
): DelegationVerificationResult {
  if (!Array.isArray(values) || values.length > MAX_DELEGATION_CHAIN_LENGTH) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.INVALID,
      detail: `delegation chain must contain at most ${String(MAX_DELEGATION_CHAIN_LENGTH)} entries`,
    };
  }
  if (values.length === 0) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.EMPTY,
      detail: "delegation chain must not be empty",
    };
  }

  const chain: DelegationV1[] = [];
  for (const value of values) {
    const verification = verifyOne(value, now);
    if (!verification.valid || !verification.delegation) return verification;
    chain.push(verification.delegation);
  }

  const root = chain[0]!;
  const trust = checkTrustedKey(
    trustStore,
    root.issuerPublicKey,
    root.issuedAt,
    "verify",
    now,
  );
  if (!trust.valid) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.ROOT_UNTRUSTED,
      detail: `delegation root is not trusted: ${trust.reasonCode}`,
    };
  }
  if (root.parentDelegationHash !== null) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.PARENT_MISMATCH,
      detail: "root delegation must not reference a parent",
    };
  }

  for (let index = 1; index < chain.length; index += 1) {
    const parent = chain[index - 1]!;
    const child = chain[index]!;
    if (
      child.parentDelegationHash !== hashDelegation(parent) ||
      child.issuerId !== parent.subjectId ||
      child.issuerPublicKey !== parent.subjectPublicKey ||
      child.issuerPublicKeyId !== parent.subjectPublicKeyId
    ) {
      return {
        valid: false,
        reasonCode: DELEGATION_REASON.PARENT_MISMATCH,
        detail: "child delegation does not match its signed parent authority",
      };
    }
    if (!isNarrower(parent, child)) {
      return {
        valid: false,
        reasonCode: DELEGATION_REASON.WIDENING,
        detail: "child delegation broadens its parent authority",
      };
    }
  }

  const leaf = chain[chain.length - 1]!;
  return {
    valid: true,
    reasonCode: DELEGATION_REASON.VALID,
    detail: "delegation chain is valid and narrowed",
    leaf,
    chainHash: sha256Hex(
      `besa:delegation-chain:v1\0${canonicalize(chain.map(hashDelegation))}`,
    ),
  };
}

export function verifyActionDelegation(
  values: unknown[],
  actionValue: ActionEnvelopeV1,
  trustStore: TrustStore,
  now = new Date(),
): DelegationVerificationResult {
  const chainResult = verifyDelegationChain(values, trustStore, now);
  if (!chainResult.valid || !chainResult.leaf || !chainResult.chainHash) {
    return chainResult;
  }

  const actionCheck = checkActionEnvelope(actionValue, now);
  if (!actionCheck.valid || !actionCheck.action) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.ACTION_NOT_GRANTED,
      detail: `delegation cannot authorize an invalid action: ${actionCheck.reasonCode}`,
    };
  }

  const action = actionCheck.action;
  const rootValidation = validateDelegation(values[0]);
  if (!rootValidation.ok || !rootValidation.delegation) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.ACTION_NOT_GRANTED,
      detail: "delegation root is unavailable",
    };
  }
  const root = rootValidation.delegation;
  const leaf = chainResult.leaf;
  const exactMatches = Object.entries(leaf.constraints.exact).every(
    ([key, expected]) =>
      key in action.constraints &&
      canonicalize(action.constraints[key]) === canonicalize(expected),
  );
  const maximumsMatch = Object.entries(leaf.constraints.maximums).every(
    ([key, maximum]) =>
      typeof action.constraints[key] === "number" &&
      action.constraints[key] <= maximum,
  );

  if (
    root.issuerId !== action.principalId ||
    leaf.subjectId !== action.agentId ||
    !leaf.allowedOperations.includes(action.operation) ||
    !leaf.allowedResources.includes(action.resource) ||
    !action.scopes.every((scope) => leaf.scopes.includes(scope)) ||
    !exactMatches ||
    !maximumsMatch ||
    Date.parse(action.expiresAt) > Date.parse(leaf.expiresAt)
  ) {
    return {
      valid: false,
      reasonCode: DELEGATION_REASON.ACTION_NOT_GRANTED,
      detail: "delegation chain does not authorize the exact supplied action",
    };
  }

  return chainResult;
}
