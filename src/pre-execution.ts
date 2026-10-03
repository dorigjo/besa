import { randomUUID, verify as ed25519Verify } from "node:crypto";
import {
  canonicalize, publicKeyFromDer, publicKeyId, sha256Hex,
  signatureMessage, signWithKeyPair, type KeyPair,
} from "./crypto.js";
import { checkActionEnvelope, hashActionEnvelope, validateActionEnvelope,
  type ActionEnvelopeV1, type JsonObject } from "./action.js";
import { admitAction, validateActionPolicy, type ActionPolicyV1 } from "./action-policy.js";
import { createActionCapability, validateActionCapability, verifyActionCapability,
  type ActionCapabilityV1 } from "./action-capability.js";
import { verifyActionDelegation, type DelegationV1 } from "./delegation.js";
import { hashExternalAuthority, validateExternalAuthority, verifyExternalAuthority } from "./external-authority.js";
import { hashRequest } from "./signing.js";
import { snapshotJson } from "./snapshot.js";
import { checkTrustedKey } from "./trust.js";
import type { Decision, TrustStore } from "./types.js";

export interface PreExecutionRequestV1 {
  requestVersion: 1;
  action: ActionEnvelopeV1;
  parameters: JsonObject;
  context: JsonObject;
  audience: string;
  policy: { id: string; version: number; hash: string };
  requestedAt: string;
}

export interface PreExecutionAdmissionInput {
  request: PreExecutionRequestV1;
  authority: unknown;
  delegationChain?: DelegationV1[];
}

export interface PreExecutionAdmissionReceiptV1 {
  artifactVersion: 1;
  receiptId: string;
  requestDigest: string;
  actionHash: string;
  principalId: string;
  agentId: string;
  audience: string;
  authorityHash: string | null;
  assertionDigest: string | null;
  delegationChainHash: string | null;
  policyId: string;
  policyVersion: 1;
  policyHash: string;
  decision: Decision;
  reasonCode: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  issuerId: string;
  issuerPublicKey: string;
  issuerPublicKeyId: string;
  algorithm: "ed25519";
  capability: ActionCapabilityV1 | null;
  signature: string;
}

export interface PreExecutionVerificationConfig {
  policy: ActionPolicyV1;
  audience: string;
  trustStore: TrustStore;
  authorityTrustStore: TrustStore;
  delegationTrustStore?: TrustStore;
}

export interface PreExecutionAdmissionConfig extends PreExecutionVerificationConfig {
  issuerId: string;
  keyPair: KeyPair;
}

const HASH = /^[a-f0-9]{64}$/;
const RECEIPT_FIELDS = new Set([
  "artifactVersion", "receiptId", "requestDigest", "actionHash", "principalId", "agentId",
  "audience", "authorityHash", "assertionDigest", "delegationChainHash", "policyId",
  "policyVersion", "policyHash", "decision", "reasonCode", "issuedAt", "expiresAt", "nonce",
  "issuerId", "issuerPublicKey", "issuerPublicKeyId", "algorithm", "capability", "signature",
]);

function isText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512 &&
    value === value.trim() && value === value.normalize("NFC") &&
    !/[\u0000-\u001f\u007f]/.test(value);
}

function isTime(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validatePreExecutionRequest(value: unknown): {
  ok: boolean; request?: PreExecutionRequestV1; reasonCode: string;
} {
  try {
    const encoded = canonicalize(value);
    if (Buffer.byteLength(encoded) > 262_144) throw new TypeError("request too large");
    const request = JSON.parse(encoded) as PreExecutionRequestV1;
    if (!object(request) || Object.keys(request).length !== 7 ||
        Object.keys(request).some((key) => ![
          "requestVersion", "action", "parameters", "context", "audience", "policy", "requestedAt",
        ].includes(key))) {
      throw new TypeError("request fields invalid");
    }
    const action = validateActionEnvelope(request.action);
    if (request.requestVersion !== 1 || !action.ok || !action.action ||
        !object(request.parameters) || !object(request.context) || !isText(request.audience) ||
        !isTime(request.requestedAt) || !object(request.policy) ||
        Object.keys(request.policy).length !== 3 ||
        Object.keys(request.policy).some((key) => !["id", "version", "hash"].includes(key)) ||
        !isText(request.policy.id) || !Number.isSafeInteger(request.policy.version) ||
        request.policy.version < 1 || typeof request.policy.hash !== "string" ||
        !HASH.test(request.policy.hash)) throw new TypeError("request invalid");
    return { ok: true, request, reasonCode: "PRE_EXECUTION_REQUEST_VALID" };
  } catch {
    return { ok: false, reasonCode: "SCHEMA_PRE_EXECUTION_REQUEST_INVALID" };
  }
}

export function hashActionPolicy(policy: ActionPolicyV1): string {
  const check = validateActionPolicy(policy);
  if (!check.ok || !check.policy) throw new TypeError("SCHEMA_POLICY_INVALID");
  return sha256Hex(`besa:action-policy:v1\0${canonicalize(check.policy)}`);
}

export function hashPreExecutionRequest(value: PreExecutionRequestV1): string {
  const check = validatePreExecutionRequest(value);
  if (!check.ok || !check.request) throw new TypeError(check.reasonCode);
  return sha256Hex(`besa:pre-execution-request:v1\0${canonicalize(check.request)}`);
}

function evaluate(
  input: PreExecutionAdmissionInput, config: PreExecutionVerificationConfig, at: Date,
  purpose: "admit" | "verify" = "admit",
): { decision: Decision; reasonCode: string; chainHash: string | null } {
  const deny = (reasonCode: string) => ({ decision: "deny" as const, reasonCode, chainHash: null });
  const { request } = input;
  const action = request.action;
  const actionCheck = checkActionEnvelope(action, at);
  if (!actionCheck.valid) return deny(actionCheck.reasonCode);
  if (request.audience !== config.audience) return deny("AUTHORITY_AUDIENCE_MISMATCH");
  if (Date.parse(request.requestedAt) > at.getTime()) return deny("ADMISSION_REQUEST_TIME_INVALID");
  if (hashRequest(request.parameters) !== action.requestHash ||
      hashRequest(request.context) !== action.contextHash ||
      Object.entries(action.constraints).some(([key, value]) =>
        !Object.hasOwn(request.parameters, key) ||
        canonicalize(request.parameters[key]) !== canonicalize(value))) {
    return deny("ACTION_REQUEST_MISMATCH");
  }
  if (request.policy.version !== 1) return deny("POLICY_VERSION_UNKNOWN");
  if (request.policy.id !== config.policy.policyId || request.policy.hash !== hashActionPolicy(config.policy)) {
    return deny("POLICY_DIGEST_MISMATCH");
  }
  const authority = verifyExternalAuthority(input.authority, action, request.audience,
    config.authorityTrustStore, at, purpose);
  if (!authority.valid || !authority.authority) return deny(authority.reasonCode);
  const chain = input.delegationChain;
  let chainHash: string | null = null;
  if (chain !== undefined && (!Array.isArray(chain) || chain.length === 0)) {
    return deny("SCHEMA_DELEGATION_INVALID");
  }
  if (chain) {
    const verified = verifyActionDelegation(chain, action,
      config.delegationTrustStore ?? config.authorityTrustStore, at);
    if (!verified.valid || !verified.chainHash) return deny(verified.reasonCode);
    chainHash = verified.chainHash;
  }
  if ((config.policy.delegationRequired || authority.authority.delegationChainHash !== null) &&
      chainHash === null) return deny("DELEGATION_REQUIRED");
  if (authority.authority.delegationChainHash !== null &&
      authority.authority.delegationChainHash !== chainHash) return deny("DELEGATION_PARENT_MISMATCH");
  const policy = admitAction(action, config.policy, at);
  return { decision: policy.decision, reasonCode: policy.reasonCode, chainHash };
}

export function admitPreExecution(
  inputValue: PreExecutionAdmissionInput, config: PreExecutionAdmissionConfig, at: Date,
): PreExecutionAdmissionReceiptV1 {
  const input = snapshotJson(inputValue);
  const requestCheck = validatePreExecutionRequest(input.request);
  if (!requestCheck.ok || !requestCheck.request) throw new TypeError(requestCheck.reasonCode);
  if (!Number.isFinite(at.getTime())) throw new TypeError("RUNTIME_CLOCK_INVALID");
  if (!checkTrustedKey(config.trustStore, config.keyPair.publicKeyDer,
    at.toISOString(), "admit", at).valid) throw new TypeError("TRUST_ADMISSION_ISSUER_UNTRUSTED");
  const request = requestCheck.request;
  const outcome = evaluate({ ...input, request }, config, at);
  const authority = validateExternalAuthority(input.authority).authority;
  const capability = outcome.decision === "allow" ? createActionCapability({
    action: request.action, policyId: config.policy.policyId,
    delegationChainHash: outcome.chainHash, decision: "allow", reasonCode: "ACTION_ALLOWED",
    issuerId: config.issuerId, issuedAt: at.toISOString(),
  }, config.keyPair) : null;
  const body: Omit<PreExecutionAdmissionReceiptV1, "signature"> = {
    artifactVersion: 1, receiptId: `adm_${randomUUID()}`,
    requestDigest: hashPreExecutionRequest(request), actionHash: hashActionEnvelope(request.action),
    principalId: request.action.principalId, agentId: request.action.agentId, audience: request.audience,
    authorityHash: authority ? hashExternalAuthority(authority) : null,
    assertionDigest: authority?.assertionDigest ?? null, delegationChainHash: outcome.chainHash,
    policyId: config.policy.policyId, policyVersion: 1, policyHash: hashActionPolicy(config.policy),
    decision: outcome.decision, reasonCode: outcome.reasonCode, issuedAt: at.toISOString(),
    expiresAt: request.action.expiresAt, nonce: request.action.nonce,
    issuerId: config.issuerId, issuerPublicKey: config.keyPair.publicKeyDer,
    issuerPublicKeyId: publicKeyId(config.keyPair.publicKeyDer), algorithm: "ed25519", capability,
  };
  const receipt = { ...body, signature: signWithKeyPair(
    signatureMessage("pre-execution-admission", body), config.keyPair).toString("base64") };
  const check = validatePreExecutionReceipt(receipt);
  if (!check.ok || !check.receipt) throw new TypeError(check.reasonCode);
  return check.receipt;
}

export function validatePreExecutionReceipt(value: unknown): {
  ok: boolean; receipt?: PreExecutionAdmissionReceiptV1; reasonCode: string;
} {
  try {
    const encoded = canonicalize(value);
    if (Buffer.byteLength(encoded) > 262_144) throw new TypeError("receipt too large");
    const r = JSON.parse(encoded) as PreExecutionAdmissionReceiptV1;
    if (!object(r) || Object.keys(r).length !== RECEIPT_FIELDS.size ||
        Object.keys(r).some((key) => !RECEIPT_FIELDS.has(key)) || r.artifactVersion !== 1 ||
        !/^adm_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.receiptId) ||
        ![r.requestDigest, r.actionHash, r.policyHash].every((hash) => typeof hash === "string" && HASH.test(hash)) ||
        ![r.authorityHash, r.assertionDigest, r.delegationChainHash].every((hash) =>
          hash === null || (typeof hash === "string" && HASH.test(hash))) ||
        ![r.principalId, r.agentId, r.audience, r.policyId, r.issuerId].every(isText) ||
        r.policyVersion !== 1 || !isTime(r.issuedAt) || !isTime(r.expiresAt) ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(r.nonce) ||
        !/^[A-Z][A-Z0-9_]{0,127}$/.test(r.reasonCode) ||
        (r.decision !== "allow" && r.decision !== "deny") ||
        (r.decision === "allow" && (r.reasonCode !== "ACTION_ALLOWED" ||
          r.authorityHash === null || r.assertionDigest === null ||
          !validateActionCapability(r.capability).ok || Date.parse(r.issuedAt) >= Date.parse(r.expiresAt))) ||
        (r.decision === "deny" && (r.capability !== null || r.reasonCode === "ACTION_ALLOWED")) ||
        r.algorithm !== "ed25519" || typeof r.signature !== "string" ||
        Buffer.from(r.signature, "base64").length !== 64 ||
        Buffer.from(r.signature, "base64").toString("base64") !== r.signature ||
        publicKeyId(r.issuerPublicKey) !== r.issuerPublicKeyId) throw new TypeError("receipt invalid");
    publicKeyFromDer(r.issuerPublicKey);
    return { ok: true, receipt: r, reasonCode: "ADMISSION_RECEIPT_VALID" };
  } catch {
    return { ok: false, reasonCode: "SCHEMA_ADMISSION_RECEIPT_INVALID" };
  }
}

export function hashPreExecutionReceipt(value: PreExecutionAdmissionReceiptV1): string {
  const check = validatePreExecutionReceipt(value);
  if (!check.ok || !check.receipt) throw new TypeError(check.reasonCode);
  return sha256Hex(`besa:pre-execution-receipt-artifact:v1\0${canonicalize(check.receipt)}`);
}

export function verifyPreExecutionAdmission(
  value: unknown, input: PreExecutionAdmissionInput, config: PreExecutionVerificationConfig,
  at: Date, mode: "execute" | "audit" = "execute",
): { valid: boolean; authorized: boolean; reasonCode: string; receipt?: PreExecutionAdmissionReceiptV1 } {
  const fail = (reasonCode: string) => ({ valid: false, authorized: false, reasonCode });
  try {
    const check = validatePreExecutionReceipt(value);
    if (!check.ok || !check.receipt) return fail(check.reasonCode);
    const r = check.receipt;
    const { signature, ...body } = r;
    if (!ed25519Verify(null, signatureMessage("pre-execution-admission", body),
      publicKeyFromDer(r.issuerPublicKey), Buffer.from(signature, "base64"))) {
      return fail("SIGNATURE_ADMISSION_RECEIPT_INVALID");
    }
    if ((mode !== "execute" && mode !== "audit") || !Number.isFinite(at.getTime()) ||
        Date.parse(r.issuedAt) > at.getTime()) return fail("ADMISSION_TIME_INVALID");
    if (!checkTrustedKey(config.trustStore, r.issuerPublicKey, r.issuedAt,
      mode === "execute" ? "admit" : "verify", at).valid) return fail("TRUST_ADMISSION_ISSUER_UNTRUSTED");
    const requestCheck = validatePreExecutionRequest(input.request);
    if (!requestCheck.ok || !requestCheck.request) return fail(requestCheck.reasonCode);
    const request = requestCheck.request;
    const authority = validateExternalAuthority(input.authority).authority;
    if (r.requestDigest !== hashPreExecutionRequest(request) ||
        r.actionHash !== hashActionEnvelope(request.action) ||
        r.principalId !== request.action.principalId || r.agentId !== request.action.agentId ||
        r.nonce !== request.action.nonce || r.expiresAt !== request.action.expiresAt ||
        r.audience !== request.audience || r.audience !== config.audience ||
        r.authorityHash !== (authority ? hashExternalAuthority(authority) : null) ||
        r.assertionDigest !== (authority?.assertionDigest ?? null)) return fail("ADMISSION_REQUEST_MISMATCH");
    if (r.policyId !== config.policy.policyId || r.policyVersion !== 1 ||
        r.policyHash !== hashActionPolicy(config.policy)) return fail("POLICY_DIGEST_MISMATCH");
    if (r.decision === "allow") {
      const admissionOutcome = evaluate(input, config, new Date(r.issuedAt), "verify");
      if (admissionOutcome.decision !== "allow") return fail(admissionOutcome.reasonCode);
      const time = mode === "audit" ? new Date(r.issuedAt) : at;
      const outcome = evaluate(input, config, time, mode === "audit" ? "verify" : "admit");
      if (outcome.decision !== "allow") return fail(outcome.reasonCode);
      if (outcome.chainHash !== r.delegationChainHash || !r.capability ||
          r.capability.issuerId !== r.issuerId || r.capability.issuerPublicKey !== r.issuerPublicKey ||
          r.capability.issuedAt !== r.issuedAt || r.capability.policyId !== r.policyId ||
          r.capability.delegationChainHash !== r.delegationChainHash) return fail("ADMISSION_REQUEST_MISMATCH");
      const capability = verifyActionCapability(r.capability, request.action, config.trustStore, time);
      if (!capability.valid || !capability.authorized) return fail(capability.reasonCode);
    }
    return { valid: true, authorized: mode === "execute" && r.decision === "allow",
      reasonCode: "ADMISSION_RECEIPT_VALID", receipt: r };
  } catch {
    return fail("ADMISSION_VERIFIER_ERROR");
  }
}
