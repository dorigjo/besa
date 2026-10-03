import { verify as ed25519Verify } from "node:crypto";
import {
  canonicalize, publicKeyFromDer, publicKeyId, sha256Hex,
  signatureMessage, signWithKeyPair, type KeyPair,
} from "./crypto.js";
import { checkActionEnvelope, type ActionEnvelopeV1 } from "./action.js";
import { admitAction, validateActionPolicy, type ActionPolicyV1 } from "./action-policy.js";
import type { DelegationConstraintsV1 } from "./delegation.js";
import { checkTrustedKey } from "./trust.js";
import type { TrustStore } from "./types.js";

export type AuthorityMechanism =
  | "oauth-access-token" | "mcp-ema-access-token"
  | "workload-identity" | "besa-delegation";

export interface ExternalAuthorityClaimsV1 {
  artifactVersion: 1;
  mechanism: AuthorityMechanism;
  principalId: string;
  agentId: string;
  issuer: string;
  audience: string;
  tools: string[];
  operations: string[];
  resources: string[];
  scopes: string[];
  constraints: DelegationConstraintsV1;
  notBefore: string;
  expiresAt: string;
  assertionDigest: string;
  delegationChainHash: string | null;
}

// A trusted normalizer attests to upstream verification; this is not an IdP token.
export interface ExternalAuthorityV1 extends ExternalAuthorityClaimsV1 {
  normalizerId: string;
  publicKey: string;
  publicKeyId: string;
  issuedAt: string;
  algorithm: "ed25519";
  signature: string;
}

export const AUTHORITY_REASON = {
  VALID: "AUTHORITY_VALID",
  INVALID: "SCHEMA_AUTHORITY_INVALID",
  MECHANISM: "AUTHORITY_MECHANISM_UNSUPPORTED",
  SIGNATURE: "SIGNATURE_AUTHORITY_INVALID",
  UNTRUSTED: "TRUST_AUTHORITY_NORMALIZER_UNTRUSTED",
  EXPIRED: "EXPIRY_AUTHORITY_NOT_ACTIVE",
  AUDIENCE: "AUTHORITY_AUDIENCE_MISMATCH",
  IDENTITY: "AUTHORITY_IDENTITY_MISMATCH",
  NOT_GRANTED: "AUTHORITY_ACTION_NOT_GRANTED",
} as const;

const MECHANISMS = new Set<unknown>([
  "oauth-access-token", "mcp-ema-access-token", "workload-identity", "besa-delegation",
]);
const FIELDS = new Set([
  "artifactVersion", "mechanism", "principalId", "agentId", "issuer", "audience",
  "tools", "operations", "resources", "scopes", "constraints", "notBefore",
  "expiresAt", "assertionDigest", "delegationChainHash", "normalizerId",
  "publicKey", "publicKeyId", "issuedAt", "algorithm", "signature",
]);
const HASH = /^[a-f0-9]{64}$/;

function textId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512 &&
    value === value.trim() && value === value.normalize("NFC") &&
    !/[\u0000-\u001f\u007f]/.test(value);
}

function timestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

function authorityPolicy(authority: ExternalAuthorityClaimsV1): ActionPolicyV1 {
  return {
    version: 1, policyId: "external-authority", delegationRequired: false,
    rules: [{
      ruleId: "authority", principals: [authority.principalId], agents: [authority.agentId],
      tools: authority.tools, operations: authority.operations, resources: authority.resources,
      allowedScopes: authority.scopes, maxRisk: "high", constraints: authority.constraints,
    }],
  };
}

export function hashAuthorityAssertion(assertion: string | Uint8Array): string {
  if ((typeof assertion !== "string" && !(assertion instanceof Uint8Array)) ||
      Buffer.byteLength(assertion) === 0 || Buffer.byteLength(assertion) > 1_048_576) {
    throw new TypeError("assertion must contain 1-1048576 bytes");
  }
  return sha256Hex(Buffer.concat([
    Buffer.from("besa:authority-assertion:v1\0", "utf8"), Buffer.from(assertion),
  ]));
}

export function validateExternalAuthority(value: unknown): {
  ok: boolean; authority?: ExternalAuthorityV1; reasonCode: string;
} {
  try {
    const encoded = canonicalize(value);
    if (Buffer.byteLength(encoded) > 131_072) throw new TypeError("authority too large");
    const candidate = JSON.parse(encoded) as ExternalAuthorityV1;
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
        Object.keys(candidate).some((field) => !FIELDS.has(field))) {
      return { ok: false, reasonCode: AUTHORITY_REASON.INVALID };
    }
    if (!MECHANISMS.has(candidate.mechanism)) {
      return { ok: false, reasonCode: AUTHORITY_REASON.MECHANISM };
    }
    if (candidate.artifactVersion !== 1 ||
        ![candidate.principalId, candidate.agentId, candidate.issuer,
          candidate.audience, candidate.normalizerId].every(textId) ||
        ![candidate.notBefore, candidate.expiresAt, candidate.issuedAt].every(timestamp) ||
        Date.parse(candidate.notBefore) >= Date.parse(candidate.expiresAt) ||
        Date.parse(candidate.issuedAt) >= Date.parse(candidate.expiresAt) ||
        !HASH.test(candidate.assertionDigest) ||
        (candidate.delegationChainHash !== null && !HASH.test(candidate.delegationChainHash)) ||
        (candidate.mechanism === "besa-delegation" && candidate.delegationChainHash === null) ||
        !validateActionPolicy(authorityPolicy(candidate)).ok ||
        candidate.algorithm !== "ed25519" ||
        typeof candidate.signature !== "string" ||
        Buffer.from(candidate.signature, "base64").length !== 64 ||
        Buffer.from(candidate.signature, "base64").toString("base64") !== candidate.signature ||
        publicKeyId(candidate.publicKey) !== candidate.publicKeyId) {
      return { ok: false, reasonCode: AUTHORITY_REASON.INVALID };
    }
    publicKeyFromDer(candidate.publicKey);
    return { ok: true, authority: candidate, reasonCode: AUTHORITY_REASON.VALID };
  } catch {
    return { ok: false, reasonCode: AUTHORITY_REASON.INVALID };
  }
}

export function createExternalAuthority(
  claims: ExternalAuthorityClaimsV1,
  normalizer: { id: string; keyPair: KeyPair; issuedAt: string },
): ExternalAuthorityV1 {
  const body = {
    ...claims, normalizerId: normalizer.id, publicKey: normalizer.keyPair.publicKeyDer,
    publicKeyId: publicKeyId(normalizer.keyPair.publicKeyDer),
    issuedAt: normalizer.issuedAt, algorithm: "ed25519" as const,
  };
  const authority = {
    ...body,
    signature: signWithKeyPair(signatureMessage("external-authority", body), normalizer.keyPair)
      .toString("base64"),
  };
  const check = validateExternalAuthority(authority);
  if (!check.ok || !check.authority) throw new TypeError(check.reasonCode);
  return check.authority;
}

export function hashExternalAuthority(value: ExternalAuthorityV1): string {
  const check = validateExternalAuthority(value);
  if (!check.ok || !check.authority) throw new TypeError(check.reasonCode);
  return sha256Hex(`besa:external-authority-artifact:v1\0${canonicalize(check.authority)}`);
}

export function verifyExternalAuthority(
  value: unknown,
  actionValue: ActionEnvelopeV1,
  audience: string,
  trustStore: TrustStore,
  at: Date,
  purpose: "admit" | "verify" = "admit",
): { valid: boolean; reasonCode: string; authority?: ExternalAuthorityV1 } {
  const check = validateExternalAuthority(value);
  if (!check.ok || !check.authority) return { valid: false, reasonCode: check.reasonCode };
  const authority = check.authority;
  const fail = (reasonCode: string) => ({ valid: false, reasonCode });
  if (!(at instanceof Date) || !Number.isFinite(at.getTime())) return fail(AUTHORITY_REASON.EXPIRED);
  const actionCheck = checkActionEnvelope(actionValue, at);
  if (!actionCheck.valid || !actionCheck.action) return fail(AUTHORITY_REASON.NOT_GRANTED);
  const action = actionCheck.action;
  const { signature, ...body } = authority;
  try {
    if (!ed25519Verify(null, signatureMessage("external-authority", body),
      publicKeyFromDer(authority.publicKey), Buffer.from(signature, "base64"))) {
      return fail(AUTHORITY_REASON.SIGNATURE);
    }
    if (!checkTrustedKey(trustStore, authority.publicKey, authority.issuedAt, purpose, at).valid) {
      return fail(AUTHORITY_REASON.UNTRUSTED);
    }
  } catch {
    return fail(AUTHORITY_REASON.UNTRUSTED);
  }
  if (!Number.isFinite(at.getTime()) || Date.parse(authority.issuedAt) > at.getTime() ||
      Date.parse(authority.notBefore) > at.getTime() || Date.parse(authority.expiresAt) <= at.getTime() ||
      Date.parse(action.expiresAt) > Date.parse(authority.expiresAt)) {
    return fail(AUTHORITY_REASON.EXPIRED);
  }
  if (authority.audience !== audience) return fail(AUTHORITY_REASON.AUDIENCE);
  if (authority.principalId !== action.principalId || authority.agentId !== action.agentId ||
      authority.issuer !== action.authority) return fail(AUTHORITY_REASON.IDENTITY);
  if (admitAction(action, authorityPolicy(authority), at).decision !== "allow") {
    return fail(AUTHORITY_REASON.NOT_GRANTED);
  }
  return { valid: true, reasonCode: AUTHORITY_REASON.VALID, authority };
}
