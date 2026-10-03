import { createExternalAuthority, hashAuthorityAssertion,
  type ExternalAuthorityClaimsV1, type ExternalAuthorityV1 } from "./external-authority.js";
import { verifyActionDelegation, type DelegationV1, type DelegationConstraintsV1 } from "./delegation.js";
import { snapshotJson } from "./snapshot.js";
import type { ActionEnvelopeV1 } from "./action.js";
import type { KeyPair } from "./crypto.js";
import type { TrustStore } from "./types.js";

export interface VerifiedAccessTokenClaims {
  tokenUse: "access-token";
  issuer: string;
  principalId: string;
  agentId: string;
  audience: string[];
  scopes: string[];
  notBefore: string;
  expiresAt: string;
}

export interface VerifiedWorkloadClaims {
  tokenUse: "workload-identity";
  issuer: string;
  spiffeId: string;
  audience: string[];
  notBefore: string;
  expiresAt: string;
}

export interface AuthorityGrantMapping {
  tools: string[];
  operations: string[];
  resources: string[];
  scopes: string[];
  constraints: DelegationConstraintsV1;
}

export interface AuthorityNormalizerOptions {
  issuer: string;
  audience: string;
  grant: AuthorityGrantMapping;
  normalizerId: string;
  keyPair: KeyPair;
  clock: () => Date;
}

function checkedTime(clock: () => Date): Date {
  const at = clock();
  if (!(at instanceof Date) || !Number.isFinite(at.getTime())) {
    throw new TypeError("RUNTIME_CLOCK_INVALID");
  }
  return new Date(at);
}

function active(notBefore: string, expiresAt: string, at: Date): boolean {
  return Number.isFinite(Date.parse(notBefore)) && Number.isFinite(Date.parse(expiresAt)) &&
    Date.parse(notBefore) <= at.getTime() && Date.parse(expiresAt) > at.getTime();
}

export async function normalizeAccessTokenAuthority(
  assertion: string,
  options: AuthorityNormalizerOptions & {
    profile: "oauth" | "mcp-ema";
    verify(assertion: string, at: Date): Promise<VerifiedAccessTokenClaims>;
  },
): Promise<ExternalAuthorityV1> {
  const at = checkedTime(options.clock);
  const grant = snapshotJson(options.grant);
  const assertionDigest = hashAuthorityAssertion(assertion);
  let claims: VerifiedAccessTokenClaims;
  try {
    claims = snapshotJson(await options.verify(assertion, at));
  } catch {
    throw new TypeError("AUTHORITY_ASSERTION_VERIFICATION_FAILED");
  }
  const issuedAt = checkedTime(options.clock);
  if (!claims || claims.tokenUse !== "access-token") throw new TypeError("AUTHORITY_TOKEN_USE_INVALID");
  if (claims.issuer !== options.issuer) throw new TypeError("AUTHORITY_ISSUER_MISMATCH");
  if (!Array.isArray(claims.audience) || !claims.audience.includes(options.audience)) {
    throw new TypeError("AUTHORITY_AUDIENCE_MISMATCH");
  }
  if (!Array.isArray(claims.scopes) || !grant.scopes.every((scope) => claims.scopes.includes(scope))) {
    throw new TypeError("AUTHORITY_SCOPE_NOT_GRANTED");
  }
  if (!active(claims.notBefore, claims.expiresAt, issuedAt)) {
    throw new TypeError("EXPIRY_AUTHORITY_NOT_ACTIVE");
  }
  if (options.profile !== "oauth" && options.profile !== "mcp-ema") {
    throw new TypeError("AUTHORITY_MECHANISM_UNSUPPORTED");
  }
  return createExternalAuthority({
    artifactVersion: 1, mechanism: options.profile === "mcp-ema" ? "mcp-ema-access-token" : "oauth-access-token",
    principalId: claims.principalId, agentId: claims.agentId, issuer: claims.issuer,
    audience: options.audience, ...grant, notBefore: claims.notBefore, expiresAt: claims.expiresAt,
    assertionDigest, delegationChainHash: null,
  }, { id: options.normalizerId, keyPair: options.keyPair, issuedAt: issuedAt.toISOString() });
}

export async function normalizeWorkloadAuthority(
  assertion: string | Uint8Array,
  options: AuthorityNormalizerOptions & {
    principalId: string;
    spiffeId: string;
    verify(assertion: string | Uint8Array, at: Date): Promise<VerifiedWorkloadClaims>;
  },
): Promise<ExternalAuthorityV1> {
  const at = checkedTime(options.clock);
  const proof = typeof assertion === "string" ? assertion : new Uint8Array(assertion);
  const grant = snapshotJson(options.grant);
  const assertionDigest = hashAuthorityAssertion(proof);
  let claims: VerifiedWorkloadClaims;
  try {
    claims = snapshotJson(await options.verify(proof, at));
  } catch {
    throw new TypeError("AUTHORITY_ASSERTION_VERIFICATION_FAILED");
  }
  const issuedAt = checkedTime(options.clock);
  if (!claims || claims.tokenUse !== "workload-identity" || typeof claims.spiffeId !== "string") {
    throw new TypeError("AUTHORITY_TOKEN_USE_INVALID");
  }
  const id = new URL(claims.spiffeId);
  if (id.protocol !== "spiffe:" || !id.host || id.username || id.password || id.port ||
      id.search || id.hash || id.href !== claims.spiffeId) throw new TypeError("AUTHORITY_IDENTITY_INVALID");
  if (claims.spiffeId !== options.spiffeId) throw new TypeError("AUTHORITY_IDENTITY_MISMATCH");
  if (claims.issuer !== options.issuer) throw new TypeError("AUTHORITY_ISSUER_MISMATCH");
  if (!Array.isArray(claims.audience) || !claims.audience.includes(options.audience)) {
    throw new TypeError("AUTHORITY_AUDIENCE_MISMATCH");
  }
  if (!active(claims.notBefore, claims.expiresAt, issuedAt)) throw new TypeError("EXPIRY_AUTHORITY_NOT_ACTIVE");
  return createExternalAuthority({
    artifactVersion: 1, mechanism: "workload-identity", principalId: options.principalId,
    agentId: claims.spiffeId, issuer: claims.issuer, audience: options.audience, ...grant,
    notBefore: claims.notBefore, expiresAt: claims.expiresAt, assertionDigest, delegationChainHash: null,
  }, { id: options.normalizerId, keyPair: options.keyPair, issuedAt: issuedAt.toISOString() });
}

export function normalizeDelegationAuthority(
  chain: DelegationV1[], action: ActionEnvelopeV1,
  options: Omit<AuthorityNormalizerOptions, "grant"> & {
    trustStore: TrustStore;
    authenticatedAgentId: string;
  },
): ExternalAuthorityV1 {
  const at = checkedTime(options.clock);
  const verified = verifyActionDelegation(chain, action, options.trustStore, at);
  if (!verified.valid || !verified.leaf || !verified.chainHash) throw new TypeError(verified.reasonCode);
  const leaf = verified.leaf;
  // This value comes from host authentication, never from the requested action.
  if (options.authenticatedAgentId !== leaf.subjectId) throw new TypeError("AUTHORITY_IDENTITY_MISMATCH");
  const claims: ExternalAuthorityClaimsV1 = {
    artifactVersion: 1, mechanism: "besa-delegation", principalId: action.principalId,
    agentId: action.agentId, issuer: options.issuer, audience: options.audience,
    tools: [action.tool], operations: leaf.allowedOperations, resources: leaf.allowedResources,
    scopes: leaf.scopes, constraints: leaf.constraints, notBefore: leaf.notBefore,
    expiresAt: leaf.expiresAt, assertionDigest: verified.chainHash, delegationChainHash: verified.chainHash,
  };
  return createExternalAuthority(claims,
    { id: options.normalizerId, keyPair: options.keyPair, issuedAt: at.toISOString() });
}
