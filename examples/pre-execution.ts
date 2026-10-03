import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  addTrustAnchor, admitPreExecution, BesaAdmissionError, canonicalize, createDelegation,
  emptyTrustStore, generateKeyPair, hashActionPolicy, hashRequest, InMemoryReplayStore,
  normalizeAccessTokenAuthority, normalizeDelegationAuthority, normalizeWorkloadAuthority,
  verifyPreExecutionAdmission, withPreExecutionAdmission,
  type ActionPolicyV1, type AuthorityNormalizerOptions, type PreExecutionAdmissionInput,
  type PreExecutionAdmissionReceiptV1, type PreExecutionRequestV1, type PreExecutionRuntimeConfig,
  type VerifiedAccessTokenClaims, type VerifiedWorkloadClaims,
} from "@dorigjo/besa";

// The application's IdP/JWKS verifier must check signature, token type, issuer,
// audience, validity, revocation and the authenticated actor before returning claims.
export async function executeEnterpriseAction<TResult>(
  accessToken: string, request: PreExecutionRequestV1,
  normalizer: AuthorityNormalizerOptions & {
    profile: "oauth" | "mcp-ema";
    verify(token: string, at: Date): Promise<VerifiedAccessTokenClaims>;
  },
  runtime: PreExecutionRuntimeConfig,
  execute: (input: PreExecutionAdmissionInput) => TResult | Promise<TResult>,
): Promise<TResult> {
  const intent = JSON.parse(canonicalize(request)) as PreExecutionRequestV1;
  const authority = await normalizeAccessTokenAuthority(accessToken, normalizer);
  return (await withPreExecutionAdmission(runtime, execute)({ request: intent, authority })).result;
}

// Workload identity requires an operator-defined authorization mapping as well
// as an authenticated JWT-SVID or mTLS session; an identity grants nothing alone.
export async function executeWorkloadAction<TResult>(
  proof: string | Uint8Array, request: PreExecutionRequestV1,
  normalizer: AuthorityNormalizerOptions & {
    principalId: string;
    spiffeId: string;
    verify(proof: string | Uint8Array, at: Date): Promise<VerifiedWorkloadClaims>;
  },
  runtime: PreExecutionRuntimeConfig,
  execute: (input: PreExecutionAdmissionInput) => TResult | Promise<TResult>,
): Promise<TResult> {
  const intent = JSON.parse(canonicalize(request)) as PreExecutionRequestV1;
  const authority = await normalizeWorkloadAuthority(proof, normalizer);
  return (await withPreExecutionAdmission(runtime, execute)({ request: intent, authority })).result;
}

export async function runAdmissionExample(): Promise<{
  denied: boolean; reasonCode: string; deniedToolCalls: number;
  denialReceiptVerified: boolean; allowedToolCalls: number;
}> {
  const now = new Date();
  const before = new Date(now.getTime() - 60_000).toISOString();
  const expiresAt = new Date(now.getTime() + 300_000).toISOString();
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const normalizerKey = generateKeyPair();
  const admissionKey = generateKeyPair();
  const recorderKey = generateKeyPair();
  const authorityTrustStore = addTrustAnchor(emptyTrustStore(), normalizerKey.publicKeyDer, before);
  const delegationTrustStore = addTrustAnchor(emptyTrustStore(), principal.publicKeyDer, before);
  const trustStore = addTrustAnchor(addTrustAnchor(emptyTrustStore(), admissionKey.publicKeyDer, before),
    recorderKey.publicKeyDer, before);
  const policy: ActionPolicyV1 = { version: 1, policyId: "ci-staging-release-v1", delegationRequired: true,
    rules: [{ ruleId: "staging-release", principals: ["principal:platform"], agents: ["agent:release"],
      tools: ["deployment.release"], operations: ["deploy"], resources: ["environment:staging"],
      allowedScopes: ["deployment:write"], maxRisk: "high",
      constraints: { exact: { environment: "staging" }, maximums: {} } }] };
  const parameters = { commit: "abc123", environment: "staging" };
  const context = { channel: "ci", pipeline: "release" };
  const request: PreExecutionRequestV1 = {
    requestVersion: 1, parameters, context, audience: "https://tools.example/release",
    requestedAt: now.toISOString(), policy: { id: policy.policyId, version: 1, hash: hashActionPolicy(policy) },
    action: { artifactVersion: 1, principalId: "principal:platform", agentId: "agent:release",
      authority: "authority:platform", tool: "deployment.release", operation: "deploy",
      resource: "environment:staging", requestHash: hashRequest(parameters), scopes: ["deployment:write"],
      constraints: { ...parameters }, expiresAt, nonce: "example_0123456789abcdef", riskClass: "high",
      contextHash: hashRequest(context) },
  };
  const chain = [createDelegation({ issuerId: request.action.principalId, subjectId: request.action.agentId,
    subjectPublicKey: agent.publicKeyDer, allowedOperations: ["deploy"],
    allowedResources: ["environment:staging"], scopes: ["deployment:write"],
    constraints: { exact: { environment: "staging" }, maximums: {} },
    issuedAt: before, notBefore: before, expiresAt, parentDelegationHash: null }, principal)];
  const authority = normalizeDelegationAuthority(chain, request.action, {
    issuer: request.action.authority, audience: request.audience, normalizerId: "normalizer:platform",
    keyPair: normalizerKey, trustStore: delegationTrustStore, clock: () => now,
    authenticatedAgentId: "agent:release",
  });
  const config = { policy, audience: request.audience, trustStore, authorityTrustStore,
    delegationTrustStore, issuerId: "besa:admission", keyPair: admissionKey };
  const receipts: PreExecutionAdmissionReceiptV1[] = [];
  let toolCalls = 0;
  const guarded = withPreExecutionAdmission({
    ...config, resolveAdmission: (input) => admitPreExecution(input, config, new Date()),
    replayStore: new InMemoryReplayStore(), admissionSink: { async append(receipt) { receipts.push(receipt); } },
    evidenceKeyPair: recorderKey, evidenceSink: { async append() {} },
    recorderId: "recorder:platform", executorId: "executor:release",
  }, (input) => {
    // In a real deployment the gateway/tool performs its side effect here using
    // only these verified fields, never a mutable original request or prompt.
    toolCalls++;
    return { operation: input.request.action.operation, resource: input.request.action.resource,
      commit: input.request.parameters.commit };
  });
  const injected = JSON.parse(canonicalize(request)) as PreExecutionRequestV1;
  injected.action.operation = "delete";
  injected.action.resource = "database:production-db";
  const malicious: PreExecutionAdmissionInput = { request: injected, authority, delegationChain: chain };
  let reasonCode = "";
  try { await guarded(malicious); } catch (error) {
    if (!(error instanceof BesaAdmissionError)) throw error;
    reasonCode = error.reasonCode;
  }
  const deniedToolCalls = toolCalls;
  const denialReceiptVerified = verifyPreExecutionAdmission(receipts[0], malicious, config, new Date()).valid;
  if (!denialReceiptVerified || deniedToolCalls !== 0 || !reasonCode) throw new Error("denial boundary failed");
  await guarded({ request, authority, delegationChain: chain });
  return { denied: true, reasonCode, deniedToolCalls, denialReceiptVerified, allowedToolCalls: toolCalls };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(await runAdmissionExample())}\n`);
}
