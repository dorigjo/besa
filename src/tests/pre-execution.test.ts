import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import {
  addTrustAnchor, admitAction, admitPreExecution, applyKeyRotation, BesaAdmissionError, canonicalize,
  createDelegation, createExternalAuthority, createKeyRotation, emptyTrustStore, generateKeyPair,
  hashActionPolicy, hashAuthorityAssertion, hashDelegation, hashPreExecutionReceipt, hashRequest,
  InMemoryReplayStore, normalizeAccessTokenAuthority, normalizeDelegationAuthority,
  normalizeWorkloadAuthority, publicKeyId, revokeTrustAnchor, signatureMessage,
  signWithKeyPair, validateExternalAuthority, validatePreExecutionReceipt,
  verifyActionDelegation, verifyActionEvidence, verifyExternalAuthority, verifyPreExecutionAdmission,
  withBesaMcp, withPreExecutionAdmission,
  type ActionPolicyV1, type ExternalAuthorityClaimsV1, type ExternalAuthorityV1,
  type PreExecutionAdmissionConfig, type PreExecutionAdmissionInput,
  type PreExecutionAdmissionReceiptV1, type PreExecutionRuntimeConfig,
  type ReplayStore, type RuntimeEvidenceRecordV1, type VerifiedAccessTokenClaims,
} from "../sdk.js";

const NOW = new Date("2026-10-03T12:00:00.000Z");
const BEFORE = "2026-10-03T11:00:00.000Z";
const EXPIRY = "2026-10-03T12:05:00.000Z";
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

function fixture() {
  const issuer = generateKeyPair();
  const normalizer = generateKeyPair();
  const recorder = generateKeyPair();
  const trust = addTrustAnchor(addTrustAnchor(emptyTrustStore(), issuer.publicKeyDer, BEFORE),
    recorder.publicKeyDer, BEFORE);
  const authorityTrust = addTrustAnchor(emptyTrustStore(), normalizer.publicKeyDer, BEFORE);
  const policy: ActionPolicyV1 = {
    version: 1, policyId: "release-v1", delegationRequired: false,
    rules: [{ ruleId: "release", principals: ["principal:platform"], agents: ["agent:release"],
      tools: ["deployment.release"], operations: ["deploy"], resources: ["environment:staging"],
      allowedScopes: ["deployment:write"], maxRisk: "high",
      constraints: { exact: { environment: "staging" }, maximums: {} } }],
  };
  const claims: ExternalAuthorityClaimsV1 = {
    artifactVersion: 1, mechanism: "mcp-ema-access-token", issuer: "https://idp.example",
    audience: "https://mcp.example", principalId: "principal:platform", agentId: "agent:release",
    tools: ["deployment.release"], operations: ["delete", "deploy"],
    resources: ["database:production", "environment:staging"], scopes: ["deployment:write"],
    constraints: { exact: {}, maximums: {} }, notBefore: BEFORE,
    expiresAt: "2026-10-03T13:00:00.000Z", assertionDigest: hashAuthorityAssertion("sensitive-bearer-credential"),
    delegationChainHash: null,
  };
  const signAuthority = (changes: Partial<ExternalAuthorityClaimsV1> = {}): ExternalAuthorityV1 =>
    createExternalAuthority({ ...claims, ...changes },
      { id: "normalizer:enterprise", keyPair: normalizer, issuedAt: BEFORE });
  const parameters = { commit: "abc123", environment: "staging" };
  const context = { channel: "ci", workflow: "release" };
  const input: PreExecutionAdmissionInput = {
    request: { requestVersion: 1, parameters, context, audience: claims.audience,
      requestedAt: NOW.toISOString(), policy: { id: policy.policyId, version: 1, hash: hashActionPolicy(policy) },
      action: { artifactVersion: 1, principalId: claims.principalId, agentId: claims.agentId,
        authority: claims.issuer, tool: "deployment.release", operation: "deploy", resource: "environment:staging",
        requestHash: hashRequest(parameters), scopes: ["deployment:write"], constraints: copy(parameters),
        expiresAt: EXPIRY, nonce: "admission_0123456789abcdef", riskClass: "high", contextHash: hashRequest(context) } },
    authority: signAuthority(),
  };
  const admissionConfig: PreExecutionAdmissionConfig = {
    policy, audience: claims.audience, trustStore: trust, authorityTrustStore: authorityTrust,
    issuerId: "besa:admission", keyPair: issuer,
  };
  const receipts: PreExecutionAdmissionReceiptV1[] = [];
  const records: RuntimeEvidenceRecordV1[] = [];
  const runtime: PreExecutionRuntimeConfig = {
    ...admissionConfig, replayStore: new InMemoryReplayStore(), evidenceKeyPair: recorder,
    evidenceSink: { async append(record) { records.push(record); } },
    recorderId: "besa:recorder", executorId: "tool:deploy", clock: () => new Date(NOW),
    resolveAdmission: (request) => admitPreExecution(request, admissionConfig, NOW),
    admissionSink: { async append(receipt) { receipts.push(receipt); } },
  };
  return { input, claims, issuer, normalizer, recorder, policy, admissionConfig, runtime,
    signAuthority, receipts, records };
}

test("admission is signed and persisted before execution; independent evidence verifies", async () => {
  const f = fixture();
  let calls = 0;
  const run = withPreExecutionAdmission(f.runtime, (input) => {
    assert.equal(f.receipts.length, 1);
    assert.ok(Object.isFrozen(input.request.parameters));
    assert.ok(Object.isFrozen(input.request.context));
    assert.equal(verifyPreExecutionAdmission(f.receipts[0], input, f.admissionConfig, NOW).authorized, true);
    calls++;
    return { deployment: input.request.parameters.commit };
  });
  const result = await run(f.input);
  assert.equal(calls, 1);
  assert.equal(result.evidence.receiptHash, hashPreExecutionReceipt(result.receipt));
  assert.equal(verifyActionEvidence(result.evidence, {
    action: f.input.request.action, capability: result.capability, result: result.result,
    receiptHash: hashPreExecutionReceipt(result.receipt), trustStore: f.admissionConfig.trustStore,
  }, NOW).valid, true);
  const publicReceipt = canonicalize(result.receipt);
  assert.ok(!publicReceipt.includes("sensitive-bearer-credential"));
  assert.ok(!publicReceipt.includes('"privateKeyDer"'));
  const later = new Date("2026-10-03T14:00:00.000Z");
  assert.equal(verifyPreExecutionAdmission(result.receipt, f.input, f.admissionConfig, later).authorized, false);
  assert.equal(verifyPreExecutionAdmission(result.receipt, f.input, f.admissionConfig, later, "audit").valid, true);
  assert.equal(verifyPreExecutionAdmission(result.receipt, f.input, f.admissionConfig, later, "audit").authorized, false);
});

const attacks: Array<[string, string, (f: ReturnType<typeof fixture>) => void]> = [
  ["unauthorized agent", "AUTHORITY_IDENTITY_MISMATCH", (f) => { f.input.request.action.agentId = "agent:attacker"; }],
  ["substituted principal", "AUTHORITY_IDENTITY_MISMATCH", (f) => { f.input.request.action.principalId = "principal:attacker"; }],
  ["prompt-injected delete production-db", "ACTION_NOT_GRANTED", (f) => {
    f.input.request.action.operation = "delete"; f.input.request.action.resource = "database:production";
  }],
  ["wrong audience / server A assertion reused for B", "AUTHORITY_AUDIENCE_MISMATCH", (f) => {
    f.input.authority = f.signAuthority({ audience: "https://server-a.example" });
  }],
  ["wrong resource", "AUTHORITY_ACTION_NOT_GRANTED", (f) => { f.input.request.action.resource = "database:other"; }],
  ["expired authority", "EXPIRY_AUTHORITY_NOT_ACTIVE", (f) => {
    f.input.authority = f.signAuthority({ expiresAt: NOW.toISOString() });
  }],
  ["insufficient scopes", "AUTHORITY_ACTION_NOT_GRANTED", (f) => {
    f.input.authority = f.signAuthority({ scopes: ["deployment:read"] });
  }],
  ["altered scopes without resigning", "SIGNATURE_AUTHORITY_INVALID", (f) => {
    (f.input.authority as ExternalAuthorityV1).scopes = ["other:scope"];
  }],
  ["forged issuer", "SIGNATURE_AUTHORITY_INVALID", (f) => {
    (f.input.authority as ExternalAuthorityV1).issuer = "https://forged.example";
  }],
  ["untrusted normalizer", "TRUST_AUTHORITY_NORMALIZER_UNTRUSTED", (f) => {
    f.admissionConfig.authorityTrustStore = emptyTrustStore();
  }],
  ["revoked normalizer", "TRUST_AUTHORITY_NORMALIZER_UNTRUSTED", (f) => {
    f.admissionConfig.authorityTrustStore = revokeTrustAnchor(f.admissionConfig.authorityTrustStore,
      publicKeyId(f.normalizer.publicKeyDer), NOW.toISOString());
  }],
  ["parameters inconsistent with constraints", "ACTION_REQUEST_MISMATCH", (f) => {
    f.input.request.parameters.environment = "production";
    f.input.request.action.requestHash = hashRequest(f.input.request.parameters);
  }],
  ["altered context", "ACTION_REQUEST_MISMATCH", (f) => { f.input.request.context.channel = "other"; }],
  ["unknown policy version", "POLICY_VERSION_UNKNOWN", (f) => { f.input.request.policy.version = 2; }],
  ["modified policy digest", "POLICY_DIGEST_MISMATCH", (f) => { f.input.request.policy.hash = "a".repeat(64); }],
  ["expired action produces denial evidence", "EXPIRY_ACTION_EXPIRED", (f) => {
    f.input.request.action.expiresAt = NOW.toISOString();
  }],
  ["future request time", "ADMISSION_REQUEST_TIME_INVALID", (f) => {
    f.input.request.requestedAt = "2026-10-03T12:00:01.000Z";
  }],
  ["unknown authority mechanism / downgrade", "AUTHORITY_MECHANISM_UNSUPPORTED", (f) => {
    (f.input.authority as ExternalAuthorityV1).mechanism = "identity-only" as never;
  }],
  ["malformed external authority", "SCHEMA_AUTHORITY_INVALID", (f) => { f.input.authority = { validated: true }; }],
  ["token/receipt confusion", "SCHEMA_AUTHORITY_INVALID", (f) => {
    f.input.authority = admitPreExecution(f.input, f.admissionConfig, NOW);
  }],
];
for (const [name, reason, mutate] of attacks) {
  test(`pre-execution fail closed: ${name}`, async () => {
    const f = fixture();
    mutate(f);
    let calls = 0;
    const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
    assert.equal(receipt.decision, "deny");
    assert.equal(receipt.reasonCode, reason);
    // Runtime verifier uses the same operator trust configuration.
    f.runtime.authorityTrustStore = f.admissionConfig.authorityTrustStore;
    await assert.rejects(withPreExecutionAdmission(f.runtime, () => { calls++; return {}; })(f.input),
      (error: unknown) => error instanceof BesaAdmissionError && error.reasonCode === reason);
    assert.equal(calls, 0);
    assert.equal(f.receipts.length, 1);
    assert.equal(verifyPreExecutionAdmission(f.receipts[0], f.input, f.admissionConfig, NOW).valid, true);
  });
}

for (const field of ["agentId", "principalId", "operation", "resource", "tool", "nonce"] as const) {
  test(`ALLOW cannot be substituted onto another ${field}`, () => {
    const f = fixture();
    const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
    const other = copy(f.input);
    other.request.action[field] += "_other";
    assert.equal(verifyPreExecutionAdmission(receipt, other, f.admissionConfig, NOW).reasonCode,
      "ADMISSION_REQUEST_MISMATCH");
  });
}

test("altered parameters after ALLOW fail independent verification", () => {
  const f = fixture();
  const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
  f.input.request.parameters.commit = "malicious";
  assert.equal(verifyPreExecutionAdmission(receipt, f.input, f.admissionConfig, NOW).valid, false);
});

test("forged receipt, unsupported version and receipt/capability downgrade fail closed", async () => {
  const f = fixture();
  const original = admitPreExecution(f.input, f.admissionConfig, NOW);
  for (const altered of [
    { ...original, requestDigest: "a".repeat(64) },
    { ...original, artifactVersion: 2 },
    original.capability,
    { ...original, access_token: "secret" },
  ]) {
    let calls = 0;
    f.runtime.resolveAdmission = () => altered as PreExecutionAdmissionReceiptV1;
    await assert.rejects(withPreExecutionAdmission(f.runtime, () => { calls++; return {}; })(f.input));
    assert.equal(calls, 0);
  }
  assert.equal(f.receipts.length, 0);
});

test("replay and concurrent duplicate execution have exactly one winner", async () => {
  const f = fixture();
  let calls = 0;
  const run = withPreExecutionAdmission(f.runtime, () => { calls++; return {}; });
  const results = await Promise.allSettled([run(f.input), run(f.input), run(f.input)]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(calls, 1);
  await assert.rejects(run(f.input), /replay key has already been consumed/);
  assert.equal(calls, 1);
});

test("failed execution is never automatically retried and consumes its nonce", async () => {
  const f = fixture();
  let calls = 0;
  const run = withPreExecutionAdmission(f.runtime, () => { calls++; throw new Error("tool failed"); });
  await assert.rejects(run(f.input));
  await assert.rejects(run(f.input), /replay key has already been consumed/);
  assert.equal(calls, 1);
  assert.equal(f.records[0]?.evidence.outcome, "failed");
});

test("verifier unavailable and admission sink failure block execution", async () => {
  for (const phase of ["verifier", "sink"] as const) {
    const f = fixture();
    let calls = 0;
    if (phase === "verifier") f.runtime.resolveAdmission = async () => { throw new Error("network down"); };
    else f.runtime.admissionSink = { async append() { throw new Error("disk down"); } };
    await assert.rejects(withPreExecutionAdmission(f.runtime, () => { calls++; return {}; })(f.input),
      (error: unknown) => error instanceof BesaAdmissionError &&
        error.reasonCode === (phase === "verifier" ? "ADMISSION_VERIFIER_UNAVAILABLE" : "ADMISSION_RECORD_FAILED"));
    assert.equal(calls, 0);
  }
});

test("policy mutation or revocation during an await blocks execution", async () => {
  for (const threat of ["policy", "revocation", "expiry"] as const) {
    const f = fixture();
    let calls = 0;
    f.runtime.admissionSink = { async append(receipt) {
      f.receipts.push(receipt);
      if (threat === "policy") f.policy.rules[0]!.resources = ["environment:other"];
      else if (threat === "revocation") {
        f.runtime.authorityTrustStore = revokeTrustAnchor(f.runtime.authorityTrustStore,
          publicKeyId(f.normalizer.publicKeyDer), NOW.toISOString());
      } else f.runtime.clock = () => new Date(EXPIRY);
    } };
    // Use the same clock closure to make changes visible across all runtime checks.
    let current = new Date(NOW);
    if (threat === "expiry") {
      f.runtime.clock = () => new Date(current);
      f.runtime.admissionSink = { async append(receipt) { f.receipts.push(receipt); current = new Date(EXPIRY); } };
    }
    await assert.rejects(withPreExecutionAdmission(f.runtime, () => { calls++; return {}; })(f.input));
    assert.equal(calls, 0);
  }
});

test("async resolver and caller cannot mutate the admitted MCP invocation", async () => {
  const f = fixture();
  const call = { name: f.input.request.action.tool, arguments: copy(f.input.request.parameters) };
  const guarded = withBesaMcp({
    ...f.runtime, replayRequirement: "enforce",
    actionForCall: () => copy(f.input.request.action),
    capability: async (action) => {
      assert.ok(Object.isFrozen(action.constraints));
      assert.throws(() => { action.constraints.environment = "production"; });
      call.arguments.environment = "production";
      const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
      return receipt.capability!;
    },
  }, (actual) => {
    assert.ok(Object.isFrozen(actual.arguments));
    assert.equal((actual.arguments as { environment: string }).environment, "staging");
    return {};
  });
  await guarded(call);
});

test("canonical request / receipt fuzz parsing rejects ambiguity without executing getters", () => {
  const f = fixture();
  const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
  const reordered = Object.fromEntries(Object.entries(receipt).reverse());
  assert.equal(hashPreExecutionReceipt(reordered as PreExecutionAdmissionReceiptV1), hashPreExecutionReceipt(receipt));
  for (let i = 0; i < 100; i++) {
    const changed = { ...receipt, [`unknown_${i}`]: i % 2 === 0 ? null : ["extra"] };
    assert.equal(validatePreExecutionReceipt(changed).ok, false);
    assert.equal(verifyPreExecutionAdmission(changed, f.input, f.admissionConfig, NOW).valid, false);
  }
  for (const malformed of [null, [], 1, "token", {}, { artifactVersion: 2 }, { ...receipt, signature: "?" }]) {
    assert.equal(validatePreExecutionReceipt(malformed).ok, false);
  }
  let getterCalls = 0;
  const accessor = { ...receipt };
  Object.defineProperty(accessor, "signature", { enumerable: true, get() { getterCalls++; return receipt.signature; } });
  assert.equal(validatePreExecutionReceipt(accessor).ok, false);
  assert.equal(getterCalls, 0);
  const canonical = { ...receipt, reasonCode: Number.NaN };
  assert.equal(validatePreExecutionReceipt(canonical).ok, false);
});

test("enforced replay store unavailable or malformed fails closed", async () => {
  for (const response of [null, {}, { status: "consumed", enforced: false }]) {
    const f = fixture();
    let calls = 0;
    f.runtime.replayStore = { mode: "enforced", async consume() { return response as never; } } satisfies ReplayStore;
    await assert.rejects(withPreExecutionAdmission(f.runtime, () => { calls++; return {}; })(f.input));
    assert.equal(calls, 0);
  }
});

test("delegation-backed authority rejects expired, forged and revoked chains", async () => {
  const f = fixture();
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const rootTrust = addTrustAnchor(emptyTrustStore(), principal.publicKeyDer, BEFORE);
  const delegation = createDelegation({
    issuerId: f.input.request.action.principalId, subjectId: f.input.request.action.agentId,
    subjectPublicKey: agent.publicKeyDer, allowedOperations: ["deploy"],
    allowedResources: ["environment:staging"], scopes: ["deployment:write"],
    constraints: { exact: {}, maximums: {} }, issuedAt: BEFORE, notBefore: BEFORE,
    expiresAt: EXPIRY, parentDelegationHash: null,
  }, principal);
  f.input.delegationChain = [delegation];
  f.input.authority = normalizeDelegationAuthority([delegation], f.input.request.action, {
    issuer: f.claims.issuer, audience: f.claims.audience, normalizerId: "normalizer:enterprise",
    keyPair: f.normalizer, clock: () => new Date(NOW), trustStore: rootTrust,
    authenticatedAgentId: f.claims.agentId,
  });
  assert.throws(() => normalizeDelegationAuthority([delegation], f.input.request.action, {
    issuer: f.claims.issuer, audience: f.claims.audience, normalizerId: "normalizer:enterprise",
    keyPair: f.normalizer, clock: () => new Date(NOW), trustStore: rootTrust,
    authenticatedAgentId: "agent:other",
  }), /AUTHORITY_IDENTITY_MISMATCH/);
  f.admissionConfig.delegationTrustStore = rootTrust;
  assert.equal(admitPreExecution(f.input, f.admissionConfig, NOW).decision, "allow");
  const original = copy(f.input);
  for (const threat of ["expired", "future", "forged", "revoked", "revocation-field", "missing"] as const) {
    f.input = copy(original);
    f.admissionConfig.delegationTrustStore = rootTrust;
    if (threat === "expired") {
      f.input.delegationChain = [createDelegation({ ...delegation, expiresAt: NOW.toISOString() }, principal)];
    } else if (threat === "future") {
      f.input.delegationChain = [createDelegation({ ...delegation,
        issuedAt: "2026-10-03T12:00:30.000Z" }, principal)];
    } else if (threat === "forged") f.input.delegationChain![0]!.subjectId = "attacker";
    else if (threat === "revocation-field") Object.assign(f.input.delegationChain![0]!, { revoked: true });
    else if (threat === "missing") delete f.input.delegationChain;
    else f.admissionConfig.delegationTrustStore = revokeTrustAnchor(rootTrust,
      publicKeyId(principal.publicKeyDer), NOW.toISOString());
    assert.equal(admitPreExecution(f.input, f.admissionConfig, NOW).decision, "deny");
    f.runtime.delegationTrustStore = f.admissionConfig.delegationTrustStore;
    let calls = 0;
    await assert.rejects(withPreExecutionAdmission(f.runtime, () => { calls++; return {}; })(f.input));
    assert.equal(calls, 0);
  }
});

test("EMA adapter accepts verified access-token claims, never an ID-JAG or ID token", async () => {
  const f = fixture();
  const verified: VerifiedAccessTokenClaims = { tokenUse: "access-token", issuer: f.claims.issuer,
    principalId: f.claims.principalId, agentId: f.claims.agentId, audience: [f.claims.audience],
    scopes: f.claims.scopes, notBefore: BEFORE, expiresAt: f.claims.expiresAt };
  const options = {
    issuer: f.claims.issuer, audience: f.claims.audience, normalizerId: "normalizer:enterprise",
    grant: { tools: f.claims.tools, operations: f.claims.operations, resources: f.claims.resources,
      scopes: f.claims.scopes, constraints: f.claims.constraints }, keyPair: f.normalizer,
    clock: () => new Date(NOW), profile: "mcp-ema" as const,
    verify: async (): Promise<VerifiedAccessTokenClaims> => verified,
  };
  const authority = await normalizeAccessTokenAuthority("raw-bearer-secret", options);
  assert.equal(authority.mechanism, "mcp-ema-access-token");
  assert.ok(!canonicalize(authority).includes("raw-bearer-secret"));
  for (const bad of [
    { ...verified, tokenUse: "id-jag" }, { ...verified, tokenUse: "id-token" },
    { ...verified, issuer: "https://forged.example" }, { ...verified, audience: ["other"] },
    { ...verified, scopes: [] }, { ...verified, expiresAt: NOW.toISOString() },
  ]) await assert.rejects(normalizeAccessTokenAuthority("raw", {
    ...options, verify: async () => bad as VerifiedAccessTokenClaims,
  }));
  await assert.rejects(normalizeAccessTokenAuthority("raw", {
    ...options, verify: async () => { throw new Error("signature invalid"); },
  }), /AUTHORITY_ASSERTION_VERIFICATION_FAILED/);
});

test("workload identity must pass both operator authorization and exact-action policy", async () => {
  const f = fixture();
  const spiffeId = "spiffe://example.org/agent/release";
  const authority = await normalizeWorkloadAuthority("jwt-svid", {
    issuer: f.claims.issuer, audience: f.claims.audience, principalId: f.claims.principalId, spiffeId,
    normalizerId: "normalizer:enterprise", keyPair: f.normalizer, clock: () => new Date(NOW),
    grant: { tools: f.claims.tools, operations: ["deploy"], resources: ["environment:staging"],
      scopes: f.claims.scopes, constraints: f.claims.constraints },
    verify: async () => ({ tokenUse: "workload-identity", issuer: f.claims.issuer, spiffeId,
      audience: [f.claims.audience], notBefore: BEFORE, expiresAt: f.claims.expiresAt }),
  });
  f.input.authority = authority;
  f.input.request.action.agentId = spiffeId;
  f.policy.rules[0]!.agents = [spiffeId];
  f.input.request.policy.hash = hashActionPolicy(f.policy);
  assert.equal(admitPreExecution(f.input, f.admissionConfig, NOW).decision, "allow");
  f.input.request.action.operation = "delete";
  assert.equal(admitPreExecution(f.input, f.admissionConfig, NOW).reasonCode, "AUTHORITY_ACTION_NOT_GRANTED");
  assert.equal(validateExternalAuthority({ ...authority, token: "raw" }).ok, false);
  await assert.rejects(normalizeWorkloadAuthority("jwt-svid", {
    issuer: f.claims.issuer, audience: f.claims.audience, principalId: f.claims.principalId,
    spiffeId: "spiffe://example.org/agent/other", normalizerId: "normalizer:enterprise",
    keyPair: f.normalizer, clock: () => new Date(NOW),
    grant: { tools: f.claims.tools, operations: ["deploy"], resources: ["environment:staging"],
      scopes: f.claims.scopes, constraints: f.claims.constraints },
    verify: async () => ({ tokenUse: "workload-identity", issuer: f.claims.issuer, spiffeId,
      audience: [f.claims.audience], notBefore: BEFORE, expiresAt: f.claims.expiresAt }),
  }), /AUTHORITY_IDENTITY_MISMATCH/);
});

test("receipt must prove authority was valid at admission time, not only execution time", () => {
  const f = fixture();
  const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
  const { signature: _signature, ...body } = receipt;
  const earlier = { ...body, issuedAt: "2026-10-03T10:00:00.000Z" };
  const forged = { ...earlier, signature: signWithKeyPair(
    signatureMessage("pre-execution-admission", earlier), f.issuer).toString("base64") };
  assert.equal(verifyPreExecutionAdmission(forged, f.input, f.admissionConfig, NOW).valid, false);
});

test("independent crypto verifier checks the admission signature and request digest", () => {
  const f = fixture();
  const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
  const { signature, ...body } = receipt;
  const pinnedKey = createPublicKey({ key: Buffer.from(f.issuer.publicKeyDer, "base64"),
    format: "der", type: "spki" });
  const bytes = Buffer.from(`besa:pre-execution-admission:v1\0${canonicalize(body)}`, "utf8");
  assert.equal(verifySignature(null, bytes, pinnedKey, Buffer.from(signature, "base64")), true);
  const digest = createHash("sha256").update(
    `besa:pre-execution-request:v1\0${canonicalize(f.input.request)}`, "utf8").digest("hex");
  assert.equal(receipt.requestDigest, digest);
  assert.equal(verifySignature(null, Buffer.from(canonicalize(body)), pinnedKey,
    Buffer.from(signature, "base64")), false);
});

test("rotated keys preserve audit verification and reject retired keys for execution", () => {
  const f = fixture();
  const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
  const successor = generateKeyPair();
  const later = new Date("2026-10-03T12:01:00.000Z");
  f.admissionConfig.trustStore = applyKeyRotation(f.admissionConfig.trustStore,
    createKeyRotation(f.issuer, successor, later.toISOString()));
  assert.equal(verifyPreExecutionAdmission(receipt, f.input, f.admissionConfig, later, "audit").valid, true);
  assert.equal(verifyPreExecutionAdmission(receipt, f.input, f.admissionConfig, later, "audit").authorized, false);
  assert.equal(verifyPreExecutionAdmission(receipt, f.input, f.admissionConfig, later).authorized, false);
  f.admissionConfig.keyPair = successor;
  const fresh = admitPreExecution(f.input, f.admissionConfig, later);
  assert.equal(verifyPreExecutionAdmission(fresh, f.input, f.admissionConfig, later).authorized, true);
});

test("policy and delegation constraints cannot be satisfied by inherited properties", () => {
  const f = fixture();
  const exact = JSON.parse('{"__proto__":{}}') as Record<string, never>;
  f.policy.rules[0]!.constraints.exact = exact;
  assert.equal(admitAction(f.input.request.action, f.policy, NOW).reasonCode, "CONSTRAINT_VIOLATION");
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const delegation = createDelegation({
    issuerId: f.claims.principalId, subjectId: f.claims.agentId, subjectPublicKey: agent.publicKeyDer,
    allowedOperations: ["deploy"], allowedResources: ["environment:staging"], scopes: f.claims.scopes,
    constraints: { exact, maximums: {} }, issuedAt: BEFORE, notBefore: BEFORE, expiresAt: EXPIRY,
    parentDelegationHash: null,
  }, principal);
  const trust = addTrustAnchor(emptyTrustStore(), principal.publicKeyDer, BEFORE);
  assert.equal(verifyActionDelegation([delegation], f.input.request.action, trust, NOW).reasonCode,
    "DELEGATION_ACTION_NOT_GRANTED");
});

test("malformed canonical intent fails before resolution or execution", async () => {
  const f = fixture();
  let resolverCalls = 0;
  f.runtime.resolveAdmission = () => { resolverCalls++; throw new Error("must not resolve"); };
  let toolCalls = 0;
  const run = withPreExecutionAdmission(f.runtime, () => { toolCalls++; return {}; });
  const malformed = { ...f.input, request: { ...f.input.request, parameters: { bad: Number.NaN } } };
  await assert.rejects(run(malformed), /SCHEMA_PRE_EXECUTION_REQUEST_INVALID/);
  const invalidVersion = { ...f.input, request: { ...f.input.request, requestVersion: 2 } };
  await assert.rejects(run(invalidVersion as PreExecutionAdmissionInput));
  assert.equal(resolverCalls, 0);
  assert.equal(toolCalls, 0);
  assert.equal(verifyExternalAuthority(f.input.authority, null as never,
    f.claims.audience, f.admissionConfig.authorityTrustStore, NOW).valid, false);
});

test("seeded receipt parsing and canonical-order properties remain deterministic", () => {
  const f = fixture();
  const receipt = admitPreExecution(f.input, f.admissionConfig, NOW);
  let seed = 0x5be5a;
  const next = (): number => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed; };
  const values: unknown[] = [null, false, "token", 3, [], {}, { artifactVersion: 999 }];
  for (let sample = 0; sample < 128; sample++) {
    const fields = Object.entries(receipt);
    for (let i = fields.length - 1; i > 0; i--) {
      const index = next() % (i + 1);
      [fields[i], fields[index]] = [fields[index]!, fields[i]!];
    }
    const permuted = Object.fromEntries(fields) as PreExecutionAdmissionReceiptV1;
    assert.equal(hashPreExecutionReceipt(permuted), hashPreExecutionReceipt(receipt));
    const malformed = Object.fromEntries(fields.slice(0, next() % fields.length).map(
      ([key]) => [key, values[next() % values.length]],
    ));
    const first = validatePreExecutionReceipt(malformed);
    const second = validatePreExecutionReceipt(malformed);
    assert.deepEqual(first, second);
    assert.equal(first.ok, false);
  }
  // These v1 JavaScript JSON equivalences are deliberately frozen, not JCS.
  assert.equal(canonicalize({ "10": "ten", "2": "two" }), '{"2":"two","10":"ten"}');
  assert.equal(canonicalize(-0), canonicalize(0));
});

test("known revoked intermediate and leaf keys cannot retain delegated authority", () => {
  const f = fixture();
  const principal = generateKeyPair();
  const broker = generateKeyPair();
  const leaf = generateKeyPair();
  const root = createDelegation({
    issuerId: f.claims.principalId, subjectId: "agent:broker", subjectPublicKey: broker.publicKeyDer,
    allowedOperations: ["deploy"], allowedResources: ["environment:staging"], scopes: f.claims.scopes,
    constraints: { exact: {}, maximums: {} }, issuedAt: BEFORE, notBefore: BEFORE,
    expiresAt: EXPIRY, parentDelegationHash: null,
  }, principal);
  const child = createDelegation({ ...root, delegationId: undefined, issuerId: "agent:broker",
    subjectId: f.claims.agentId, subjectPublicKey: leaf.publicKeyDer,
    parentDelegationHash: hashDelegation(root) }, broker);
  const trusted = addTrustAnchor(addTrustAnchor(addTrustAnchor(emptyTrustStore(),
    principal.publicKeyDer, BEFORE), broker.publicKeyDer, BEFORE), leaf.publicKeyDer, BEFORE);
  assert.equal(verifyActionDelegation([root, child], f.input.request.action, trusted, NOW).valid, true);
  for (const compromised of [broker, leaf]) {
    const revoked = revokeTrustAnchor(trusted, publicKeyId(compromised.publicKeyDer), NOW.toISOString());
    assert.equal(verifyActionDelegation([root, child], f.input.request.action, revoked, NOW).reasonCode,
      "TRUST_DELEGATION_KEY_REVOKED");
  }
});
