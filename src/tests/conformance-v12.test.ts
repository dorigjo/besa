import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  hashActionPolicy, hashExternalAuthority, hashPreExecutionReceipt,
  hashPreExecutionRequest, verifyPreExecutionAdmission,
  generateKeyPair, InMemoryReplayStore, withBesaExecutor,
  type ExternalAuthorityV1, type PreExecutionAdmissionInput,
  type PreExecutionAdmissionReceiptV1, type PreExecutionVerificationConfig,
} from "../sdk.js";

interface AdmissionVector {
  at: string;
  config: PreExecutionVerificationConfig;
  input: PreExecutionAdmissionInput;
  receipt: PreExecutionAdmissionReceiptV1;
  deniedInput: PreExecutionAdmissionInput;
  deniedReceipt: PreExecutionAdmissionReceiptV1;
}

const vector = JSON.parse(readFileSync(
  new URL("../../conformance/pre-execution-v1.json", import.meta.url), "utf8",
)) as AdmissionVector;
const at = new Date(vector.at);
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

test("published pre-execution v1 vector independently authorizes the exact request", () => {
  const result = verifyPreExecutionAdmission(vector.receipt, vector.input, vector.config, at);
  assert.equal(result.valid, true, result.reasonCode);
  assert.equal(result.authorized, true);
});

test("published pre-execution hashes remain frozen", () => {
  assert.equal(hashActionPolicy(vector.config.policy),
    "9ac3973a212b68edd33d8186843edb5165d18b529f37cc8dd6b8237fab6a4553");
  assert.equal(hashPreExecutionRequest(vector.input.request),
    "4480410bb1b00d36a5d0042f7250d6e8b6e5228809fd430d60ec3d94a5f84027");
  assert.equal(hashExternalAuthority(vector.input.authority as ExternalAuthorityV1),
    "1b52215b23ec41c2b1d2968b8d627dc745dc0f566c3cca857d67991a6e64a232");
  assert.equal(hashPreExecutionReceipt(vector.receipt),
    "8d9b547c57a321727a4d23e0ebb87ed62709742d4af1ed54411b8f1ae42c5018");
  assert.equal(hashPreExecutionReceipt(vector.deniedReceipt),
    "eafaed0fafcb6e70f01ef7ecfdc521dbbf85b8b280b29b005f2d4bbc8980e884");
});

test("published denial is verifiable evidence, never execution authority", () => {
  const result = verifyPreExecutionAdmission(
    vector.deniedReceipt, vector.deniedInput, vector.config, at,
  );
  assert.equal(result.valid, true, result.reasonCode);
  assert.equal(result.authorized, false);
  assert.equal(result.receipt?.reasonCode, "ACTION_REQUEST_MISMATCH");
  assert.equal(result.receipt?.capability, null);
});

test("historical admission audit never permits current execution", () => {
  const after = new Date("2030-01-02T00:00:00.000Z");
  assert.equal(verifyPreExecutionAdmission(
    vector.receipt, vector.input, vector.config, after,
  ).authorized, false);
  const audit = verifyPreExecutionAdmission(
    vector.receipt, vector.input, vector.config, after, "audit",
  );
  assert.equal(audit.valid, true, audit.reasonCode);
  assert.equal(audit.authorized, false);
});

test("published admission rejects parameter, executor, version and signature substitution", () => {
  for (const mutate of [
    (input: PreExecutionAdmissionInput) => { input.request.parameters.content = "substituted"; },
    (input: PreExecutionAdmissionInput) => { input.request.context.executorId = "executor:other"; },
    (input: PreExecutionAdmissionInput) => { input.request.policy.version = 2; },
  ]) {
    const input = copy(vector.input);
    mutate(input);
    assert.equal(verifyPreExecutionAdmission(vector.receipt, input, vector.config, at).valid, false);
  }
  for (const receipt of [
    { ...vector.receipt, artifactVersion: 2 },
    { ...vector.receipt, signature: "A".repeat(86) + "==" },
  ]) {
    assert.equal(verifyPreExecutionAdmission(receipt, vector.input, vector.config, at).valid, false);
  }
});

test("frozen admission blocks every substituted trust fact before executor invocation", async () => {
  const mutations: Array<[string, (input: PreExecutionAdmissionInput) => void]> = [
    ["principal", (i) => { i.request.action.principalId = "principal:other"; }],
    ["agent", (i) => { i.request.action.agentId = "agent:other"; }],
    ["authority", (i) => { i.request.action.authority = "authority:other"; }],
    ["tool", (i) => { i.request.action.tool = "database.delete"; }],
    ["operation", (i) => { i.request.action.operation = "delete"; }],
    ["resource", (i) => { i.request.action.resource = "database:production"; }],
    ["parameters", (i) => { i.request.parameters.content = "substituted"; }],
    ["executor", (i) => { i.request.context.executorId = "executor:other"; }],
    ["runtime context", (i) => { i.request.context.runtimeId = "runtime:other"; }],
    ["policy id", (i) => { i.request.policy.id = "policy:other"; }],
    ["policy version", (i) => { i.request.policy.version = 2; }],
    ["policy digest", (i) => { i.request.policy.hash = "0".repeat(64); }],
    ["nonce", (i) => { i.request.action.nonce = "nonce_9876543210abcdef"; }],
    ["expiry", (i) => { i.request.action.expiresAt = "2031-01-01T00:00:00.000Z"; }],
    ["assertion", (i) => { (i.authority as ExternalAuthorityV1).assertionDigest = "0".repeat(64); }],
    ["issuer", (i) => { (i.authority as ExternalAuthorityV1).issuer = "issuer:other"; }],
    ["delegation digest", (i) => { (i.authority as ExternalAuthorityV1).delegationChainHash = "0".repeat(64); }],
    ["delegation", (i) => { i.delegationChain = []; }],
  ];
  const recorder = generateKeyPair();
  for (const [name, mutate] of mutations) {
    const input = copy(vector.input);
    mutate(input);
    assert.equal(verifyPreExecutionAdmission(vector.receipt, input, vector.config, at).valid, false, name);
    let calls = 0;
    const execute = withBesaExecutor({
      ...vector.config, clock: () => new Date(at),
      executorId: String(vector.input.request.context.executorId), recorderId: "recorder:conformance",
      evidenceKeyPair: recorder, replayStore: new InMemoryReplayStore(),
      admissionSink: { async append() {} }, evidenceSink: { async append() {} },
    }, () => { calls++; return { mutated: true }; });
    await assert.rejects(execute(input, vector.receipt, {
      principalId: vector.input.request.action.principalId,
      agentId: vector.input.request.action.agentId,
    }), name);
    assert.equal(calls, 0, name);
  }
});
