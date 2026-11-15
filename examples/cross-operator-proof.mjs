import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  addTrustAnchor,
  admitPreExecution,
  createExternalAuthority,
  emptyTrustStore,
  generateKeyPair,
  hashActionPolicy,
  hashPreExecutionReceipt,
  hashRequest,
  InMemoryReplayStore,
  parseArtifactJson,
  verifyActionEvidence,
  verifyPreExecutionAdmission,
  withBesaExecutor,
} from "@dorigjo/besa";

const script = fileURLToPath(import.meta.url);
const asJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
const readJson = (path) => parseArtifactJson(readFileSync(path));
const writeJson = (path, value) => writeFileSync(path, asJson(value), { flag: "wx", mode: 0o600 });
const inputPath = (root) => join(root, "admission.json");
const executionPath = (root) => join(root, "execution.json");
const verificationPath = (root) => join(root, "verification.json");
const outputPath = (root) => join(root, "artifact.txt");

function runOperator(role, root) {
  execFileSync(process.execPath, [script, role, root], { stdio: "pipe", encoding: "utf8" });
}

function issuer(root) {
  const now = new Date();
  const issuedAt = now.toISOString();
  const notBefore = new Date(now.getTime() - 60_000).toISOString();
  const expiresAt = new Date(now.getTime() + 300_000).toISOString();
  const issuerKey = generateKeyPair();
  const normalizerKey = generateKeyPair();
  const principalId = "principal:platform";
  const agentId = "agent:release-bot";
  const audience = "https://tools.example/artifacts";
  const executorId = "executor:staging-artifact-store";
  const policy = {
    version: 1,
    policyId: "artifact-publish-staging-v1",
    delegationRequired: false,
    rules: [{
      ruleId: "staging-publish",
      principals: [principalId],
      agents: [agentId],
      tools: ["artifact.publish"],
      operations: ["publish"],
      resources: ["artifact:staging"],
      allowedScopes: ["artifact:write"],
      maxRisk: "medium",
      constraints: { exact: { environment: "staging" }, maximums: {} },
    }],
  };
  const parameters = { content: "BESA protected artifact", environment: "staging" };
  const context = { executorId, route: "artifact-store/staging" };
  const request = {
    requestVersion: 1,
    parameters,
    context,
    audience,
    requestedAt: issuedAt,
    policy: { id: policy.policyId, version: 1, hash: hashActionPolicy(policy) },
    action: {
      artifactVersion: 1,
      principalId,
      agentId,
      authority: "authority:ci-platform",
      tool: "artifact.publish",
      operation: "publish",
      resource: "artifact:staging",
      requestHash: hashRequest(parameters),
      scopes: ["artifact:write"],
      constraints: { environment: "staging" },
      expiresAt,
      nonce: "cross_operator_0123456789abcdef",
      riskClass: "medium",
      contextHash: hashRequest(context),
    },
  };
  const authority = createExternalAuthority({
    artifactVersion: 1,
    mechanism: "mcp-ema-access-token",
    principalId,
    agentId,
    issuer: "authority:ci-platform",
    audience,
    tools: ["artifact.publish"],
    operations: ["publish"],
    resources: ["artifact:staging"],
    scopes: ["artifact:write"],
    constraints: { exact: { environment: "staging" }, maximums: {} },
    notBefore,
    expiresAt,
    assertionDigest: "a".repeat(64),
    delegationChainHash: null,
  }, { id: "normalizer:ci-platform", keyPair: normalizerKey, issuedAt });
  const trustStore = addTrustAnchor(emptyTrustStore(), issuerKey.publicKeyDer, notBefore);
  const authorityTrustStore = addTrustAnchor(emptyTrustStore(), normalizerKey.publicKeyDer, notBefore);
  const input = { request, authority };
  const receipt = admitPreExecution(input, {
    policy,
    audience,
    issuerId: "admission:ci-platform",
    keyPair: issuerKey,
    trustStore,
    authorityTrustStore,
  }, now);
  assert.equal(receipt.decision, "allow");
  writeJson(inputPath(root), { format: "besa-pre-execution-bundle-v1", input, receipt,
    policy, audience, trustStore, authorityTrustStore });
}

async function executor(root) {
  const bundle = readJson(inputPath(root));
  const recorderKey = generateKeyPair();
  const caller = { principalId: "principal:platform", agentId: "agent:release-bot" };
  let handlerCalls = 0;
  let evidence;
  const guarded = withBesaExecutor({
    policy: bundle.policy,
    audience: bundle.audience,
    trustStore: bundle.trustStore,
    authorityTrustStore: bundle.authorityTrustStore,
    executorId: "executor:staging-artifact-store",
    recorderId: "recorder:artifact-store",
    evidenceKeyPair: recorderKey,
    replayStore: new InMemoryReplayStore(),
    admissionSink: { async append() {} },
    evidenceSink: { async append(record) { evidence = record.evidence; } },
  }, (verified) => {
    handlerCalls += 1;
    const content = verified.request.parameters.content;
    writeFileSync(outputPath(root), content, { flag: "wx", mode: 0o600 });
    return { stored: true, resource: verified.request.action.resource, bytes: Buffer.byteLength(content) };
  });

  const result = await guarded(bundle.input, bundle.receipt, caller);
  assert.ok(evidence, "executor must write signed result evidence");

  const mutatedInput = structuredClone(bundle.input);
  mutatedInput.request.parameters.content = "substituted content";
  let mutationRejected = false;
  try { await guarded(mutatedInput, bundle.receipt, caller); }
  catch { mutationRejected = true; }

  let replayRejected = false;
  try { await guarded(bundle.input, bundle.receipt, caller); }
  catch { replayRejected = true; }

  assert.equal(mutationRejected, true);
  assert.equal(replayRejected, true);
  assert.equal(handlerCalls, 1, "mutation and replay must not invoke the executor again");
  assert.equal(readFileSync(outputPath(root), "utf8"), bundle.input.request.parameters.content);

  const verificationTrustStore = addTrustAnchor(bundle.trustStore, recorderKey.publicKeyDer,
    new Date().toISOString());
  writeJson(executionPath(root), {
    result: result.result,
    evidence,
    recorderTrustStore: verificationTrustStore,
    handlerCalls,
    mutationRejected,
    replayRejected,
  });
}

function verifier(root) {
  const bundle = readJson(inputPath(root));
  const execution = readJson(executionPath(root));
  const admission = verifyPreExecutionAdmission(bundle.receipt, bundle.input, {
    policy: bundle.policy,
    audience: bundle.audience,
    trustStore: bundle.trustStore,
    authorityTrustStore: bundle.authorityTrustStore,
  }, new Date(), "audit");
  const executionEvidence = verifyActionEvidence(execution.evidence, {
    action: bundle.input.request.action,
    capability: bundle.receipt.capability,
    result: execution.result,
    trustStore: execution.recorderTrustStore,
    receiptHash: hashPreExecutionReceipt(bundle.receipt),
  });
  const report = {
    verifier: "operator-c-offline-verifier",
    admissionValid: admission.valid,
    admissionDecision: admission.receipt?.decision ?? null,
    admissionReason: admission.reasonCode,
    executionEvidenceValid: executionEvidence.valid,
    executionEvidenceReason: executionEvidence.reasonCode,
    handlerCalls: execution.handlerCalls,
    mutationRejected: execution.mutationRejected,
    replayRejected: execution.replayRejected,
    effectMatchesAuthorizedInput: existsSync(outputPath(root)) &&
      readFileSync(outputPath(root), "utf8") === bundle.input.request.parameters.content,
    privateKeysProvided: false,
    networkUsed: false,
  };
  assert.equal(report.admissionValid, true);
  assert.equal(report.admissionDecision, "allow");
  assert.equal(report.executionEvidenceValid, true);
  assert.equal(report.handlerCalls, 1);
  assert.equal(report.mutationRejected, true);
  assert.equal(report.replayRejected, true);
  assert.equal(report.effectMatchesAuthorizedInput, true);
  writeJson(verificationPath(root), report);
}

function main() {
  const role = process.argv[2];
  const root = process.argv[3];
  if (role === "issuer") return issuer(root);
  if (role === "executor") return executor(root);
  if (role === "verifier") return verifier(root);
  const keep = process.argv.includes("--keep");
  const workspace = mkdtempSync(join(tmpdir(), "besa-cross-operator-"));
  try {
    runOperator("issuer", workspace);
    runOperator("executor", workspace);
    runOperator("verifier", workspace);
    const report = readJson(verificationPath(workspace));
    const bundle = {
      format: "besa-cross-operator-proof-bundle-v1",
      admission: readJson(inputPath(workspace)),
      execution: readJson(executionPath(workspace)),
      verification: report,
    };
    writeJson(join(workspace, "proof-bundle.json"), bundle);
    process.stdout.write(`${JSON.stringify({ ...report, proofBundle: keep ? join(workspace, "proof-bundle.json") : undefined })}\n`);
    if (!keep) rmSync(workspace, { recursive: true, force: true });
  } catch (error) {
    if (!keep) rmSync(workspace, { recursive: true, force: true });
    throw error;
  }
}

await main();
