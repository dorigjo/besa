import { createHash, randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, linkSync, lstatSync, mkdirSync,
  openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  addTrustAnchor, admitPreExecution, AppendOnlyEvidenceLog, createDelegation,
  emptyTrustStore, FileReplayStore, generateKeyPair, hashActionPolicy, hashRequest,
  normalizeDelegationAuthority, withBesaExecutor,
  type ActionPolicyV1, type BesaExecutorConfig, type PreExecutionAdmissionInput,
  type PreExecutionAdmissionReceiptV1, type PreExecutionRequestV1,
} from "@dorigjo/besa";

function digest(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

export function createArtifactPublisher(directory: string, config: BesaExecutorConfig):
  ReturnType<typeof withBesaExecutor<{ artifactHash: string; created: boolean }>> {
  const root = resolve(directory);
  return withBesaExecutor(config, (input) => {
    const { action, parameters } = input.request;
    const content = parameters.content;
    if (typeof content !== "string" || Buffer.byteLength(content) > 65_536 ||
        action.tool !== "artifact.publish" || action.operation !== "publish" ||
        parameters.artifactHash !== digest(content) ||
        action.resource !== `artifact:staging:${digest(content)}`) {
      throw new Error("ARTIFACT_CONTRACT_MISMATCH");
    }
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const directoryStat = lstatSync(root);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error("unsafe artifact root");
    const artifactHash = digest(content);
    const destination = join(root, `${artifactHash}.artifact`);
    const temporary = join(root, `.publish-${randomUUID()}.tmp`);
    const descriptor = openSync(temporary, "wx", 0o600);
    try {
      try {
        writeFileSync(descriptor, content, "utf8");
        fsyncSync(descriptor);
      } finally { closeSync(descriptor); }
      let created = true;
      // A hard link atomically exposes complete bytes and never replaces a target.
      try { linkSync(temporary, destination); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const stat = lstatSync(destination);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65_536 ||
            digest(readFileSync(destination)) !== artifactHash) throw new Error("ARTIFACT_CONFLICT");
        created = false;
      }
      if (process.platform !== "win32") {
        const parent = openSync(root, "r");
        try { fsyncSync(parent); } finally { closeSync(parent); }
      }
      return { artifactHash, created };
    } finally { unlinkSync(temporary); }
  });
}

export async function runProtectedArtifactExample(directory: string): Promise<{
  deniedWithoutReceipt: boolean; replayBlockedAfterRestart: boolean;
  artifactPresent: boolean; secondAttemptCreated: boolean;
}> {
  const root = resolve(directory);
  const state = join(root, ".besa");
  mkdirSync(state, { recursive: true, mode: 0o700 });
  const now = new Date();
  const before = new Date(now.getTime() - 60_000).toISOString();
  const expiresAt = new Date(now.getTime() + 300_000).toISOString();
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const normalizer = generateKeyPair();
  const issuer = generateKeyPair();
  const recorder = generateKeyPair();
  const caller = { agentId: "agent:ci", principalId: "principal:release" };
  // The production host must obtain caller from authenticated transport/job
  // context, never from the untrusted request body or the receipt's own claims.
  const content = '{"environment":"staging","revision":"abc123"}\n';
  const artifactHash = digest(content);
  const resource = `artifact:staging:${artifactHash}`;
  const policy: ActionPolicyV1 = { version: 1, policyId: "ci-artifact-v1", delegationRequired: true,
    rules: [{ ruleId: "publish-staging", principals: [caller.principalId], agents: [caller.agentId],
      tools: ["artifact.publish"], operations: ["publish"], resources: [resource],
      allowedScopes: ["artifact:write"], maxRisk: "medium",
      constraints: { exact: { artifactHash }, maximums: {} } }] };
  const parameters = { content, artifactHash };
  const context = { executorId: "executor:ci-artifacts", pipeline: "release" };
  const request: PreExecutionRequestV1 = { requestVersion: 1, parameters, context,
    audience: "https://ci.example/artifacts", requestedAt: now.toISOString(),
    policy: { id: policy.policyId, version: 1, hash: hashActionPolicy(policy) },
    action: { artifactVersion: 1, ...caller, authority: "authority:ci", tool: "artifact.publish",
      operation: "publish", resource, requestHash: hashRequest(parameters), scopes: ["artifact:write"],
      constraints: { artifactHash }, expiresAt, nonce: randomUUID(), riskClass: "medium",
      contextHash: hashRequest(context) } };
  const delegationTrustStore = addTrustAnchor(emptyTrustStore(), principal.publicKeyDer, before);
  const delegationChain = [createDelegation({ issuerId: caller.principalId, subjectId: caller.agentId,
    subjectPublicKey: agent.publicKeyDer, allowedOperations: ["publish"], allowedResources: [resource],
    scopes: ["artifact:write"], constraints: { exact: { artifactHash }, maximums: {} },
    issuedAt: before, notBefore: before, expiresAt, parentDelegationHash: null }, principal)];
  const authority = normalizeDelegationAuthority(delegationChain, request.action, {
    issuer: request.action.authority, audience: request.audience, normalizerId: "normalizer:ci",
    keyPair: normalizer, trustStore: delegationTrustStore, clock: () => now,
    authenticatedAgentId: caller.agentId,
  });
  const admissionConfig = { policy, audience: request.audience, delegationTrustStore,
    trustStore: addTrustAnchor(addTrustAnchor(emptyTrustStore(), issuer.publicKeyDer, before),
      recorder.publicKeyDer, before),
    authorityTrustStore: addTrustAnchor(emptyTrustStore(), normalizer.publicKeyDer, before),
    issuerId: "admission:ci", keyPair: issuer };
  const input: PreExecutionAdmissionInput = { request, authority, delegationChain };
  const receipt = admitPreExecution(input, admissionConfig, new Date());
  const config: BesaExecutorConfig = {
    policy, audience: request.audience, trustStore: admissionConfig.trustStore,
    authorityTrustStore: admissionConfig.authorityTrustStore, delegationTrustStore,
    // Explicit process-crash durability for this cross-platform example.
    // Production POSIX deployments should use the strict default power-loss mode.
    replayStore: new FileReplayStore(join(state, "replay"), { durability: "process" }),
    admissionSink: new AppendOnlyEvidenceLog<PreExecutionAdmissionReceiptV1>(join(state, "admissions.jsonl")),
    evidenceSink: new AppendOnlyEvidenceLog(join(state, "execution.jsonl")),
    evidenceKeyPair: recorder, executorId: context.executorId, recorderId: "recorder:ci",
  };
  const publish = createArtifactPublisher(join(root, "artifacts"), config);
  let deniedWithoutReceipt = false;
  try { await publish(input, undefined, caller); } catch { deniedWithoutReceipt = true; }
  if (!deniedWithoutReceipt) throw new Error("receipt-free execution allowed");
  await publish(input, receipt, caller);
  const restarted = createArtifactPublisher(join(root, "artifacts"), {
    ...config, replayStore: new FileReplayStore(join(state, "replay"), { durability: "process" }),
  });
  let replayBlockedAfterRestart = false;
  try { await restarted(input, receipt, caller); } catch { replayBlockedAfterRestart = true; }
  if (!replayBlockedAfterRestart) throw new Error("restart replay allowed");
  const next = { ...input, request: { ...request, action: { ...request.action, nonce: randomUUID() } } };
  const retry = await restarted(next, admitPreExecution(next, admissionConfig, new Date()), caller);
  const artifactPresent = existsSync(join(root, "artifacts", `${artifactHash}.artifact`));
  if (!artifactPresent || retry.result.created) throw new Error("artifact idempotency failed");
  return { deniedWithoutReceipt, replayBlockedAfterRestart, artifactPresent,
    secondAttemptCreated: retry.result.created };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(await runProtectedArtifactExample(
    process.argv[2] ?? join(process.cwd(), ".besa", "artifact-example"),
  ))}\n`);
}
