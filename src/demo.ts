import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type ActionEnvelopeV1,
  type ActionPolicyV1,
  type EvidenceSink,
  type RuntimeEvidenceRecordV1,
  BesaRuntimeError,
  InMemoryReplayStore,
  addTrustAnchor,
  admitAction,
  createActionCapability,
  emptyTrustStore,
  generateKeyPair,
  hashRequest,
  verifyActionEvidence,
  withBesa,
} from "./sdk.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");

class MemoryEvidenceSink implements EvidenceSink {
  readonly records: RuntimeEvidenceRecordV1[] = [];

  async append(record: RuntimeEvidenceRecordV1): Promise<void> {
    this.records.push(record);
  }
}

interface DemoOutcome {
  decision: "allow" | "deny";
  reasonCode: string;
  executorCalled: boolean;
  capabilityId?: string;
  actionHash?: string;
  verification?: string;
  evidenceRecorded?: boolean;
}

function action(
  values: Pick<
    ActionEnvelopeV1,
    "principalId" | "agentId" | "tool" | "operation" | "resource" | "scopes" | "constraints" | "nonce"
  >,
): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    authority: "iam:example:approved-agents",
    requestHash: hashRequest(values.constraints),
    expiresAt: "2026-09-21T12:05:00.000Z",
    riskClass: "high",
    ...values,
  };
}

function policyFor(
  requested: ActionEnvelopeV1,
  constraints: ActionPolicyV1["rules"][number]["constraints"],
): ActionPolicyV1 {
  return {
    version: 1,
    policyId: `policy:${requested.operation}-v1`,
    delegationRequired: false,
    rules: [
      {
        ruleId: `allow-${requested.operation}`,
        principals: [requested.principalId],
        agents: [requested.agentId],
        tools: [requested.tool],
        operations: [requested.operation],
        resources: [requested.resource],
        allowedScopes: requested.scopes,
        maxRisk: "high",
        constraints,
      },
    ],
  };
}

async function runAction<TResult>(
  requested: ActionEnvelopeV1,
  policy: ActionPolicyV1,
  execute: () => TResult | Promise<TResult>,
): Promise<DemoOutcome> {
  const authority = generateKeyPair();
  const recorder = generateKeyPair();
  let trustStore = addTrustAnchor(
    emptyTrustStore(),
    authority.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );
  trustStore = addTrustAnchor(
    trustStore,
    recorder.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );
  const sink = new MemoryEvidenceSink();
  const decision = admitAction(requested, policy, NOW);
  let executorCalled = false;
  const guarded = withBesa(
    {
      trustStore,
      capability: (candidate) =>
        createActionCapability(
          {
            action: candidate,
            decision: decision.decision,
            reasonCode: decision.reasonCode,
            policyId: decision.policyId,
            delegationChainHash: null,
            issuerId: "authority:demo",
            issuedAt: NOW.toISOString(),
          },
          authority,
        ),
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: recorder,
      evidenceSink: sink,
      recorderId: "authority:demo-evidence",
      executorId: "service:demo-executor",
      clock: () => new Date(NOW),
    },
    async () => {
      executorCalled = true;
      return execute();
    },
  );

  try {
    const execution = await guarded(requested);
    const verification = verifyActionEvidence(
      execution.evidence,
      {
        action: requested,
        capability: execution.capability,
        result: execution.result,
        trustStore,
      },
      new Date("2026-09-21T12:01:00.000Z"),
    );
    return {
      decision: "allow",
      reasonCode: execution.capability.reasonCode,
      executorCalled,
      capabilityId: execution.capability.capabilityId,
      actionHash: execution.evidence.actionHash,
      verification: verification.reasonCode,
      evidenceRecorded: sink.records.length === 1,
    };
  } catch (error) {
    if (error instanceof BesaRuntimeError) {
      return {
        decision: "deny",
        reasonCode: error.reasonCode,
        executorCalled,
      };
    }
    throw error;
  }
}

function printAction(requested: ActionEnvelopeV1, contract: string): void {
  console.log("ACTION");
  console.log(`agent: ${requested.agentId}`);
  console.log(`operation: ${requested.operation}`);
  console.log(`resource: ${requested.resource}`);
  console.log(`authorized contract: ${contract}`);
  console.log("upstream authentication: ACCEPTED (demo input)");
  console.log("");
}

function printOutcome(outcome: DemoOutcome): void {
  console.log("RESULT");
  console.log(outcome.decision.toUpperCase());
  console.log(outcome.reasonCode);
  console.log(`executor called: ${outcome.executorCalled ? "yes" : "no"}`);
  if (outcome.capabilityId) console.log(`signed capability: ${outcome.capabilityId}`);
  if (outcome.actionHash) console.log(`action hash: ${outcome.actionHash}`);
  if (outcome.verification) console.log(`evidence verification: ${outcome.verification}`);
  if (outcome.evidenceRecorded !== undefined) {
    console.log(`evidence recorded: ${outcome.evidenceRecorded ? "yes" : "no"}`);
  }
  console.log("");
}

export async function runDemo(): Promise<void> {
  console.log("BESA EXACT-ACTION DEMO");
  console.log("AUTHENTICATED != AUTHORIZED FOR THIS EXACT ACTION");
  console.log("Besa starts after upstream identity and immediately before execution.\n");

  const deployAllowed = action({
    principalId: "principal:platform",
    agentId: "agent:deploy-agent",
    tool: "aws.change",
    operation: "deploy",
    resource: "environment:staging",
    scopes: ["cloud:write"],
    constraints: { commit: "abc123", environment: "staging" },
    nonce: "demo_deploy_allow_012345678",
  });
  const deployPolicy = policyFor(deployAllowed, {
    exact: { commit: "abc123", environment: "staging" },
    maximums: {},
  });
  const deleteProduction = action({
    principalId: "principal:platform",
    agentId: "agent:deploy-agent",
    tool: "aws.change",
    operation: "delete",
    resource: "database:production-db",
    scopes: ["cloud:write"],
    constraints: { database: "production-db" },
    nonce: "demo_delete_deny_0123456789",
  });

  printAction(deleteProduction, "deploy commit abc123 to environment:staging");
  printOutcome(
    await runAction(deleteProduction, deployPolicy, async () => ({ deleted: true })),
  );

  printAction(deployAllowed, "deploy commit abc123 to environment:staging");
  printOutcome(
    await runAction(deployAllowed, deployPolicy, async () => ({ deploymentId: "deploy-abc123" })),
  );
}

const entryPath = process.argv[1];
if (entryPath !== undefined && fileURLToPath(import.meta.url) === resolve(entryPath)) {
  void runDemo().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "unknown demo failure";
    console.error(`Demo failed: ${message}`);
    process.exitCode = 1;
  });
}
