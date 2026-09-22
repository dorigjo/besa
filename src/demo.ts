import {
  type ActionEnvelopeV1,
  type ActionPolicyV1,
  type BesaExecutionResult,
  type EvidenceSink,
  type RuntimeEvidenceRecordV1,
  BesaMcpError,
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
  withBesaMcp,
} from "./sdk.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");

class MemoryEvidenceSink implements EvidenceSink {
  readonly records: RuntimeEvidenceRecordV1[] = [];

  async append(record: RuntimeEvidenceRecordV1): Promise<void> {
    this.records.push(record);
  }
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
  label: string,
  requested: ActionEnvelopeV1,
  policy: ActionPolicyV1,
  execute: () => TResult | Promise<TResult>,
): Promise<BesaExecutionResult<TResult> | undefined> {
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
    execute,
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
    console.log(`${label}: ALLOW ${execution.capability.capabilityId}`);
    console.log(`  action=${execution.evidence.actionHash.slice(0, 16)} evidence=${verification.reasonCode}`);
    return execution;
  } catch (error) {
    if (error instanceof BesaRuntimeError) {
      console.log(`${label}: DENY ${error.reasonCode}`);
      return undefined;
    }
    throw error;
  }
}

async function runMcpDenial(): Promise<void> {
  const authority = generateKeyPair();
  const recorder = generateKeyPair();
  let trustStore = addTrustAnchor(emptyTrustStore(), authority.publicKeyDer, "2026-09-21T11:00:00.000Z");
  trustStore = addTrustAnchor(trustStore, recorder.publicKeyDer, "2026-09-21T11:00:00.000Z");
  const sink = new MemoryEvidenceSink();
  const authenticatedCall = { name: "database.drop", arguments: { database: "production" } };
  const requested = action({
    principalId: "principal:platform",
    agentId: "agent:mcp-admin",
    tool: authenticatedCall.name,
    operation: "drop",
    resource: "database:production/orders",
    scopes: ["database:write"],
    constraints: { database: "production" },
    nonce: "demo_mcp_0123456789abcdef",
  });
  const policy: ActionPolicyV1 = {
    version: 1,
    policyId: "policy:mcp-v1",
    delegationRequired: false,
    rules: [
      {
        ruleId: "allow-staging-delete",
        principals: ["principal:platform"],
        agents: ["agent:mcp-admin"],
        tools: ["database.delete"],
        operations: ["delete"],
        resources: ["database:staging/orders"],
        allowedScopes: ["database:write"],
        maxRisk: "high",
        constraints: { exact: { database: "staging" }, maximums: {} },
      },
    ],
  };
  const decision = admitAction(requested, policy, NOW);
  const guarded = withBesaMcp(
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
      executorId: "service:mcp-server",
      clock: () => new Date(NOW),
      actionForCall: () => requested,
    },
    async () => "should-not-run",
  );

  console.log("MCP authentication: accepted by the example transport");
  try {
    await guarded(authenticatedCall);
  } catch (error) {
    if (error instanceof BesaRuntimeError || error instanceof BesaMcpError) {
      console.log(`Privileged MCP action: DENY ${error.reasonCode}`);
      return;
    }
    throw error;
  }
}

async function main(): Promise<void> {
  console.log("BESA consequential-action demo");

  const deployDenied = action({
    principalId: "principal:platform",
    agentId: "agent:release",
    tool: "deployment.release",
    operation: "deploy",
    resource: "environment:production",
    scopes: ["deployment:write"],
    constraints: { commit: "unreviewed", environment: "production", repository: "dorigjo/besa" },
    nonce: "demo_deploy_deny_0123456789",
  });
  const deployAllowed = action({
    ...deployDenied,
    constraints: { commit: "abc123", environment: "production", repository: "dorigjo/besa" },
    nonce: "demo_deploy_allow_012345678",
  });
  await runAction(
    "Production deployment (unreviewed commit)",
    deployDenied,
    policyFor(deployDenied, {
      exact: { commit: "abc123", environment: "production", repository: "dorigjo/besa" },
      maximums: {},
    }),
    async () => ({ deploymentId: "never-created" }),
  );
  await runAction(
    "Production deployment (approved commit)",
    deployAllowed,
    policyFor(deployAllowed, {
      exact: { commit: "abc123", environment: "production", repository: "dorigjo/besa" },
      maximums: {},
    }),
    async () => ({ deploymentId: "deploy-abc123" }),
  );

  const deleteStaging = action({
    principalId: "principal:database",
    agentId: "agent:maintenance",
    tool: "database.delete",
    operation: "delete",
    resource: "database:staging/orders",
    scopes: ["database:write"],
    constraints: { maxRows: 10, table: "orders" },
    nonce: "demo_database_allow_012345678",
  });
  const deleteProduction = action({
    ...deleteStaging,
    resource: "database:production/orders",
    nonce: "demo_database_deny_0123456789",
  });
  const deletePolicy = policyFor(deleteStaging, {
    exact: { table: "orders" },
    maximums: { maxRows: 10 },
  });
  await runAction("Destructive database delete (staging)", deleteStaging, deletePolicy, async () => ({ deletedRows: 4 }));
  await runAction("Destructive database delete (production)", deleteProduction, deletePolicy, async () => ({ deletedRows: 0 }));

  const transfer = action({
    principalId: "principal:finance",
    agentId: "agent:payments",
    tool: "payments.transfer",
    operation: "transfer",
    resource: "account:merchant-123",
    scopes: ["payments:write"],
    constraints: { amount: 100, currency: "EUR", recipient: "merchant-123" },
    nonce: "demo_transfer_allow_0123456789",
  });
  await runAction(
    "External payment rail mock (EUR 100 to merchant-123)",
    transfer,
    policyFor(transfer, {
      exact: { currency: "EUR", recipient: "merchant-123" },
      maximums: { amount: 100 },
    }),
    async () => ({ rail: "mock-bank-rail", transferId: "transfer-001" }),
  );

  await runMcpDenial();
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown demo failure";
  console.error(`Demo failed: ${message}`);
  process.exitCode = 1;
});
