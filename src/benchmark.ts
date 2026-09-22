import { cpus, platform, release } from "node:os";
import {
  addTrustAnchor,
  admitAction,
  canonicalize,
  createActionCapability,
  createActionEvidence,
  createDelegation,
  emptyTrustStore,
  generateKeyPair,
  hashActionEnvelope,
  hashDelegation,
  hashRequest,
  verifyActionCapability,
  verifyActionDelegation,
  verifyActionEvidence,
  type ActionEnvelopeV1,
  type ActionPolicyV1,
} from "./sdk.js";

const AT = new Date("2030-01-01T00:00:03.000Z");
const WARMUP_ITERATIONS = 100;
const OPERATIONS_PER_SAMPLE = 10;

function readIterations(): number {
  const raw = process.env.BESA_BENCHMARK_ITERATIONS ?? "250";
  const iterations = Number(raw);
  if (!Number.isSafeInteger(iterations) || iterations < 100 || iterations > 100_000) {
    throw new Error("BESA_BENCHMARK_ITERATIONS must be an integer from 100 to 100000");
  }
  return iterations;
}

function percentile(values: number[], percentileValue: number): number {
  const index = Math.min(
    values.length - 1,
    Math.max(0, Math.ceil(values.length * percentileValue) - 1),
  );
  return values[index]!;
}

function measure(name: string, iterations: number, operation: () => void): {
  name: string;
  medianUs: number;
  p95Us: number;
  p99Us: number;
} {
  for (let index = 0; index < WARMUP_ITERATIONS; index += 1) operation();

  const samples: number[] = [];
  for (let index = 0; index < iterations; index += 1) {
    const startedAt = process.hrtime.bigint();
    for (let operationIndex = 0; operationIndex < OPERATIONS_PER_SAMPLE; operationIndex += 1) {
      operation();
    }
    samples.push(Number(process.hrtime.bigint() - startedAt) / 1_000 / OPERATIONS_PER_SAMPLE);
  }
  samples.sort((left, right) => left - right);
  return {
    name,
    medianUs: Number(percentile(samples, 0.5).toFixed(3)),
    p95Us: Number(percentile(samples, 0.95).toFixed(3)),
    p99Us: Number(percentile(samples, 0.99).toFixed(3)),
  };
}

const issuer = generateKeyPair();
const agent = generateKeyPair();
const action: ActionEnvelopeV1 = {
  artifactVersion: 1,
  principalId: "principal:benchmark",
  agentId: "agent:benchmark",
  authority: "customer:benchmark",
  tool: "payments.transfer",
  operation: "transfer",
  resource: "payment:merchant-benchmark",
  requestHash: hashRequest({ amountEur: 100, merchantId: "merchant-benchmark" }),
  scopes: ["payments:transfer"],
  constraints: { amountEur: 100, merchantId: "merchant-benchmark" },
  expiresAt: "2030-01-02T00:00:00.000Z",
  nonce: "benchmark_nonce_00001",
  riskClass: "high",
};
const policy: ActionPolicyV1 = {
  version: 1,
  policyId: "policy:benchmark:v1",
  delegationRequired: true,
  rules: [
    {
      ruleId: "allow-benchmark-transfer",
      principals: [action.principalId],
      agents: [action.agentId],
      tools: [action.tool],
      operations: [action.operation],
      resources: [action.resource],
      allowedScopes: [...action.scopes],
      maxRisk: action.riskClass,
      constraints: {
        exact: { merchantId: "merchant-benchmark" },
        maximums: { amountEur: 100 },
      },
    },
  ],
};
const delegation = createDelegation(
  {
    delegationId: "dlg_22222222-2222-4222-8222-222222222222",
    issuerId: action.principalId,
    subjectId: action.agentId,
    subjectPublicKey: agent.publicKeyDer,
    allowedOperations: [action.operation],
    allowedResources: [action.resource],
    scopes: [...action.scopes],
    constraints: {
      exact: { merchantId: "merchant-benchmark" },
      maximums: { amountEur: 100 },
    },
    issuedAt: "2029-12-31T00:00:00.000Z",
    notBefore: "2029-12-31T00:00:00.000Z",
    expiresAt: action.expiresAt,
    parentDelegationHash: null,
  },
  issuer,
);
const trustStore = addTrustAnchor(
  emptyTrustStore(),
  issuer.publicKeyDer,
  "2029-12-30T00:00:00.000Z",
);
const capability = createActionCapability(
  {
    capabilityId: "cap_22222222-2222-4222-8222-222222222222",
    action,
    policyId: policy.policyId,
    delegationChainHash: hashDelegation(delegation),
    decision: "allow",
    reasonCode: "ACTION_ALLOWED",
    issuerId: "besa:benchmark",
    issuedAt: "2029-12-31T00:00:00.000Z",
  },
  issuer,
);
const result = { rail: "mock", railReference: "benchmark-001", status: "accepted" };
const evidence = createActionEvidence(
  {
    evidenceId: "evd_22222222-2222-4222-8222-222222222222",
    action,
    capability,
    result,
    outcome: "succeeded",
    executorId: "rail:benchmark",
    recorderId: "besa:benchmark",
    receiptHash: null,
    startedAt: "2030-01-01T00:00:00.000Z",
    completedAt: "2030-01-01T00:00:01.000Z",
    recordedAt: "2030-01-01T00:00:02.000Z",
  },
  issuer,
);

const iterations = readIterations();
const results = [
  measure("canonicalize", iterations, () => {
    canonicalize(action);
  }),
  measure("hashActionEnvelope", iterations, () => {
    hashActionEnvelope(action);
  }),
  measure("verifyActionCapability", iterations, () => {
    verifyActionCapability(capability, action, trustStore, AT);
  }),
  measure("admitAction", iterations, () => {
    admitAction(action, policy, AT);
  }),
  measure("fullActionVerification", iterations, () => {
    verifyActionDelegation([delegation], action, trustStore, AT);
    verifyActionCapability(capability, action, trustStore, AT);
    verifyActionEvidence(
      evidence,
      { action, capability, result, trustStore, receiptHash: null },
      AT,
    );
  }),
];

console.log(
  JSON.stringify(
    {
      benchmark: "besa-v1.1-consequential-action",
      node: process.version,
      platform: `${platform()} ${release()} ${process.arch}`,
      cpu: cpus()[0]?.model ?? "unknown",
      iterations,
      warmupIterations: WARMUP_ITERATIONS,
      operationsPerSample: OPERATIONS_PER_SAMPLE,
      methodology:
        "Synchronous operations are warmed, then timed with process.hrtime.bigint in batches of ten; results are microseconds per operation.",
      results,
    },
    null,
    2,
  ),
);
