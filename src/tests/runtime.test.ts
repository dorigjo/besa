import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ActionEnvelopeV1 } from "../action.js";
import { createActionCapability } from "../action-capability.js";
import { verifyActionEvidence } from "../action-evidence.js";
import { generateKeyPair } from "../crypto.js";
import {
  InMemoryReplayStore,
  VerificationOnlyReplayStore,
  type ReplayStore,
} from "../replay.js";
import {
  AppendOnlyEvidenceLog,
  BesaRuntimeError,
  withBesa,
  type EvidenceSink,
  type RuntimeEvidenceRecordV1,
} from "../runtime.js";
import { addTrustAnchor, emptyTrustStore } from "../trust.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");

function action(overrides: Partial<ActionEnvelopeV1> = {}): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:platform",
    agentId: "agent:release",
    authority: "iam:example:release-engineers",
    tool: "deployment.release",
    operation: "deploy",
    resource: "environment:staging",
    requestHash: "e".repeat(64),
    scopes: ["deployment:write"],
    constraints: { commit: "abc123", environment: "staging" },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "runtime_0123456789abcdef",
    riskClass: "high",
    ...overrides,
  };
}

class MemoryEvidenceSink implements EvidenceSink {
  readonly records: RuntimeEvidenceRecordV1[] = [];

  async append(record: RuntimeEvidenceRecordV1): Promise<void> {
    this.records.push(record);
  }
}

function setup(decision: "allow" | "deny" = "allow") {
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
  return {
    authority,
    recorder,
    sink,
    trustStore,
    resolveCapability: (requested: ActionEnvelopeV1) =>
      createActionCapability(
        {
          action: requested,
          decision,
          reasonCode:
            decision === "allow" ? "ACTION_ALLOWED" : "CONSTRAINT_VIOLATION",
          policyId: "policy:deploy-v1",
          delegationChainHash: null,
          issuerId: "authority:admission",
          issuedAt: NOW.toISOString(),
        },
        authority,
      ),
  };
}

test("withBesa executes once and records independently verifiable evidence", async () => {
  const fixture = setup();
  const replayStore = new InMemoryReplayStore();
  let calls = 0;
  const guarded = withBesa(
    {
      trustStore: fixture.trustStore,
      capability: fixture.resolveCapability,
      replayStore,
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:deployment-gateway",
      clock: () => new Date(NOW),
    },
    async () => {
      calls += 1;
      return { deploymentId: "deploy-123", status: "queued" };
    },
  );

  const requested = action();
  const execution = await guarded(requested);
  assert.equal(calls, 1);
  assert.equal(fixture.sink.records.length, 1);
  assert.deepEqual(execution.result, {
    deploymentId: "deploy-123",
    status: "queued",
  });
  assert.equal(
    verifyActionEvidence(
      execution.evidence,
      {
        action: requested,
        capability: execution.capability,
        result: execution.result,
        trustStore: fixture.trustStore,
      },
      new Date("2026-09-21T12:01:00.000Z"),
    ).valid,
    true,
  );

  await assert.rejects(
    guarded(requested),
    (error: unknown) =>
      error instanceof BesaRuntimeError && error.reasonCode === "REPLAY_DETECTED",
  );
  assert.equal(calls, 1);
});

test("withBesa blocks signed deny decisions before the handler", async () => {
  const fixture = setup("deny");
  let called = false;
  const guarded = withBesa(
    {
      trustStore: fixture.trustStore,
      capability: fixture.resolveCapability,
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:deployment-gateway",
      clock: () => new Date(NOW),
    },
    async () => {
      called = true;
      return "should-not-run";
    },
  );

  await assert.rejects(
    guarded(action()),
    (error: unknown) =>
      error instanceof BesaRuntimeError &&
      error.reasonCode === "CONSTRAINT_VIOLATION",
  );
  assert.equal(called, false);
});

test("withBesa fails closed when enforced replay protection is unavailable", async () => {
  const fixture = setup();
  const guarded = withBesa(
    {
      trustStore: fixture.trustStore,
      capability: fixture.resolveCapability,
      replayStore: new VerificationOnlyReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:deployment-gateway",
      clock: () => new Date(NOW),
    },
    async () => "should-not-run",
  );

  await assert.rejects(
    guarded(action()),
    (error: unknown) =>
      error instanceof BesaRuntimeError &&
      error.reasonCode === "REPLAY_STORE_UNAVAILABLE",
  );
});

test("withBesa appends signed evidence as one JSONL record", async () => {
  const directory = mkdtempSync(join(tmpdir(), "besa-evidence-log-"));
  const logPath = join(directory, "evidence.jsonl");
  const fixture = setup();
  try {
    const guarded = withBesa(
      {
        trustStore: fixture.trustStore,
        capability: fixture.resolveCapability,
        replayStore: new InMemoryReplayStore(),
        replayRequirement: "enforce",
        evidenceKeyPair: fixture.recorder,
        evidenceSink: new AppendOnlyEvidenceLog(logPath),
        recorderId: "authority:evidence",
        executorId: "service:deployment-gateway",
        clock: () => new Date(NOW),
      },
      async () => ({ deploymentId: "deploy-log" }),
    );

    const execution = await guarded(action());
    const lines = readFileSync(logPath, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    const record = JSON.parse(lines[0]!) as RuntimeEvidenceRecordV1;
    assert.equal(record.recordVersion, 1);
    assert.equal(record.evidence.evidenceId, execution.evidence.evidenceId);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("withBesa records signed failure evidence when the handler throws", async () => {
  const fixture = setup();
  const guarded = withBesa(
    {
      trustStore: fixture.trustStore,
      capability: fixture.resolveCapability,
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:deployment-gateway",
      clock: () => new Date(NOW),
    },
    async () => {
      throw new Error("execution failed");
    },
  );

  await assert.rejects(
    guarded(action()),
    (error: unknown) =>
      error instanceof BesaRuntimeError &&
      error.reasonCode === "ACTION_HANDLER_FAILED" &&
      error.evidence?.outcome === "failed",
  );
  assert.equal(fixture.sink.records.length, 1);
  assert.equal(fixture.sink.records[0]!.evidence.outcome, "failed");
  assert.equal(
    verifyActionEvidence(
      fixture.sink.records[0]!.evidence,
      {
        action: action(),
        capability: fixture.sink.records[0]!.capability,
        result: { errorType: "Error" },
        trustStore: fixture.trustStore,
      },
      new Date("2026-09-21T12:01:00.000Z"),
    ).valid,
    true,
  );
});

test("withBesa accepts a capability issued during asynchronous resolution", async () => {
  const fixture = setup();
  const times = [
    "2026-09-21T12:00:00.000Z",
    "2026-09-21T12:00:01.000Z",
    "2026-09-21T12:00:02.000Z",
    "2026-09-21T12:00:03.000Z",
    "2026-09-21T12:00:04.000Z",
  ];
  let clockIndex = 0;
  const guarded = withBesa(
    {
      trustStore: fixture.trustStore,
      capability: async (requested) =>
        createActionCapability(
          {
            action: requested,
            decision: "allow",
            reasonCode: "ACTION_ALLOWED",
            policyId: "policy:deploy-v1",
            delegationChainHash: null,
            issuerId: "authority:admission",
            issuedAt: "2026-09-21T12:00:01.000Z",
          },
          fixture.authority,
        ),
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:deployment-gateway",
      clock: () => new Date(times[Math.min(clockIndex++, times.length - 1)]!),
    },
    async () => ({ deploymentId: "deploy-fresh-capability" }),
  );

  const execution = await guarded(action());

  assert.equal(execution.capability.issuedAt, "2026-09-21T12:00:01.000Z");
  assert.equal(execution.evidence.startedAt, "2026-09-21T12:00:02.000Z");
});

test("withBesa rechecks expiry after an asynchronous replay-store call", async () => {
  const fixture = setup();
  const times = [
    "2026-09-21T12:00:00.000Z",
    "2026-09-21T12:04:59.000Z",
    "2026-09-21T12:05:00.000Z",
  ];
  let clockIndex = 0;
  let called = false;
  const replayStore: ReplayStore = {
    mode: "enforced",
    async consume() {
      return {
        status: "consumed",
        reasonCode: "REPLAY_CONSUMED",
        detail: "consumed for expiry-boundary test",
        enforced: true,
      };
    },
  };
  const guarded = withBesa(
    {
      trustStore: fixture.trustStore,
      capability: fixture.resolveCapability,
      replayStore,
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:deployment-gateway",
      clock: () => new Date(times[Math.min(clockIndex++, times.length - 1)]!),
    },
    async () => {
      called = true;
      return "must-not-run";
    },
  );

  await assert.rejects(
    guarded(action()),
    (error: unknown) =>
      error instanceof BesaRuntimeError &&
      error.reasonCode === "EXPIRY_CAPABILITY_NOT_ACTIVE",
  );
  assert.equal(called, false);
});

test("withBesa does not mislabel evidence-creation failure as handler failure", async () => {
  const fixture = setup();
  let calls = 0;
  const guarded = withBesa(
    {
      trustStore: fixture.trustStore,
      capability: fixture.resolveCapability,
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:deployment-gateway",
      clock: () => new Date(NOW),
    },
    async () => {
      calls += 1;
      return 1n;
    },
  );

  await assert.rejects(
    guarded(action()),
    (error: unknown) =>
      error instanceof BesaRuntimeError &&
      error.reasonCode === "EVIDENCE_CREATION_FAILED" &&
      error.evidence === undefined,
  );
  assert.equal(calls, 1);
  assert.equal(fixture.sink.records.length, 0);
});

test("withBesa rejects unsafe runtime configuration before execution", () => {
  const fixture = setup();
  const baseConfig = {
    trustStore: fixture.trustStore,
    capability: fixture.resolveCapability,
    replayStore: new InMemoryReplayStore(),
    replayRequirement: "enforce" as const,
    evidenceKeyPair: fixture.recorder,
    evidenceSink: fixture.sink,
    recorderId: "authority:evidence",
    executorId: "service:deployment-gateway",
    clock: () => new Date(NOW),
  };

  assert.throws(
    () => withBesa({ ...baseConfig, recorderId: "" }, async () => "unused"),
    /recorderId and executorId/,
  );
  assert.throws(
    () =>
      withBesa(
        { ...baseConfig, replayRequirement: "best-effort" as never },
        async () => "unused",
      ),
    /replayRequirement/,
  );
});
