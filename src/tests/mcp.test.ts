import { test } from "node:test";
import assert from "node:assert/strict";
import type { ActionEnvelopeV1 } from "../action.js";
import { createActionCapability } from "../action-capability.js";
import { generateKeyPair } from "../crypto.js";
import { hashRequest } from "../signing.js";
import { InMemoryReplayStore } from "../replay.js";
import {
  BesaMcpError,
  withBesaMcp,
  type McpToolCall,
} from "../mcp.js";
import type { EvidenceSink, RuntimeEvidenceRecordV1 } from "../runtime.js";
import { addTrustAnchor, emptyTrustStore } from "../trust.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");

class MemorySink implements EvidenceSink {
  readonly records: RuntimeEvidenceRecordV1[] = [];
  async append(record: RuntimeEvidenceRecordV1): Promise<void> {
    this.records.push(record);
  }
}

function actionForCall(call: McpToolCall): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:platform",
    agentId: "agent:mcp",
    authority: "mcp-auth:session-123",
    tool: call.name,
    operation: "delete",
    resource: "database:staging/orders",
    requestHash: hashRequest(call.arguments),
    scopes: ["database:write"],
    constraints: { maxRows: 10 },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "mcp_0123456789abcdef",
    riskClass: "high",
  };
}

function setup() {
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
  const sink = new MemorySink();
  return { authority, recorder, trustStore, sink };
}

test("MCP middleware admits and records an exact tool call", async () => {
  const fixture = setup();
  let calls = 0;
  const guarded = withBesaMcp(
    {
      trustStore: fixture.trustStore,
      capability: (action) =>
        createActionCapability(
          {
            action,
            decision: "allow",
            reasonCode: "ACTION_ALLOWED",
            policyId: "policy:mcp-v1",
            delegationChainHash: null,
            issuerId: "authority:mcp",
            issuedAt: NOW.toISOString(),
          },
          fixture.authority,
        ),
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:mcp-tool-server",
      clock: () => new Date(NOW),
      actionForCall,
    },
    async (call) => {
      calls += 1;
      return { tool: call.name, deletedRows: 2 };
    },
  );

  const execution = await guarded({ name: "database.delete", arguments: { where: "id=1" } });
  assert.equal(calls, 1);
  assert.equal(execution.evidence.outcome, "succeeded");
  assert.equal(fixture.sink.records.length, 1);
});

test("MCP middleware blocks tool and parameter substitution before execution", async () => {
  const fixture = setup();
  let calls = 0;
  const original: McpToolCall = { name: "database.delete", arguments: { where: "id=1" } };
  const guarded = withBesaMcp(
    {
      trustStore: fixture.trustStore,
      capability: (action) =>
        createActionCapability(
          {
            action,
            decision: "allow",
            reasonCode: "ACTION_ALLOWED",
            policyId: "policy:mcp-v1",
            delegationChainHash: null,
            issuerId: "authority:mcp",
            issuedAt: NOW.toISOString(),
          },
          fixture.authority,
        ),
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:mcp-tool-server",
      clock: () => new Date(NOW),
      actionForCall: () => actionForCall(original),
    },
    async () => {
      calls += 1;
      return "should-not-run";
    },
  );

  await assert.rejects(
    guarded({ name: "database.drop", arguments: original.arguments }),
    (error: unknown) =>
      error instanceof BesaMcpError && error.reasonCode === "ACTION_TOOL_MISMATCH",
  );
  await assert.rejects(
    guarded({ name: original.name, arguments: { where: "id > 0" } }),
    (error: unknown) =>
      error instanceof BesaMcpError && error.reasonCode === "ACTION_REQUEST_MISMATCH",
  );
  assert.equal(calls, 0);
});

test("MCP middleware rejects malformed call objects before mapping or execution", async () => {
  const fixture = setup();
  let calls = 0;
  const guarded = withBesaMcp(
    {
      trustStore: fixture.trustStore,
      capability: (action) =>
        createActionCapability(
          {
            action,
            decision: "allow",
            reasonCode: "ACTION_ALLOWED",
            policyId: "policy:mcp-v1",
            delegationChainHash: null,
            issuerId: "authority:mcp",
            issuedAt: NOW.toISOString(),
          },
          fixture.authority,
        ),
      replayStore: new InMemoryReplayStore(),
      replayRequirement: "enforce",
      evidenceKeyPair: fixture.recorder,
      evidenceSink: fixture.sink,
      recorderId: "authority:evidence",
      executorId: "service:mcp-tool-server",
      clock: () => new Date(NOW),
      actionForCall,
    },
    async () => {
      calls += 1;
      return "must-not-run";
    },
  );

  for (const invalid of [null, { name: "database.delete" }]) {
    await assert.rejects(
      guarded(invalid as never),
      (error: unknown) =>
        error instanceof BesaMcpError &&
        error.reasonCode === "SCHEMA_MCP_CALL_INVALID",
    );
  }
  assert.equal(calls, 0);
});
