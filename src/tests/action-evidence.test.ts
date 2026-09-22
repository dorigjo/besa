import { test } from "node:test";
import assert from "node:assert/strict";
import type { ActionEnvelopeV1 } from "../action.js";
import { createActionCapability } from "../action-capability.js";
import {
  EVIDENCE_REASON,
  createActionEvidence,
  verifyActionEvidence,
} from "../action-evidence.js";
import { generateKeyPair, publicKeyId } from "../crypto.js";
import { addTrustAnchor, emptyTrustStore } from "../trust.js";

const VERIFY_AT = new Date("2026-09-21T12:01:00.000Z");

function action(overrides: Partial<ActionEnvelopeV1> = {}): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:database",
    agentId: "agent:maintenance",
    authority: "iam:example:database-operators",
    tool: "database.execute",
    operation: "delete",
    resource: "database:staging/orders",
    requestHash: "c".repeat(64),
    scopes: ["database:write"],
    constraints: { maxRows: 10, whereHash: "d".repeat(64) },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "database_0123456789abcdef",
    riskClass: "high",
    ...overrides,
  };
}

function setup() {
  const authority = generateKeyPair();
  const recorder = generateKeyPair();
  const requested = action();
  const capability = createActionCapability(
    {
      action: requested,
      decision: "allow",
      reasonCode: "ACTION_ALLOWED",
      policyId: "policy:database-v1",
      delegationChainHash: null,
      issuerId: "authority:admission",
      issuedAt: "2026-09-21T12:00:00.000Z",
    },
    authority,
  );
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
  const result = { deletedRows: 4, transactionId: "tx-123" };
  const evidence = createActionEvidence(
    {
      action: requested,
      capability,
      result,
      outcome: "succeeded",
      executorId: "service:database-gateway",
      recorderId: "authority:evidence",
      receiptHash: null,
      startedAt: "2026-09-21T12:00:05.000Z",
      completedAt: "2026-09-21T12:00:06.000Z",
      recordedAt: "2026-09-21T12:00:07.000Z",
    },
    recorder,
  );
  return { capability, evidence, requested, result, trustStore };
}

test("action evidence links an authorized action to supplied execution evidence", () => {
  const fixture = setup();
  const result = verifyActionEvidence(
    fixture.evidence,
    {
      action: fixture.requested,
      capability: fixture.capability,
      result: fixture.result,
      trustStore: fixture.trustStore,
    },
    VERIFY_AT,
  );

  assert.equal(result.valid, true, result.detail);
  assert.equal(result.reasonCode, EVIDENCE_REASON.VALID);
});

test("action evidence rejects substituted action or result data", () => {
  const fixture = setup();

  assert.equal(
    verifyActionEvidence(
      fixture.evidence,
      {
        action: action({ resource: "database:production/orders" }),
        capability: fixture.capability,
        result: fixture.result,
        trustStore: fixture.trustStore,
      },
      VERIFY_AT,
    ).reasonCode,
    EVIDENCE_REASON.LINK_MISMATCH,
  );
  assert.equal(
    verifyActionEvidence(
      fixture.evidence,
      {
        action: fixture.requested,
        capability: fixture.capability,
        result: { deletedRows: 400, transactionId: "tx-123" },
        trustStore: fixture.trustStore,
      },
      VERIFY_AT,
    ).reasonCode,
    EVIDENCE_REASON.LINK_MISMATCH,
  );
});

test("action evidence rejects mutation of a signed field", () => {
  const fixture = setup();
  const tampered = { ...fixture.evidence, executorId: "service:attacker" };

  assert.equal(
    verifyActionEvidence(
      tampered,
      {
        action: fixture.requested,
        capability: fixture.capability,
        result: fixture.result,
        trustStore: fixture.trustStore,
      },
      VERIFY_AT,
    ).reasonCode,
    EVIDENCE_REASON.SIGNATURE_INVALID,
  );
});

test("evidence schema rejects base64 key bytes that are not Ed25519 SPKI", () => {
  const fixture = setup();
  const notAKey = Buffer.from("not-an-ed25519-spki", "utf8").toString("base64");

  const result = verifyActionEvidence(
    {
      ...fixture.evidence,
      recorderPublicKey: notAKey,
      recorderPublicKeyId: publicKeyId(notAKey),
    },
    {
      action: fixture.requested,
      capability: fixture.capability,
      result: fixture.result,
      trustStore: fixture.trustStore,
    },
    VERIFY_AT,
  );

  assert.equal(result.reasonCode, EVIDENCE_REASON.INVALID);
});
