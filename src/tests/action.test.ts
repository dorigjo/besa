import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ACTION_REASON,
  checkActionEnvelope,
  hashActionEnvelope,
  validateActionEnvelope,
  type ActionEnvelopeV1,
} from "../action.js";

function action(overrides: Partial<ActionEnvelopeV1> = {}): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:operations",
    agentId: "agent:deploy",
    authority: "iam:example:production-deployers",
    tool: "deploy.release",
    operation: "deploy",
    resource: "environment:production",
    requestHash: "a".repeat(64),
    scopes: ["deploy:write"],
    constraints: {
      commit: "abc123",
      maxRisk: "medium",
    },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "nonce_0123456789abcdef",
    riskClass: "high",
    ...overrides,
  };
}

test("action envelopes validate and hash deterministically", () => {
  const first = action({
    constraints: { commit: "abc123", maxRisk: "medium" },
  });
  const second = action({
    constraints: { maxRisk: "medium", commit: "abc123" },
  });

  assert.equal(validateActionEnvelope(first).ok, true);
  assert.equal(hashActionEnvelope(first), hashActionEnvelope(second));
  assert.match(hashActionEnvelope(first), /^[a-f0-9]{64}$/);
});

test("security-relevant action mutations change the action hash", () => {
  const original = action();

  assert.notEqual(
    hashActionEnvelope(original),
    hashActionEnvelope(action({ resource: "environment:staging" })),
  );
  assert.notEqual(
    hashActionEnvelope(original),
    hashActionEnvelope(
      action({ constraints: { commit: "def456", maxRisk: "medium" } }),
    ),
  );
});

test("action validation rejects unknown fields and ambiguous text", () => {
  const withUnknown = { ...action(), extension: true };
  const withNonNfc = action({ resource: "resource:e\u0301" });
  const withBadNonce = action({ nonce: "short" });

  assert.equal(validateActionEnvelope(withUnknown).ok, false);
  assert.equal(validateActionEnvelope(withNonNfc).ok, false);
  assert.equal(validateActionEnvelope(withBadNonce).ok, false);
});

test("action scope ordering is deterministic and locale independent", () => {
  assert.equal(
    validateActionEnvelope(action({ scopes: ["scope:z", "scope:ä"] })).ok,
    true,
  );
  assert.equal(
    validateActionEnvelope(action({ scopes: ["scope:ä", "scope:z"] })).ok,
    false,
  );
});

test("action checks reject expired envelopes with a stable reason code", () => {
  const result = checkActionEnvelope(
    action(),
    new Date("2026-09-21T12:05:00.001Z"),
  );

  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, ACTION_REASON.EXPIRED);
});
