import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonicalize,
  hashActionEnvelope,
  hashRequest,
  validateActionEnvelope,
  type ActionEnvelopeV1,
  type JsonObject,
} from "../sdk.js";

const FUTURE = "2030-01-02T00:00:00.000Z";

function action(overrides: Partial<ActionEnvelopeV1> = {}): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:fuzz",
    agentId: "agent:fuzz",
    authority: "authority:fuzz",
    tool: "deploy.release",
    operation: "deploy",
    resource: "environment:staging",
    requestHash: hashRequest({ commit: "abc123", environment: "staging" }),
    scopes: ["deploy:write"],
    constraints: { commit: "abc123", environment: "staging" },
    expiresAt: FUTURE,
    nonce: "fuzz_nonce_00000001",
    riskClass: "medium",
    ...overrides,
  };
}

function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    return state;
  };
}

function nestedConstraint(depth: number): JsonObject {
  let result: JsonObject = { leaf: "value" };
  for (let index = 0; index < depth; index += 1) {
    result = { [`level${String(index)}`]: result };
  }
  return result;
}

test("action-envelope fuzz parsing is deterministic and fails closed", () => {
  const next = prng(0xBE5A11);
  const malformed: unknown[] = [
    null,
    true,
    42,
    "action",
    [],
    { ...action(), unexpected: true },
    { ...action(), constraints: nestedConstraint(128) },
    { ...action(), constraints: { oversized: "x".repeat(16_385) } },
    { ...action(), agentId: "agent:e\u0301" },
    { ...action(), nonce: "too-short" },
    { ...action(), requestHash: "A".repeat(64) },
    { ...action(), scopes: ["deploy:write", "deploy:write"] },
  ];

  for (let index = 0; index < 256; index += 1) {
    const candidate = {
      ...action(),
      constraints: {
        value: next(),
        text: `fuzz-${String(next())}`,
      },
      nonce: `fuzz_nonce_${String(next()).padStart(10, "0")}`,
    };
    malformed.push(index % 2 === 0 ? candidate : { ...candidate, unexpected: index });
  }

  for (const candidate of malformed) {
    const first = validateActionEnvelope(candidate);
    const second = validateActionEnvelope(candidate);
    assert.deepEqual(second, first);
    assert.equal(typeof first.ok, "boolean");
    assert.ok(first.errors.length >= 0);
  }
});

test("accepted security-relevant action mutations change the action hash", () => {
  const base = action();
  const baseHash = hashActionEnvelope(base);
  const mutations: ActionEnvelopeV1[] = [
    action({ principalId: "principal:other" }),
    action({ agentId: "agent:other" }),
    action({ authority: "authority:other" }),
    action({ tool: "deploy.rollback" }),
    action({ operation: "rollback" }),
    action({ resource: "environment:production" }),
    action({ requestHash: hashRequest({ commit: "def456", environment: "staging" }) }),
    action({ scopes: ["deploy:admin"] }),
    action({ constraints: { commit: "def456", environment: "staging" } }),
    action({ expiresAt: "2030-01-02T00:00:01.000Z" }),
    action({ nonce: "fuzz_nonce_00000002" }),
    action({ riskClass: "high" }),
    action({ contextHash: hashRequest({ correlation: "fuzz-1" }) }),
  ];

  for (const candidate of mutations) {
    const validation = validateActionEnvelope(candidate);
    assert.equal(validation.ok, true, validation.errors.join("; "));
    assert.ok(validation.action);
    assert.notEqual(hashActionEnvelope(validation.action), baseHash);
  }
});

test("canonical action input rejects non-finite values before hashing", () => {
  for (const value of [NaN, Infinity, -Infinity]) {
    const result = validateActionEnvelope(action({ constraints: { amount: value } }));
    assert.equal(result.ok, false);
    assert.throws(() => canonicalize({ value }));
  }
});
