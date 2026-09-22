import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  addTrustAnchor,
  checkActionEnvelope,
  emptyTrustStore,
  hashActionCapability,
  hashActionEnvelope,
  hashDelegation,
  InMemoryReplayStore,
  replayKey,
  validateActionCapability,
  verifyActionCapability,
  verifyActionDelegation,
  verifyActionEvidence,
  verifyDelegationChain,
} from "../sdk.js";

interface ConsequentialActionVector {
  issuerPublicKey: string;
  action: Record<string, unknown>;
  delegation: Record<string, unknown>;
  capability: Record<string, unknown>;
  evidence: Record<string, unknown>;
  executionResult: unknown;
}

interface NegativeVectorCase {
  id: string;
  target: "action" | "capability" | "delegation" | "runtime";
  mutation?: Record<string, unknown>;
  actionMutation?: Record<string, unknown>;
  at: string;
  expected: { valid: boolean; reasonCode: string };
}

const VECTOR = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL("../../conformance/consequential-action-v1.json", import.meta.url),
    ),
    "utf8",
  ),
) as ConsequentialActionVector;

const NEGATIVE = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL(
        "../../conformance/consequential-action-negative-v1.json",
        import.meta.url,
      ),
    ),
    "utf8",
  ),
) as { cases: NegativeVectorCase[] };

const AT = new Date("2030-01-01T00:00:03.000Z");
const TRUST = addTrustAnchor(
  emptyTrustStore(),
  VECTOR.issuerPublicKey,
  "2029-12-30T00:00:00.000Z",
);

test("published consequential-action v1 vector verifies end to end", () => {
  const action = checkActionEnvelope(VECTOR.action, AT);
  assert.equal(action.valid, true, action.detail);
  assert.ok(action.action);

  const chain = verifyDelegationChain([VECTOR.delegation], TRUST, AT);
  assert.equal(chain.valid, true, chain.detail);
  assert.equal(
    verifyActionDelegation([VECTOR.delegation], action.action, TRUST, AT).valid,
    true,
  );

  const capability = verifyActionCapability(VECTOR.capability, action.action, TRUST, AT);
  assert.equal(capability.valid, true, capability.detail);
  assert.equal(capability.authorized, true);

  const evidence = verifyActionEvidence(
    VECTOR.evidence,
    {
      action: action.action,
      capability: VECTOR.capability,
      result: VECTOR.executionResult,
      trustStore: TRUST,
      receiptHash: null,
    },
    AT,
  );
  assert.equal(evidence.valid, true, evidence.detail);
});

test("published consequential-action hashes remain frozen", () => {
  const action = checkActionEnvelope(VECTOR.action, AT);
  assert.equal(action.valid, true);
  assert.ok(action.action);
  assert.equal(
    hashActionEnvelope(action.action),
    "6fb383c582a2a0d95e0c6586fccb2891a5c716c4ec064dbcba5bb8fc6cc2a7a5",
  );

  const delegation = verifyDelegationChain([VECTOR.delegation], TRUST, AT);
  assert.equal(delegation.valid, true);
  assert.ok(delegation.leaf);
  assert.equal(
    hashDelegation(delegation.leaf),
    "7c98ba263832063ce13abf717163225e91f68ccc6d5ef2cd22177c314454da84",
  );

  const capability = validateActionCapability(VECTOR.capability);
  assert.equal(capability.ok, true);
  assert.ok(capability.capability);
  assert.equal(
    hashActionCapability(capability.capability),
    "5f51ebadec94808392ead60e82226f624dfa56138c739f8a2cc8b5c5750a6af3",
  );
});

test("consequential-action vector rejects resource and constraint substitution", () => {
  const changedResource = { ...VECTOR.action, resource: "payment:merchant-999" };
  const changedConstraints = {
    ...VECTOR.action,
    constraints: { amountEur: 10_000, merchantId: "merchant-123" },
  };

  assert.equal(
    verifyActionCapability(VECTOR.capability, changedResource, TRUST, AT).valid,
    false,
  );
  assert.equal(
    verifyActionCapability(VECTOR.capability, changedConstraints, TRUST, AT).valid,
    false,
  );
});

test("consequential-action vector rejects signature mutation, expiry, and unknown fields", () => {
  const signature = String(VECTOR.capability.signature);
  const corruptedCapability = {
    ...VECTOR.capability,
    signature: `${signature.slice(0, -2)}AA`,
  };
  assert.equal(
    verifyActionCapability(corruptedCapability, VECTOR.action, TRUST, AT).valid,
    false,
  );

  assert.equal(
    checkActionEnvelope(VECTOR.action, new Date("2030-01-02T00:00:00.000Z")).valid,
    false,
  );
  assert.equal(
    validateActionCapability({ ...VECTOR.capability, unexpected: true }).ok,
    false,
  );
});

test("published consequential-action negative vectors yield stable reason codes", async (t) => {
  for (const negative of NEGATIVE.cases) {
    await t.test(negative.id, async () => {
      const at = new Date(negative.at);
      if (negative.target === "action") {
        const result = checkActionEnvelope(
          { ...VECTOR.action, ...negative.mutation },
          at,
        );
        assert.equal(result.valid, negative.expected.valid);
        assert.equal(result.reasonCode, negative.expected.reasonCode);
        return;
      }

      if (negative.target === "capability") {
        const result = verifyActionCapability(
          { ...VECTOR.capability, ...negative.mutation },
          { ...VECTOR.action, ...negative.actionMutation },
          TRUST,
          at,
        );
        assert.equal(result.valid, negative.expected.valid);
        assert.equal(result.reasonCode, negative.expected.reasonCode);
        return;
      }

      if (negative.target === "delegation") {
        const action = { ...VECTOR.action, ...negative.actionMutation };
        const checkedAction = checkActionEnvelope(action, at);
        assert.equal(checkedAction.valid, true, checkedAction.detail);
        if (!checkedAction.action) throw new Error("negative vector action did not validate");
        const result = negative.mutation
          ? verifyDelegationChain([{ ...VECTOR.delegation, ...negative.mutation }], TRUST, at)
          : verifyActionDelegation([VECTOR.delegation], checkedAction.action, TRUST, at);
        assert.equal(result.valid, negative.expected.valid);
        assert.equal(result.reasonCode, negative.expected.reasonCode);
        return;
      }

      const checked = checkActionEnvelope(VECTOR.action, at);
      assert.equal(checked.valid, true);
      if (!checked.action || !checked.actionHash) {
        throw new Error("published action did not validate");
      }
      const store = new InMemoryReplayStore();
      const key = replayKey(checked.actionHash, checked.action.nonce);
      assert.equal((await store.consume(key, checked.action.expiresAt, at)).status, "consumed");
      const replay = await store.consume(key, checked.action.expiresAt, at);
      assert.equal(replay.status, "replay");
      assert.equal(replay.reasonCode, negative.expected.reasonCode);
    });
  }
});
