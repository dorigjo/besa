import { test } from "node:test";
import assert from "node:assert/strict";
import type { ActionEnvelopeV1 } from "../action.js";
import {
  ACTION_POLICY_REASON,
  admitAction,
  validateActionPolicy,
  type ActionPolicyV1,
} from "../action-policy.js";

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
    requestHash: "f".repeat(64),
    scopes: ["deployment:write"],
    constraints: {
      environment: "staging",
      repository: "dorigjo/besa",
      riskScore: 25,
    },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "policy_0123456789abcdef",
    riskClass: "high",
    ...overrides,
  };
}

function policy(): ActionPolicyV1 {
  return {
    version: 1,
    policyId: "policy:deployment-v1",
    delegationRequired: false,
    rules: [
      {
        ruleId: "allow-staging-deploy",
        principals: ["principal:platform"],
        agents: ["agent:release"],
        tools: ["deployment.release"],
        operations: ["deploy"],
        resources: ["environment:staging"],
        allowedScopes: ["deployment:write"],
        maxRisk: "high",
        constraints: {
          exact: {
            environment: "staging",
            repository: "dorigjo/besa",
          },
          maximums: { riskScore: 50 },
        },
      },
    ],
  };
}

test("action policy allows an exact action deterministically", () => {
  const decision = admitAction(action(), policy(), NOW);

  assert.equal(validateActionPolicy(policy()).ok, true);
  assert.equal(decision.decision, "allow");
  assert.equal(decision.reasonCode, ACTION_POLICY_REASON.ALLOWED);
  assert.equal(decision.policyId, "policy:deployment-v1");
});

test("action policy returns stable denial categories", () => {
  assert.equal(
    admitAction(
      action({ principalId: "principal:attacker" }),
      policy(),
      NOW,
    ).reasonCode,
    ACTION_POLICY_REASON.PRINCIPAL_NOT_GRANTED,
  );
  assert.equal(
    admitAction(
      action({ resource: "environment:production" }),
      policy(),
      NOW,
    ).reasonCode,
    ACTION_POLICY_REASON.RESOURCE_NOT_GRANTED,
  );
  assert.equal(
    admitAction(
      action({
        constraints: {
          environment: "staging",
          repository: "dorigjo/besa",
          riskScore: 500,
        },
      }),
      policy(),
      NOW,
    ).reasonCode,
    ACTION_POLICY_REASON.CONSTRAINT_VIOLATION,
  );
});

test("action policy rejects unknown policy fields", () => {
  const invalid = { ...policy(), remoteCallback: "https://attacker.test" };
  const validation = validateActionPolicy(invalid);

  assert.equal(validation.ok, false);
  assert.equal(
    admitAction(action(), invalid, NOW).reasonCode,
    ACTION_POLICY_REASON.POLICY_INVALID,
  );
});
