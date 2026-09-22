import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../crypto.js";
import { addTrustAnchor, emptyTrustStore } from "../trust.js";
import type { ActionEnvelopeV1 } from "../action.js";
import {
  DELEGATION_REASON,
  createDelegation,
  hashDelegation,
  verifyActionDelegation,
  verifyDelegationChain,
  type CreateDelegationInput,
  type DelegationV1,
} from "../delegation.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");

function action(overrides: Partial<ActionEnvelopeV1> = {}): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:operations",
    agentId: "agent:deploy",
    authority: "iam:example:deployment",
    tool: "deploy.release",
    operation: "deploy",
    resource: "environment:staging",
    requestHash: "a".repeat(64),
    scopes: ["deploy:write"],
    constraints: {
      environment: "staging",
      repository: "dorigjo/besa",
      riskScore: 20,
    },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "delegate_0123456789abcdef",
    riskClass: "high",
    ...overrides,
  };
}

function rootInput(subjectPublicKey: string): CreateDelegationInput {
  return {
    issuerId: "principal:operations",
    subjectId: "service:deployment",
    subjectPublicKey,
    allowedOperations: ["deploy"],
    allowedResources: ["environment:production", "environment:staging"],
    scopes: ["deploy:write"],
    constraints: {
      exact: { repository: "dorigjo/besa" },
      maximums: { riskScore: 80 },
    },
    issuedAt: "2026-09-21T11:55:00.000Z",
    notBefore: "2026-09-21T11:55:00.000Z",
    expiresAt: "2026-09-21T12:30:00.000Z",
    parentDelegationHash: null,
  };
}

function childInput(
  subjectPublicKey: string,
  parent: DelegationV1,
): CreateDelegationInput {
  return {
    issuerId: parent.subjectId,
    subjectId: "agent:deploy",
    subjectPublicKey,
    allowedOperations: ["deploy"],
    allowedResources: ["environment:staging"],
    scopes: ["deploy:write"],
    constraints: {
      exact: { repository: "dorigjo/besa", environment: "staging" },
      maximums: { riskScore: 40 },
    },
    issuedAt: "2026-09-21T11:56:00.000Z",
    notBefore: "2026-09-21T11:56:00.000Z",
    expiresAt: "2026-09-21T12:10:00.000Z",
    parentDelegationHash: hashDelegation(parent),
  };
}

test("a narrowed delegation chain verifies from a trusted root", () => {
  const principal = generateKeyPair();
  const service = generateKeyPair();
  const agent = generateKeyPair();
  const root = createDelegation(rootInput(service.publicKeyDer), principal);
  const child = createDelegation(childInput(agent.publicKeyDer, root), service);
  const trust = addTrustAnchor(
    emptyTrustStore(),
    principal.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );

  const result = verifyDelegationChain([root, child], trust, NOW);
  assert.equal(result.valid, true, result.detail);
  assert.equal(result.reasonCode, DELEGATION_REASON.VALID);
  assert.equal(result.leaf?.subjectId, "agent:deploy");
});

test("a delegation chain authorizes only its exact bounded action", () => {
  const principal = generateKeyPair();
  const service = generateKeyPair();
  const agent = generateKeyPair();
  const root = createDelegation(rootInput(service.publicKeyDer), principal);
  const child = createDelegation(childInput(agent.publicKeyDer, root), service);
  const trust = addTrustAnchor(
    emptyTrustStore(),
    principal.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );

  assert.equal(
    verifyActionDelegation([root, child], action(), trust, NOW).valid,
    true,
  );
  assert.equal(
    verifyActionDelegation(
      [root, child],
      action({ resource: "environment:production" }),
      trust,
      NOW,
    ).reasonCode,
    DELEGATION_REASON.ACTION_NOT_GRANTED,
  );
});

test("a child delegation cannot broaden resources or numeric maximums", () => {
  const principal = generateKeyPair();
  const service = generateKeyPair();
  const agent = generateKeyPair();
  const root = createDelegation(rootInput(service.publicKeyDer), principal);
  const trust = addTrustAnchor(
    emptyTrustStore(),
    principal.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );

  const broaderResource = createDelegation(
    {
      ...childInput(agent.publicKeyDer, root),
      allowedResources: ["environment:development", "environment:staging"],
    },
    service,
  );
  const broaderMaximum = createDelegation(
    {
      ...childInput(agent.publicKeyDer, root),
      constraints: {
        exact: { repository: "dorigjo/besa" },
        maximums: { riskScore: 90 },
      },
    },
    service,
  );

  assert.equal(
    verifyDelegationChain([root, broaderResource], trust, NOW).reasonCode,
    DELEGATION_REASON.WIDENING,
  );
  assert.equal(
    verifyDelegationChain([root, broaderMaximum], trust, NOW).reasonCode,
    DELEGATION_REASON.WIDENING,
  );
});

test("delegation verification rejects tampering and an untrusted root", () => {
  const principal = generateKeyPair();
  const service = generateKeyPair();
  const root = createDelegation(rootInput(service.publicKeyDer), principal);
  const tampered = { ...root, subjectId: "service:attacker" };

  assert.equal(
    verifyDelegationChain([tampered], addTrustAnchor(emptyTrustStore(), principal.publicKeyDer, NOW.toISOString()), NOW).reasonCode,
    DELEGATION_REASON.SIGNATURE_INVALID,
  );
  assert.equal(
    verifyDelegationChain([root], emptyTrustStore(), NOW).reasonCode,
    DELEGATION_REASON.ROOT_UNTRUSTED,
  );
});

test("delegation creation rejects canonical base64 that is not an Ed25519 key", () => {
  const principal = generateKeyPair();
  const notAKey = Buffer.from("not-an-ed25519-spki", "utf8").toString("base64");

  assert.throws(
    () => createDelegation(rootInput(notAKey), principal),
    /canonical Ed25519 public key/,
  );
});

test("delegation verification rejects chains above the bounded length", () => {
  const principal = generateKeyPair();
  const service = generateKeyPair();
  const root = createDelegation(rootInput(service.publicKeyDer), principal);
  const trust = addTrustAnchor(
    emptyTrustStore(),
    principal.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );

  const result = verifyDelegationChain(
    Array.from({ length: 65 }, () => root),
    trust,
    NOW,
  );

  assert.equal(result.reasonCode, DELEGATION_REASON.INVALID);
});
