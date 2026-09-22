import { test } from "node:test";
import assert from "node:assert/strict";
import type { ActionEnvelopeV1 } from "../action.js";
import {
  CAPABILITY_REASON,
  createActionCapability,
  verifyActionCapability,
} from "../action-capability.js";
import { generateKeyPair, publicKeyId } from "../crypto.js";
import { addTrustAnchor, emptyTrustStore } from "../trust.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");

function action(overrides: Partial<ActionEnvelopeV1> = {}): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:finance",
    agentId: "agent:payments",
    authority: "iam:example:payment-operators",
    tool: "payments.transfer",
    operation: "transfer",
    resource: "account:merchant-123",
    requestHash: "b".repeat(64),
    scopes: ["payments:write"],
    constraints: { amount: 100, currency: "EUR", recipient: "merchant-123" },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "payment_0123456789abcdef",
    riskClass: "high",
    ...overrides,
  };
}

function trustedIssuer() {
  const keypair = generateKeyPair();
  const trustStore = addTrustAnchor(
    emptyTrustStore(),
    keypair.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );
  return { keypair, trustStore };
}

test("an action capability authorizes only its exact action", () => {
  const issuer = trustedIssuer();
  const requested = action();
  const capability = createActionCapability(
    {
      action: requested,
      decision: "allow",
      reasonCode: "ACTION_ALLOWED",
      policyId: "policy:payments-v1",
      delegationChainHash: null,
      issuerId: "authority:besa",
      issuedAt: NOW.toISOString(),
    },
    issuer.keypair,
  );

  const result = verifyActionCapability(
    capability,
    requested,
    issuer.trustStore,
    NOW,
  );
  assert.equal(result.valid, true, result.detail);
  assert.equal(result.authorized, true);
  assert.equal(result.reasonCode, CAPABILITY_REASON.VALID);

  for (const mutated of [
    action({ resource: "account:attacker" }),
    action({ constraints: { amount: 10_000, currency: "EUR", recipient: "merchant-123" } }),
    action({ nonce: "payment_abcdef0123456789" }),
  ]) {
    assert.equal(
      verifyActionCapability(capability, mutated, issuer.trustStore, NOW).reasonCode,
      CAPABILITY_REASON.ACTION_MISMATCH,
    );
  }
});

test("an action capability fails closed for an untrusted issuer", () => {
  const issuer = trustedIssuer();
  const capability = createActionCapability(
    {
      action: action(),
      decision: "allow",
      reasonCode: "ACTION_ALLOWED",
      policyId: "policy:payments-v1",
      delegationChainHash: null,
      issuerId: "authority:besa",
      issuedAt: NOW.toISOString(),
    },
    issuer.keypair,
  );

  assert.equal(
    verifyActionCapability(capability, action(), emptyTrustStore(), NOW).reasonCode,
    CAPABILITY_REASON.ISSUER_UNTRUSTED,
  );
});

test("a signed deny decision verifies but never authorizes execution", () => {
  const issuer = trustedIssuer();
  const requested = action();
  const capability = createActionCapability(
    {
      action: requested,
      decision: "deny",
      reasonCode: "CONSTRAINT_AMOUNT_EXCEEDED",
      policyId: "policy:payments-v1",
      delegationChainHash: null,
      issuerId: "authority:besa",
      issuedAt: NOW.toISOString(),
    },
    issuer.keypair,
  );

  const result = verifyActionCapability(
    capability,
    requested,
    issuer.trustStore,
    NOW,
  );
  assert.equal(result.valid, true, result.detail);
  assert.equal(result.authorized, false);
});

test("capability schema rejects base64 key bytes that are not Ed25519 SPKI", () => {
  const issuer = trustedIssuer();
  const capability = createActionCapability(
    {
      action: action(),
      decision: "allow",
      reasonCode: "ACTION_ALLOWED",
      policyId: "policy:payments-v1",
      delegationChainHash: null,
      issuerId: "authority:besa",
      issuedAt: NOW.toISOString(),
    },
    issuer.keypair,
  );
  const notAKey = Buffer.from("not-an-ed25519-spki", "utf8").toString("base64");

  const result = verifyActionCapability(
    {
      ...capability,
      issuerPublicKey: notAKey,
      issuerPublicKeyId: publicKeyId(notAKey),
    },
    action(),
    issuer.trustStore,
    NOW,
  );

  assert.equal(result.reasonCode, CAPABILITY_REASON.INVALID);
});
