import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../crypto.js";
import {
  createAdmissionAttestation,
  validateAdmissionAttestation,
  verifyAdmissionAttestationDetailed,
} from "../attestation.js";
import { GOLDEN_MANIFEST_HASH } from "./fixtures/golden-v1.js";

function baseInput() {
  return {
    manifestHash: GOLDEN_MANIFEST_HASH,
    toolName: "crm.lookup",
    decision: "allow" as const,
    reasonCode: "ALLOWED",
    detail: "tool call admitted",
    meterCountAtCheck: 3,
  };
}

test("createAdmissionAttestation produces a shape that validates and verifies", () => {
  const keypair = generateKeyPair();
  const attestation = createAdmissionAttestation(baseInput(), keypair);

  const shapeCheck = validateAdmissionAttestation(attestation);
  assert.equal(shapeCheck.ok, true);

  const verification = verifyAdmissionAttestationDetailed(attestation, keypair.publicKeyDer);
  assert.deepEqual(verification, {
    valid: true,
    reasonCode: "OK",
    detail: "admission attestation signature is valid",
  });
});

test("attestationId is att_ prefixed and unique per call", () => {
  const keypair = generateKeyPair();
  const first = createAdmissionAttestation(baseInput(), keypair);
  const second = createAdmissionAttestation(baseInput(), keypair);

  assert.match(first.attestationId, /^att_[0-9a-f-]{36}$/);
  assert.notEqual(first.attestationId, second.attestationId);
});

test("verification fails closed against the wrong public key", () => {
  const keypair = generateKeyPair();
  const attestation = createAdmissionAttestation(baseInput(), keypair);
  const wrongKey = generateKeyPair().publicKeyDer;

  const verification = verifyAdmissionAttestationDetailed(attestation, wrongKey);
  assert.equal(verification.valid, false);
  assert.equal(verification.reasonCode, "E_PUBLIC_KEY_ID_MISMATCH");
});

test("tampering with any signed field invalidates the attestation", () => {
  const keypair = generateKeyPair();
  const attestation = createAdmissionAttestation(baseInput(), keypair);

  const tamperedDecision = { ...attestation, decision: "deny" as const, reasonCode: "TOOL_NOT_FOUND" };
  const decisionResult = verifyAdmissionAttestationDetailed(tamperedDecision, keypair.publicKeyDer);
  assert.equal(decisionResult.valid, false);

  const tamperedCount = { ...attestation, meterCountAtCheck: attestation.meterCountAtCheck + 1 };
  const countResult = verifyAdmissionAttestationDetailed(tamperedCount, keypair.publicKeyDer);
  assert.equal(countResult.valid, false);
});

test("deny attestations reject reasonCode ALLOWED, allow attestations require it", () => {
  const keypair = generateKeyPair();

  assert.throws(() =>
    createAdmissionAttestation(
      { ...baseInput(), decision: "deny", reasonCode: "ALLOWED" },
      keypair,
    ),
  );

  assert.throws(() =>
    createAdmissionAttestation(
      { ...baseInput(), decision: "allow", reasonCode: "TOOL_NOT_FOUND" },
      keypair,
    ),
  );
});

test("validateAdmissionAttestation rejects an unexpected extra field", () => {
  const keypair = generateKeyPair();
  const attestation = createAdmissionAttestation(baseInput(), keypair);
  const withExtra = { ...attestation, extra: "field" };

  const result = validateAdmissionAttestation(withExtra);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes("extra")));
});

test("validateAdmissionAttestation rejects a negative meterCountAtCheck", () => {
  const keypair = generateKeyPair();
  const attestation = createAdmissionAttestation(baseInput(), keypair);
  const negative = { ...attestation, meterCountAtCheck: -1 };

  const result = validateAdmissionAttestation(negative);
  assert.equal(result.ok, false);
});
