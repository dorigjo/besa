import { test } from "node:test";
import assert from "node:assert/strict";
import { createEvidenceEnvelope } from "../evidence.js";
import { addTrustAnchor, emptyTrustStore } from "../trust.js";
import { GOLDEN_RECEIPT, GOLDEN_SIGNED_MANIFEST } from "./fixtures/golden-v1.js";

const FIXED_NOW = (): string => "2024-01-01T00:00:00.000Z";

function trustedGoldenKeyStore() {
  return addTrustAnchor(emptyTrustStore(), GOLDEN_SIGNED_MANIFEST.publicKey);
}

test("createEvidenceEnvelope reports valid verification for a trusted, matching pair", () => {
  const envelope = createEvidenceEnvelope(
    GOLDEN_SIGNED_MANIFEST,
    GOLDEN_RECEIPT,
    trustedGoldenKeyStore(),
    FIXED_NOW,
  );

  assert.equal(envelope.envelopeVersion, 1);
  assert.equal(envelope.generatedAt, "2024-01-01T00:00:00.000Z");
  assert.equal(envelope.subject.manifestHash, GOLDEN_RECEIPT.manifestHash);
  assert.equal(envelope.subject.receiptId, GOLDEN_RECEIPT.receiptId);
  assert.equal(envelope.provenance.serverName, GOLDEN_SIGNED_MANIFEST.manifest.serverName);
  assert.equal(envelope.verification.manifestTrusted, true);
  assert.equal(envelope.verification.receiptSignatureValid, true);
  assert.equal(envelope.verification.manifestHashMatch, true);
  assert.match(envelope.disclaimer, /not a compliance certification/);
});

test("createEvidenceEnvelope reports untrusted manifest instead of throwing", () => {
  const envelope = createEvidenceEnvelope(
    GOLDEN_SIGNED_MANIFEST,
    GOLDEN_RECEIPT,
    emptyTrustStore(),
    FIXED_NOW,
  );

  assert.equal(envelope.verification.manifestTrusted, false);
  assert.notEqual(envelope.verification.manifestReasonCode, "");
});

test("createEvidenceEnvelope reports a tampered receipt signature as invalid", () => {
  const tamperedReceipt = { ...GOLDEN_RECEIPT, toolName: "crm.delete" };
  const envelope = createEvidenceEnvelope(
    GOLDEN_SIGNED_MANIFEST,
    tamperedReceipt,
    trustedGoldenKeyStore(),
    FIXED_NOW,
  );

  assert.equal(envelope.verification.receiptSignatureValid, false);
});

test("createEvidenceEnvelope flags a manifestHash mismatch between receipt and manifest", () => {
  const mismatched = { ...GOLDEN_RECEIPT, manifestHash: "0".repeat(64) };
  const envelope = createEvidenceEnvelope(
    GOLDEN_SIGNED_MANIFEST,
    mismatched,
    trustedGoldenKeyStore(),
    FIXED_NOW,
  );

  assert.equal(envelope.verification.manifestHashMatch, false);
});
