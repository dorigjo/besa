import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../crypto.js";
import { loadManifest } from "../manifest.js";
import { LocalKeyProvider } from "../keys/local-provider.js";
import {
  GOLDEN_RECEIPT,
  GOLDEN_SIGNED_MANIFEST,
} from "./fixtures/golden-v1.js";
import {
  createReceipt,
  createReceiptWithProvider,
  signManifest,
  signManifestWithProvider,
  verifyReceipt,
  verifySignedManifest,
} from "../signing.js";

const MANIFEST_PATH = new URL(
  "../../examples/manifest.yaml",
  import.meta.url,
).pathname.replace(/^\/([A-Za-z]:)/, "$1");

// Test 1: legacy signManifest(KeyPair) and signManifestWithProvider(LocalKeyProvider)
// must be structurally identical — same shape, same canonicalization, same hash,
// differing only in the fields that are inherently per-call (signedAt, signature).
test("signManifestWithProvider is structurally identical to signManifest for the same key", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);
  const manifest = loadManifest(MANIFEST_PATH);

  const legacy = signManifest(manifest, keypair);
  const viaProvider = await signManifestWithProvider(manifest, provider);

  assert.equal(viaProvider.artifactVersion, legacy.artifactVersion);
  assert.deepEqual(viaProvider.manifest, legacy.manifest);
  assert.equal(viaProvider.manifestHash, legacy.manifestHash);
  assert.equal(viaProvider.algorithm, legacy.algorithm);
  assert.equal(viaProvider.publicKey, legacy.publicKey);
  assert.equal(viaProvider.publicKeyId, legacy.publicKeyId);
  // signedAt and signature legitimately differ per call (fresh timestamp,
  // fresh signature over that timestamp) — exactly as two consecutive
  // signManifest() calls with the same keypair would also differ.
  assert.equal(typeof viaProvider.signedAt, "string");
  assert.equal(typeof viaProvider.signature, "string");
});

// Test 2: legacy createReceipt(KeyPair) and createReceiptWithProvider(provider)
// must be structurally identical under the same validation rules and inputs.
test("createReceiptWithProvider is structurally identical to createReceipt for the same key", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);
  const input = {
    manifestHash:
      "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504",
    toolName: "crm.lookup",
    decision: "allow" as const,
    reasonCode: "ALLOWED",
    request: { customerId: "cust_0001" },
  };

  const legacy = createReceipt(input, keypair);
  const viaProvider = await createReceiptWithProvider(input, provider);

  assert.equal(viaProvider.artifactVersion, legacy.artifactVersion);
  assert.equal(viaProvider.manifestHash, legacy.manifestHash);
  assert.equal(viaProvider.toolName, legacy.toolName);
  assert.equal(viaProvider.decision, legacy.decision);
  assert.equal(viaProvider.reasonCode, legacy.reasonCode);
  assert.equal(viaProvider.requestHash, legacy.requestHash);
  assert.equal(viaProvider.publicKeyId, legacy.publicKeyId);
  assert.equal(viaProvider.algorithm, legacy.algorithm);
  // receiptId/timestamp/signature are freshly generated per call by design —
  // same as two consecutive createReceipt() calls with the same keypair.
  assert.match(viaProvider.receiptId, /^rcpt_[0-9a-f-]{36}$/);
  assert.notEqual(viaProvider.receiptId, legacy.receiptId);
});

// Test 3: verifySignedManifest() must accept a manifest signed via the
// provider-native path exactly as it accepts one signed via the legacy path.
test("verifySignedManifest accepts a manifest signed via signManifestWithProvider", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, provider);

  assert.deepEqual(verifySignedManifest(signed), {
    valid: true,
    reasonCode: "OK",
    detail: "manifest signature is valid",
  });
});

// Test 4: verifyReceipt() must accept a receipt signed via the provider-native
// path exactly as it accepts one signed via the legacy path.
test("verifyReceipt accepts a receipt signed via createReceiptWithProvider", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);

  const receipt = await createReceiptWithProvider(
    {
      manifestHash:
        "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504",
      toolName: "crm.lookup",
      decision: "allow",
      reasonCode: "ALLOWED",
      request: { customerId: "cust_0001" },
    },
    provider,
  );

  assert.equal(verifyReceipt(receipt, keypair.publicKeyDer), true);
});

// Test 5: the Phase-1 golden vectors — signed under the legacy synchronous
// path before this refactor existed — must still verify unchanged. This is
// the guarantee that the internal signWithKeyPair/buildManifestBody/
// buildReceiptBody refactor did not alter canonicalization, hashing, or the
// signature domain for any existing artifact.
test("golden vectors still verify after the provider-native signing refactor", () => {
  assert.equal(verifySignedManifest(GOLDEN_SIGNED_MANIFEST).valid, true);
  assert.equal(
    verifyReceipt(GOLDEN_RECEIPT, GOLDEN_SIGNED_MANIFEST.publicKey),
    true,
  );
});
