import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, publicKeyId } from "../crypto.js";
import { loadManifest } from "../manifest.js";
import { LocalKeyProvider } from "../keys/local-provider.js";
import type { KeyProvider } from "../keys/provider.js";
import {
  createReceiptWithProvider,
  signManifestWithProvider,
  verifyReceipt,
  verifySignedManifest,
} from "../signing.js";

const MANIFEST_PATH = new URL(
  "../../examples/manifest.yaml",
  import.meta.url,
).pathname.replace(/^\/([A-Za-z]:)/, "$1");

// A minimal KeyProvider double whose getKeyId() lies about the key it
// actually signs with — used to prove that verification catches an
// inconsistent identity claim rather than trusting whatever a provider
// self-reports. No production code constructs a provider like this; it
// exists only to exercise the fail-closed path.
function mismatchedIdentityProvider(real: KeyProvider, fakeKeyId: string): KeyProvider {
  return {
    getPublicKey: () => real.getPublicKey(),
    getKeyId: () => Promise.resolve(fakeKeyId),
    sign: (payload) => real.sign(payload),
  };
}

test("verifySignedManifest fails closed against the wrong public key", async () => {
  const signerKeypair = generateKeyPair();
  const otherKeypair = generateKeyPair();
  const provider = new LocalKeyProvider(signerKeypair);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, provider);
  // Swap in an unrelated public key while keeping the original signature —
  // this must fail, not silently verify against the wrong key.
  const tampered = { ...signed, publicKey: otherKeypair.publicKeyDer };

  const result = verifySignedManifest(tampered);
  assert.equal(result.valid, false);
});

test("verifyReceipt fails closed when checked against the wrong public key", async () => {
  const signerKeypair = generateKeyPair();
  const otherKeypair = generateKeyPair();
  const provider = new LocalKeyProvider(signerKeypair);

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

  assert.equal(verifyReceipt(receipt, otherKeypair.publicKeyDer), false);
});

test("signManifestWithProvider fails closed when the provider misreports its own key id", async () => {
  const keypair = generateKeyPair();
  const realProvider = new LocalKeyProvider(keypair);
  const fakeKeyId = publicKeyId(generateKeyPair().publicKeyDer);
  const liar = mismatchedIdentityProvider(realProvider, fakeKeyId);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, liar);

  // The artifact carries the liar's claimed publicKeyId, but the actual
  // public key bytes don't hash to it — verification must reject this,
  // not trust the provider's self-reported identity.
  assert.equal(signed.publicKeyId, fakeKeyId);
  const result = verifySignedManifest(signed);
  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_PUBLIC_KEY_ID_MISMATCH");
});

test("verifySignedManifest fails closed on a corrupted provider signature", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, provider);
  const corruptedBytes = Buffer.from(signed.signature, "base64");
  corruptedBytes[0] = corruptedBytes[0]! ^ 0xff;
  const corrupted = { ...signed, signature: corruptedBytes.toString("base64") };

  const result = verifySignedManifest(corrupted);
  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_SIGNATURE_INVALID");
});

test("verifyReceipt fails closed on a corrupted provider signature", async () => {
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
  const corruptedBytes = Buffer.from(receipt.signature, "base64");
  corruptedBytes[0] = corruptedBytes[0]! ^ 0xff;
  const corrupted = { ...receipt, signature: corruptedBytes.toString("base64") };

  assert.equal(verifyReceipt(corrupted, keypair.publicKeyDer), false);
});

test("LocalKeyProvider construction error never contains the rejected key material", () => {
  const badPublicKey = "not-canonical-base64!!";
  const badPrivateKey = "also-not-canonical-base64!!";

  try {
    new LocalKeyProvider({
      publicKeyDer: badPublicKey,
      privateKeyDer: badPrivateKey,
    });
    assert.fail("expected LocalKeyProvider construction to throw");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert.equal(message.includes(badPublicKey), false);
    assert.equal(message.includes(badPrivateKey), false);
  }
});

test("a provider-signed manifest's serialized JSON never contains the private key material", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, provider);
  const serialized = JSON.stringify(signed);

  assert.equal(serialized.includes(keypair.privateKeyDer), false);
});

test("a provider-signed receipt's serialized JSON never contains the private key material", async () => {
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
  const serialized = JSON.stringify(receipt);

  assert.equal(serialized.includes(keypair.privateKeyDer), false);
});

// Passphrase handling is a CLI/keystore-only concept (src/index.ts,
// src/keystore.ts) — KeyProvider itself has no passphrase parameter by
// design, so there is nothing passphrase-shaped for this suite to leak.
// Passphrase-non-logging is covered by the Phase 2 secret-hygiene smoke
// tests (scripts/smoke.mjs) and by the repository-wide
// `grep -rn "console\\.(log|error)\\(.*passphrase"` check performed during
// the Phase 3 audit, which returned zero matches.
