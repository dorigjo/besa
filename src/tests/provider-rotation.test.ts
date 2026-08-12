import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, publicKeyId } from "../crypto.js";
import { LocalKeyProvider } from "../keys/local-provider.js";
import { RemoteSimulationProvider } from "../keys/remote-simulation-provider.js";
import type { KeyProvider } from "../keys/provider.js";
import {
  addTrustAnchor,
  applyKeyRotation,
  createKeyRotation,
  createKeyRotationWithProvider,
  emptyTrustStore,
  verifyKeyRotation,
} from "../trust.js";

const FAST = { latencyMs: 5, timeoutMs: 30, maxRetries: 1 };

function mismatchedIdentityProvider(real: KeyProvider, fakeKeyId: string): KeyProvider {
  return {
    getPublicKey: () => real.getPublicKey(),
    getKeyId: () => Promise.resolve(fakeKeyId),
    sign: (payload) => real.sign(payload),
  };
}

test("createKeyRotationWithProvider is structurally identical to createKeyRotation for the same keys", async () => {
  const previousKeypair = generateKeyPair();
  const nextKeypair = generateKeyPair();
  const rotatedAt = new Date().toISOString();

  const legacy = createKeyRotation(previousKeypair, nextKeypair, rotatedAt);
  const viaProvider = await createKeyRotationWithProvider(
    new LocalKeyProvider(previousKeypair),
    new LocalKeyProvider(nextKeypair),
    rotatedAt,
  );

  assert.equal(viaProvider.artifactVersion, legacy.artifactVersion);
  assert.equal(viaProvider.algorithm, legacy.algorithm);
  assert.equal(viaProvider.previousPublicKey, legacy.previousPublicKey);
  assert.equal(viaProvider.previousPublicKeyId, legacy.previousPublicKeyId);
  assert.equal(viaProvider.newPublicKey, legacy.newPublicKey);
  assert.equal(viaProvider.newPublicKeyId, legacy.newPublicKeyId);
  assert.equal(viaProvider.rotatedAt, legacy.rotatedAt);
  assert.equal(viaProvider.signature, legacy.signature);
  assert.equal(verifyKeyRotation(viaProvider).valid, true);
});

test("createKeyRotationWithProvider works end to end with RemoteSimulationProvider on both sides — the case that matters: rotating a key that never exposes its private material to the caller", async () => {
  const previousKeypair = generateKeyPair();
  const nextKeypair = generateKeyPair();
  const previous = new RemoteSimulationProvider(previousKeypair, FAST);
  const next = new RemoteSimulationProvider(nextKeypair, FAST);

  const anchoredAt = new Date(Date.now() - 60_000).toISOString();
  const store = addTrustAnchor(emptyTrustStore(), previousKeypair.publicKeyDer, anchoredAt);
  const rotation = await createKeyRotationWithProvider(previous, next);
  assert.equal(verifyKeyRotation(rotation).valid, true);

  const rotated = applyKeyRotation(store, rotation);
  const activeKey = rotated.keys.find((key) => key.status === "active");

  assert.equal(activeKey?.publicKeyId, publicKeyId(nextKeypair.publicKeyDer));
});

test("createKeyRotationWithProvider fails closed when the previous provider misreports its key id", async () => {
  const previousKeypair = generateKeyPair();
  const nextKeypair = generateKeyPair();
  const realPrevious = new LocalKeyProvider(previousKeypair);
  const fakeKeyId = publicKeyId(generateKeyPair().publicKeyDer);
  const liar = mismatchedIdentityProvider(realPrevious, fakeKeyId);

  const rotation = await createKeyRotationWithProvider(
    liar,
    new LocalKeyProvider(nextKeypair),
  );

  assert.equal(rotation.previousPublicKeyId, fakeKeyId);
  const result = verifyKeyRotation(rotation);
  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_PUBLIC_KEY_ID_MISMATCH");
});

test("createKeyRotationWithProvider rejects rotating a provider to itself", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);

  await assert.rejects(
    () => createKeyRotationWithProvider(provider, provider),
    /different new key/,
  );
});

test("createKeyRotationWithProvider produces a rotation proof rejected by verifyKeyRotation when tampered, identically to the legacy path", async () => {
  const previous = new LocalKeyProvider(generateKeyPair());
  const next = new LocalKeyProvider(generateKeyPair());

  const rotation = await createKeyRotationWithProvider(previous, next);
  const otherKeypair = generateKeyPair();
  const tampered = { ...rotation, newPublicKey: otherKeypair.publicKeyDer };

  assert.equal(verifyKeyRotation(tampered).valid, false);
});
