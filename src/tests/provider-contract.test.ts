import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, publicKeyId } from "../crypto.js";
import { loadManifest } from "../manifest.js";
import { LocalKeyProvider } from "../keys/local-provider.js";
import { RemoteSimulationProvider } from "../keys/remote-simulation-provider.js";
import type { KeyProvider } from "../keys/provider.js";
import {
  createReceiptWithProvider,
  signManifestWithProvider,
  verifyReceipt,
  verifySignedManifest,
} from "../signing.js";
import {
  GOLDEN_RECEIPT,
  GOLDEN_SIGNED_MANIFEST,
} from "./fixtures/golden-v1.js";

const MANIFEST_PATH = new URL(
  "../../examples/manifest.yaml",
  import.meta.url,
).pathname.replace(/^\/([A-Za-z]:)/, "$1");

const RECEIPT_INPUT = {
  manifestHash:
    "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504",
  toolName: "crm.lookup",
  decision: "allow" as const,
  reasonCode: "ALLOWED",
  request: { customerId: "cust_0001" },
};

// Fast, deterministic simulation settings — short latency/timeout keep the
// suite quick while still exercising real async timer races, not fakes.
const FAST = { latencyMs: 5, timeoutMs: 30, maxRetries: 1 };

function mismatchedIdentityProvider(real: KeyProvider, fakeKeyId: string): KeyProvider {
  return {
    getPublicKey: () => real.getPublicKey(),
    getKeyId: () => Promise.resolve(fakeKeyId),
    sign: (payload) => real.sign(payload),
  };
}

function mismatchedPublicKeyProvider(real: KeyProvider, fakePublicKey: string): KeyProvider {
  return {
    getPublicKey: () => Promise.resolve(fakePublicKey),
    getKeyId: () => real.getKeyId(),
    sign: (payload) => real.sign(payload),
  };
}

// --- Equivalence: RemoteSimulationProvider vs LocalKeyProvider ---

test("RemoteSimulationProvider produces a manifest signature structurally equivalent to LocalKeyProvider", async () => {
  const keypair = generateKeyPair();
  const local = new LocalKeyProvider(keypair);
  const remote = new RemoteSimulationProvider(keypair, FAST);
  const manifest = loadManifest(MANIFEST_PATH);

  const viaLocal = await signManifestWithProvider(manifest, local);
  const viaRemote = await signManifestWithProvider(manifest, remote);

  assert.equal(viaRemote.artifactVersion, viaLocal.artifactVersion);
  assert.deepEqual(viaRemote.manifest, viaLocal.manifest);
  assert.equal(viaRemote.manifestHash, viaLocal.manifestHash);
  assert.equal(viaRemote.algorithm, viaLocal.algorithm);
  assert.equal(viaRemote.publicKey, viaLocal.publicKey);
  assert.equal(viaRemote.publicKeyId, viaLocal.publicKeyId);
  assert.equal(verifySignedManifest(viaRemote).valid, true);
});

test("RemoteSimulationProvider produces a receipt signature structurally equivalent to LocalKeyProvider", async () => {
  const keypair = generateKeyPair();
  const local = new LocalKeyProvider(keypair);
  const remote = new RemoteSimulationProvider(keypair, FAST);

  const viaLocal = await createReceiptWithProvider(RECEIPT_INPUT, local);
  const viaRemote = await createReceiptWithProvider(RECEIPT_INPUT, remote);

  assert.equal(viaRemote.artifactVersion, viaLocal.artifactVersion);
  assert.equal(viaRemote.manifestHash, viaLocal.manifestHash);
  assert.equal(viaRemote.toolName, viaLocal.toolName);
  assert.equal(viaRemote.decision, viaLocal.decision);
  assert.equal(viaRemote.reasonCode, viaLocal.reasonCode);
  assert.equal(viaRemote.requestHash, viaLocal.requestHash);
  assert.equal(viaRemote.publicKeyId, viaLocal.publicKeyId);
  assert.equal(viaRemote.algorithm, viaLocal.algorithm);
  assert.equal(verifyReceipt(viaRemote, keypair.publicKeyDer), true);
});

test("verifySignedManifest accepts a manifest signed via RemoteSimulationProvider", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, FAST);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, remote);

  assert.deepEqual(verifySignedManifest(signed), {
    valid: true,
    reasonCode: "OK",
    detail: "manifest signature is valid",
  });
});

test("verifyReceipt accepts a receipt signed via RemoteSimulationProvider", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, FAST);

  const receipt = await createReceiptWithProvider(RECEIPT_INPUT, remote);

  assert.equal(verifyReceipt(receipt, keypair.publicKeyDer), true);
});

test("golden vectors still verify with RemoteSimulationProvider present in the codebase", () => {
  assert.equal(verifySignedManifest(GOLDEN_SIGNED_MANIFEST).valid, true);
  assert.equal(
    verifyReceipt(GOLDEN_RECEIPT, GOLDEN_SIGNED_MANIFEST.publicKey),
    true,
  );
});

// --- Failure model: every case must fail closed ---

test("RemoteSimulationProvider.sign rejects on simulated timeout (fails closed)", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    ...FAST,
    failureMode: "timeout",
  });

  await assert.rejects(
    () => remote.sign(Buffer.from("payload")),
    /timed out/,
  );
  // Retries the full budget before giving up — a persistent timeout is not
  // silently downgraded to "succeeded on some attempt".
  assert.equal(remote.lastAttemptCount, FAST.maxRetries + 1);
});

test("RemoteSimulationProvider.sign rejects on simulated provider error (fails closed)", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    ...FAST,
    failureMode: "provider-error",
  });

  await assert.rejects(
    () => remote.sign(Buffer.from("payload")),
    /remote signing service returned an error/,
  );
});

test("RemoteSimulationProvider.sign rejects on a cancelled request without retrying", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    ...FAST,
    failureMode: "cancelled",
  });

  await assert.rejects(
    () => remote.sign(Buffer.from("payload")),
    /cancelled/,
  );
  // A cancelled request models the caller giving up — retrying it would be
  // wrong, unlike a transient timeout/provider error.
  assert.equal(remote.lastAttemptCount, 1);
});

test("a manifest signed with an invalid-signature-injecting provider fails closed on verify", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    ...FAST,
    failureMode: "invalid-signature",
  });
  const manifest = loadManifest(MANIFEST_PATH);

  // Signing itself succeeds (the "network call" completed) — the corruption
  // simulates transit/provider-side tampering, so it must be caught at
  // verification, exactly like the corrupted-signature cases in
  // provider-security.test.ts.
  const signed = await signManifestWithProvider(manifest, remote);
  const result = verifySignedManifest(signed);

  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_SIGNATURE_INVALID");
});

test("signManifestWithProvider fails closed when a RemoteSimulationProvider misreports its public key", async () => {
  const keypair = generateKeyPair();
  const otherKeypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, FAST);
  const liar = mismatchedPublicKeyProvider(remote, otherKeypair.publicKeyDer);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, liar);
  const result = verifySignedManifest(signed);

  assert.equal(result.valid, false);
});

test("signManifestWithProvider fails closed when a RemoteSimulationProvider misreports its key id", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, FAST);
  const fakeKeyId = publicKeyId(generateKeyPair().publicKeyDer);
  const liar = mismatchedIdentityProvider(remote, fakeKeyId);
  const manifest = loadManifest(MANIFEST_PATH);

  const signed = await signManifestWithProvider(manifest, liar);
  const result = verifySignedManifest(signed);

  assert.equal(signed.publicKeyId, fakeKeyId);
  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_PUBLIC_KEY_ID_MISMATCH");
});

// --- Timeout recovery: a transient failure that clears up mid-retry-loop ---
//
// The suite above only proves "always times out" fails closed. It never
// proved the retry loop's *success* path actually works — a real remote
// signing service that is briefly overloaded and recovers within the retry
// budget must resolve successfully, not be indistinguishable from a
// permanently dead one. Reproduces a real gap: before failUntilAttempt
// existed, RemoteSimulationProvider could only simulate "never fails" or
// "never recovers", so this path was structurally untestable.

test("RemoteSimulationProvider.sign recovers when a timeout clears before maxRetries is exhausted", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    latencyMs: 5,
    timeoutMs: 30,
    maxRetries: 3,
    failureMode: "timeout",
    failUntilAttempt: 2,
  });

  const signature = await remote.sign(Buffer.from("payload"));

  assert.equal(signature.length, 64);
  // Attempts 1-2 time out, attempt 3 succeeds — proves the call resolves
  // instead of exhausting retries, and reports the exact recovery point.
  assert.equal(remote.lastAttemptCount, 3);
});

test("RemoteSimulationProvider.sign still fails closed when recovery would arrive after maxRetries is exhausted", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    latencyMs: 5,
    timeoutMs: 30,
    maxRetries: 1,
    failureMode: "timeout",
    failUntilAttempt: 5,
  });

  await assert.rejects(
    () => remote.sign(Buffer.from("payload")),
    /timed out/,
  );
  assert.equal(remote.lastAttemptCount, 2);
});

test("RemoteSimulationProvider.sign recovers from a provider-error, not only from a timeout", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    latencyMs: 5,
    timeoutMs: 30,
    maxRetries: 2,
    failureMode: "provider-error",
    failUntilAttempt: 1,
  });

  const signature = await remote.sign(Buffer.from("payload"));

  assert.equal(signature.length, 64);
  assert.equal(remote.lastAttemptCount, 2);
});

test("omitting failUntilAttempt preserves the pre-existing always-fails timeout behavior", async () => {
  const keypair = generateKeyPair();
  const remote = new RemoteSimulationProvider(keypair, {
    ...FAST,
    failureMode: "timeout",
  });

  await assert.rejects(() => remote.sign(Buffer.from("payload")), /timed out/);
  assert.equal(remote.lastAttemptCount, FAST.maxRetries + 1);
});
