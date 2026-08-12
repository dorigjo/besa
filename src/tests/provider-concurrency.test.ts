import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../crypto.js";
import { loadManifest } from "../manifest.js";
import { RemoteSimulationProvider } from "../keys/remote-simulation-provider.js";
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

// Regression coverage for a real, reproduced bug: RemoteSimulationProvider's
// #call() used to reset a *shared* instance counter to 0 at the start of
// every call, so one call's in-progress retry loop could be reset mid-flight
// by another concurrent call on the same instance. Fixed by tracking
// attempts locally per call and writing the shared field exactly once, when
// that call settles. These tests exercise the exact concurrent-call shape
// that exposed the original defect.

test("concurrent sign() calls on one RemoteSimulationProvider instance each produce independently correct signatures", async () => {
  const keypair = generateKeyPair();
  const provider = new RemoteSimulationProvider(keypair, {
    latencyMs: 5,
    timeoutMs: 200,
  });

  const payloads = Array.from({ length: 20 }, (_, index) =>
    Buffer.from(`payload-${String(index)}`),
  );
  const signatures = await Promise.all(
    payloads.map((payload) => provider.sign(payload)),
  );

  assert.equal(signatures.length, 20);
  for (const signature of signatures) {
    assert.equal(signature.length, 64);
  }
  // Every call succeeded in exactly one round trip (failureMode "none"), so
  // whichever call finished last must report attempts=1 — never a value
  // corrupted by another call's reset.
  assert.equal(provider.lastAttemptCount, 1);
});

test("concurrent sign() calls that all exhaust retries report the correct attempt count, not a corrupted one", async () => {
  const keypair = generateKeyPair();
  const maxRetries = 2;
  const provider = new RemoteSimulationProvider(keypair, {
    latencyMs: 5,
    timeoutMs: 20,
    maxRetries,
    failureMode: "timeout",
  });

  const results = await Promise.allSettled(
    Array.from({ length: 10 }, (_, index) =>
      provider.sign(Buffer.from(`payload-${String(index)}`)),
    ),
  );

  assert.ok(results.every((result) => result.status === "rejected"));
  // Every call independently retries maxRetries+1 times before giving up.
  // Under the old shared-reset bug, concurrent calls interleaving their
  // resets could leave this at 1 or any other value below maxRetries+1 —
  // deterministically wrong for a scenario where every call *must* exhaust
  // its full retry budget.
  assert.equal(provider.lastAttemptCount, maxRetries + 1);
});

test("signManifestWithProvider and createReceiptWithProvider run correctly concurrently against one shared RemoteSimulationProvider", async () => {
  const keypair = generateKeyPair();
  const provider = new RemoteSimulationProvider(keypair, {
    latencyMs: 5,
    timeoutMs: 200,
  });
  const manifest = loadManifest(MANIFEST_PATH);
  const receiptInput = {
    manifestHash:
      "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504",
    toolName: "crm.lookup",
    decision: "allow" as const,
    reasonCode: "ALLOWED",
    request: { customerId: "cust_0001" },
  };

  const [manifestResults, receiptResults] = await Promise.all([
    Promise.all(
      Array.from({ length: 5 }, () => signManifestWithProvider(manifest, provider)),
    ),
    Promise.all(
      Array.from({ length: 5 }, () => createReceiptWithProvider(receiptInput, provider)),
    ),
  ]);

  for (const signed of manifestResults) {
    assert.equal(verifySignedManifest(signed).valid, true);
  }
  for (const receipt of receiptResults) {
    assert.equal(verifyReceipt(receipt, keypair.publicKeyDer), true);
  }
});
