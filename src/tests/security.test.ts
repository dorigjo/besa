import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  REASON,
  addTrustAnchor,
  admit,
  admitAndConsume,
  canonicalize,
  checkTrustedKey,
  createKeyRotation,
  createReceipt,
  emptyTrustStore,
  generateKeyPair,
  openKeyPair,
  publicKeyId,
  sealKeyPair,
  signManifest,
  signatureMessage,
  validateGrantSet,
  validateManifest,
  validateReceipt,
  validateTrustStore,
  verifyKeyRotation,
  verifySignedManifest,
  type Manifest,
} from "../sdk.js";
import { MAX_ARTIFACT_BYTES, readUtf8File } from "../io.js";

const PASSPHRASE =
  process.env.BESA_KEY_PASSPHRASE ?? randomBytes(32).toString("base64url");

function manifest(): Manifest {
  return {
    serverName: "security-test",
    serverVersion: "1.0.0",
    serverUrl: "https://tools.example.test/mcp",
    createdAt: "2026-06-19T00:00:00Z",
    tools: [
      {
        name: "vault.read",
        description: "Read one test value.",
        capability: "read",
        risk: "low",
        scopes: ["vault:read"],
        budgetLimit: 2,
        inputSchema: { type: "object" },
      },
    ],
  };
}

test("public key ids are full SHA-256 fingerprints of key bytes", () => {
  const keypair = generateKeyPair();
  assert.match(publicKeyId(keypair.publicKeyDer), /^[a-f0-9]{64}$/);
});

test("signature messages are domain separated", () => {
  const payload = { value: "same" };
  assert.notDeepEqual(
    signatureMessage("receipt", payload),
    signatureMessage("signed-manifest", payload),
  );
});

test("canonical JSON rejects excessive depth and bytes", () => {
  let nested: Record<string, unknown> = {};
  for (let index = 0; index < 66; index += 1) nested = { nested };

  assert.throws(() => canonicalize(nested), /depth limit/);
  assert.throws(
    () => canonicalize("x".repeat(MAX_ARTIFACT_BYTES + 1)),
    /byte limit/,
  );
});

test("signed artifacts require the current artifact version", () => {
  const signed = signManifest(manifest(), generateKeyPair()) as unknown as Record<string, unknown>;
  delete signed.artifactVersion;

  const result = verifySignedManifest(signed);
  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_SIGNED_MANIFEST_INVALID");
});

test("keystore encryption authenticates ciphertext and hides private key material", () => {
  const keypair = generateKeyPair();
  const stored = sealKeyPair(keypair, PASSPHRASE);
  const serialized = JSON.stringify(stored);

  assert.equal(serialized.includes(keypair.privateKeyDer), false);
  assert.deepEqual(openKeyPair(stored, PASSPHRASE), keypair);
  assert.throws(() => openKeyPair(stored, "wrong-passphrase-16"), /authentication failed/);

  const ciphertext = Buffer.from(stored.protection.ciphertext, "base64");
  ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
  const tampered = {
    ...stored,
    protection: {
      ...stored.protection,
      ciphertext: ciphertext.toString("base64"),
    },
  };
  assert.throws(() => openKeyPair(tampered, PASSPHRASE), /authentication failed/);
});

test("admission fails closed for invalid runtime inputs", () => {
  assert.equal(admit(manifest(), "vault.read", Number.NaN).reasonCode, REASON.INVALID_CALL_COUNT);
  assert.equal(
    admit({ ...manifest(), tools: [] }, "vault.read", 0).reasonCode,
    REASON.INVALID_MANIFEST,
  );
  assert.equal(
    admit(manifest(), "vault.read", 0, {} as never).reasonCode,
    REASON.INVALID_POLICY,
  );
});

test("manifest and grant schemas reject extensions, insecure URLs, and duplicates", () => {
  assert.equal(
    validateManifest({ ...manifest(), extension: true }).ok,
    false,
  );
  assert.equal(
    validateManifest({ ...manifest(), serverUrl: "http://tools.example.test" }).ok,
    false,
  );
  assert.equal(
    validateGrantSet({
      grants: [{ agentId: "agent", tools: ["vault.read", "vault.read"] }],
    }).ok,
    false,
  );
});

test("trust validation rejects extensions and future-dated artifacts", () => {
  const keypair = generateKeyPair();
  const now = new Date("2026-06-19T12:00:00.000Z");
  const store = addTrustAnchor(emptyTrustStore(), keypair.publicKeyDer, now.toISOString());

  assert.equal(
    validateTrustStore({ ...store, extension: true }).ok,
    false,
  );
  assert.equal(
    checkTrustedKey(
      store,
      keypair.publicKeyDer,
      "2026-06-19T12:06:00.000Z",
      "verify",
      now,
    ).reasonCode,
    "E_ARTIFACT_TIMESTAMP_FUTURE",
  );
});

test("key rotations and receipts reject unsigned extension fields", () => {
  const previous = generateKeyPair();
  const rotation = createKeyRotation(previous, generateKeyPair()) as unknown as Record<string, unknown>;
  rotation.extension = true;
  assert.equal(verifyKeyRotation(rotation).reasonCode, "E_ROTATION_INVALID");

  const signed = signManifest(manifest(), previous);
  const receipt = createReceipt(
    {
      manifestHash: signed.manifestHash,
      toolName: "vault.read",
      decision: "allow",
      reasonCode: "ALLOWED",
      request: {},
    },
    previous,
  ) as unknown as Record<string, unknown>;
  receipt.extension = true;
  assert.equal(validateReceipt(receipt).ok, false);
});

test("bounded UTF-8 file reads reject oversized and malformed artifacts", () => {
  const directory = mkdtempSync(join(tmpdir(), "besa-io-security-"));
  const oversized = join(directory, "oversized.json");
  const malformed = join(directory, "malformed.json");

  try {
    writeFileSync(oversized, Buffer.alloc(MAX_ARTIFACT_BYTES + 1, 0x20));
    writeFileSync(malformed, Buffer.from([0xff]));
    assert.throws(() => readUtf8File(oversized), /byte limit/);
    assert.throws(() => readUtf8File(malformed));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("stale meter locks owned by a live process are not stolen", () => {
  const directory = mkdtempSync(join(tmpdir(), "besa-live-lock-"));
  const meter = join(directory, "meter.json");
  const lock = `${meter}.lock`;

  try {
    writeFileSync(
      lock,
      JSON.stringify({ pid: process.pid, token: "live", createdAt: new Date().toISOString() }),
      "utf8",
    );
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock, old, old);

    assert.throws(
      () =>
        admitAndConsume(
          meter,
          "a".repeat(64),
          manifest(),
          "vault.read",
          undefined,
          { staleMs: 1, timeoutMs: 20, retryMs: 1 },
        ),
      /timed out waiting for meter lock/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
