import { test } from "node:test";
import assert from "node:assert/strict";
import { sign as ed25519Sign } from "node:crypto";
import {
  generateKeyPair,
  privateKeyFromDer,
  publicKeyId,
  signatureMessage,
} from "../crypto.js";
import { signManifest, verifySignedManifest } from "../signing.js";
import { loadManifest } from "../manifest.js";
import { LocalKeyProvider } from "../keys/local-provider.js";

const MANIFEST_PATH = new URL(
  "../../examples/manifest.yaml",
  import.meta.url,
).pathname.replace(/^\/([A-Za-z]:)/, "$1");

test("LocalKeyProvider reports the same public key and key id as the raw KeyPair", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);

  assert.equal(await provider.getPublicKey(), keypair.publicKeyDer);
  assert.equal(await provider.getKeyId(), publicKeyId(keypair.publicKeyDer));
});

test("LocalKeyProvider.sign produces byte-identical signatures to the legacy ed25519Sign path", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);
  const payload = signatureMessage("receipt", { hello: "world" });

  const fromProvider = await provider.sign(payload);
  const fromLegacyPath = ed25519Sign(
    null,
    payload,
    privateKeyFromDer(keypair.privateKeyDer),
  );

  assert.deepEqual(Buffer.from(fromProvider), fromLegacyPath);
});

test("LocalKeyProvider.sign output verifies as a valid manifest signature end to end", async () => {
  const keypair = generateKeyPair();
  const provider = new LocalKeyProvider(keypair);
  const manifest = loadManifest(MANIFEST_PATH);

  // Build the signed-manifest body the same way signManifest does, but sign
  // it through the provider instead of the legacy synchronous path.
  const legacySigned = signManifest(manifest, keypair);
  const payload = signatureMessage("signed-manifest", {
    artifactVersion: legacySigned.artifactVersion,
    manifest: legacySigned.manifest,
    manifestHash: legacySigned.manifestHash,
    algorithm: legacySigned.algorithm,
    publicKey: legacySigned.publicKey,
    publicKeyId: legacySigned.publicKeyId,
    signedAt: legacySigned.signedAt,
  });

  const providerSignature = await provider.sign(payload);
  const rebuilt = {
    ...legacySigned,
    signature: Buffer.from(providerSignature).toString("base64"),
  };

  assert.equal(verifySignedManifest(rebuilt).valid, true);
});

test("LocalKeyProvider rejects an invalid or mismatched key pair", () => {
  assert.throws(() => {
    new LocalKeyProvider({
      publicKeyDer: "not-base64!!",
      privateKeyDer: "also-not-base64!!",
    });
  });
});
