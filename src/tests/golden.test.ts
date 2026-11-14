import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  canonicalize,
  hashManifest,
  hashRequest,
  verifyReceiptDetailed,
  verifySignedManifest,
} from "../sdk.js";
import {
  GOLDEN_CANONICAL_ORDERING,
  GOLDEN_CANONICAL_ORDERING_INPUT,
  GOLDEN_MANIFEST_HASH,
  GOLDEN_PUBLIC_KEY_DER,
  GOLDEN_RECEIPT,
  GOLDEN_REQUEST,
  GOLDEN_REQUEST_HASH,
  GOLDEN_SIGNED_MANIFEST,
} from "./fixtures/golden-v1.js";

/**
 * The v1.4 replacement conformance vectors. This file ships in the npm package
 * so an independent implementer can self-check without cloning the repo. The
 * neutral-domain migration changes vector identity/signatures, not v1 artifact
 * semantics; the previous release remains immutable in its release history.
 */
const CONFORMANCE = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../conformance/golden-v1.json", import.meta.url)),
    "utf8",
  ),
) as {
  vectorSet: string;
  canonicalOrdering: { input: unknown; expected: string };
  publicKeyDer: string;
  manifestHash: string;
  requestHash: string;
  request: unknown;
  signedManifest: unknown;
  receipt: unknown;
};

test("v1.4 neutral-domain vectors match the in-repo fixtures exactly", () => {
  assert.equal(CONFORMANCE.vectorSet, "v1.4-neutral-domain");
  assert.deepEqual(CONFORMANCE.signedManifest, GOLDEN_SIGNED_MANIFEST);
  assert.deepEqual(CONFORMANCE.receipt, GOLDEN_RECEIPT);
  assert.deepEqual(CONFORMANCE.request, GOLDEN_REQUEST);
  assert.equal(CONFORMANCE.publicKeyDer, GOLDEN_PUBLIC_KEY_DER);
  assert.equal(CONFORMANCE.manifestHash, GOLDEN_MANIFEST_HASH);
  assert.equal(CONFORMANCE.requestHash, GOLDEN_REQUEST_HASH);
  assert.deepEqual(
    CONFORMANCE.canonicalOrdering.input,
    GOLDEN_CANONICAL_ORDERING_INPUT,
  );
  assert.equal(CONFORMANCE.canonicalOrdering.expected, GOLDEN_CANONICAL_ORDERING);
});

test("replacement conformance vectors verify cryptographically", () => {
  // Verifies the exact bytes an external implementer receives, not the in-repo
  // fixture they were copied from.
  assert.equal(
    verifySignedManifest(CONFORMANCE.signedManifest).valid,
    true,
    "published signedManifest vector must verify",
  );
  assert.equal(
    verifyReceiptDetailed(CONFORMANCE.receipt, CONFORMANCE.publicKeyDer).valid,
    true,
    "published receipt vector must verify",
  );
});

test("golden signed manifest still verifies (forward compatibility)", () => {
  const result = verifySignedManifest(GOLDEN_SIGNED_MANIFEST);
  assert.equal(result.valid, true, result.detail);
});

test("golden receipt still verifies against its public key", () => {
  const result = verifyReceiptDetailed(GOLDEN_RECEIPT, GOLDEN_PUBLIC_KEY_DER);
  assert.equal(result.valid, true, result.detail);
});

test("canonical JSON key ordering is frozen", () => {
  assert.equal(
    canonicalize(GOLDEN_CANONICAL_ORDERING_INPUT),
    GOLDEN_CANONICAL_ORDERING,
  );
});

test("manifest hashing rule is frozen", () => {
  assert.equal(hashManifest(GOLDEN_SIGNED_MANIFEST.manifest), GOLDEN_MANIFEST_HASH);
});

test("request hashing rule is frozen", () => {
  assert.equal(hashRequest(GOLDEN_REQUEST), GOLDEN_REQUEST_HASH);
});

test("tampering with a golden receipt field fails closed", () => {
  const tampered = { ...GOLDEN_RECEIPT, toolName: "crm.delete" };
  const result = verifyReceiptDetailed(tampered, GOLDEN_PUBLIC_KEY_DER);
  assert.equal(result.valid, false);
});

test("tampering with the golden manifest body fails closed", () => {
  const tampered = {
    ...GOLDEN_SIGNED_MANIFEST,
    manifest: { ...GOLDEN_SIGNED_MANIFEST.manifest, serverName: "evil" },
  };
  const result = verifySignedManifest(tampered);
  assert.equal(result.valid, false);
});
