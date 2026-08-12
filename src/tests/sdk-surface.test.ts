import { test } from "node:test";
import assert from "node:assert/strict";
import * as sdk from "../sdk.js";

/**
 * Frozen v1.0 public SDK surface (runtime value exports).
 *
 * Removing or renaming any of these is a breaking change that requires a major
 * version bump. Adding a new export is additive (minor) and must be reflected
 * here deliberately. This snapshot makes accidental surface drift a failing test
 * rather than a silent break for downstream consumers.
 */
const FROZEN_SDK_SURFACE = [
  "DEFAULT_POLICY",
  "GRANT_REASON",
  "REASON",
  "addTrustAnchor",
  "admit",
  "admitAndConsume",
  "applyKeyRotation",
  "canonicalize",
  "checkGrant",
  "checkTrustedKey",
  "createEvidenceEnvelope",
  "createKeyRotation",
  "createKeyRotationWithProvider",
  "createReceipt",
  "createReceiptWithProvider",
  "emptyTrustStore",
  "findGrant",
  "findTool",
  "generateKeyPair",
  "getCount",
  "hashManifest",
  "hashRequest",
  "increment",
  "isStoredKeyPair",
  "loadGrants",
  "loadManifest",
  "loadMeter",
  "meterKey",
  "openKeyPair",
  "publicKeyId",
  "revokeTrustAnchor",
  "saveMeter",
  "sealKeyPair",
  "signManifest",
  "signManifestWithProvider",
  "signWithKeyPair",
  "signatureMessage",
  "validateGrantSet",
  "validateKeyPair",
  "validateManifest",
  "validateReceipt",
  "validateSignedManifest",
  "validateTrustStore",
  "verifyKeyRotation",
  "verifyReceipt",
  "verifyReceiptDetailed",
  "verifySignedManifest",
  "verifyTrustedSignedManifest",
];

test("public SDK export surface is frozen", () => {
  const actual = Object.keys(sdk).sort();
  assert.deepEqual(actual, FROZEN_SDK_SURFACE);
});
