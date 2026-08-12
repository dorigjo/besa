/**
 * Canonical receipt drift check.
 *
 * There is exactly one illustrative receipt across all public surfaces. This
 * script is its single source of truth: it asserts that README.md, site/index.html,
 * and docs/index.html each embed this exact receipt — same fields, same order,
 * same values. Any divergence (a stray timestamp, a different publicKeyId, a
 * missing artifactVersion) fails the check.
 *
 * The receipt is synthetic and illustrative. Its signature is an explicit
 * placeholder, never a pseudo-real unverifiable string. Field order matches the
 * object produced by createReceipt() in src/signing.ts.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// The single canonical receipt. Field order mirrors createReceipt() output.
const CANONICAL_RECEIPT = {
  artifactVersion: 1,
  receiptId: "rcpt_2d7942c7-8f70-4984-9c3f-24876acfd860",
  manifestHash: "ea7e9ca22d199f40281cdf9e5d6145440c6c7d6bfbe94157c4b1da5527054410",
  toolName: "crm.lookup",
  decision: "allow",
  reasonCode: "ALLOWED",
  timestamp: "2026-06-19T10:00:00.000Z",
  requestHash: "b27b80d1227c167a6fca199778645daa77d20a8087782fc48802d11d6281c920",
  publicKeyId: "f68668614543c4896cf8cee418492f1a4df1f1acdba8850f94728b8a94cf90fe",
  algorithm: "ed25519",
  signature: "<base64-ed25519-signature>",
};

const SURFACES = ["README.md", "site/index.html", "docs/index.html"];

// Whitespace-insensitive needle: same fields, same order, same values. HTML
// entity-unescaping lets the <pre>-embedded copies (which must escape < and >)
// match the Markdown copy byte-for-byte after normalization.
const needle = JSON.stringify(CANONICAL_RECEIPT);

function normalize(text) {
  return text
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&")
    .replace(/\s+/g, "");
}

const failures = [];

for (const surface of SURFACES) {
  const content = readFileSync(join(root, surface), "utf8");
  if (!normalize(content).includes(normalize(needle))) {
    failures.push(surface);
  }
}

if (failures.length > 0) {
  console.error("RECEIPT DRIFT: canonical receipt not found (or altered) in:");
  for (const surface of failures) {
    console.error(`  - ${surface}`);
  }
  console.error("");
  console.error("Every public surface must embed this exact receipt:");
  console.error(JSON.stringify(CANONICAL_RECEIPT, null, 2));
  process.exit(1);
}

console.log(
  `DOCS RECEIPT OK: canonical receipt is consistent across ${SURFACES.length} surfaces`,
);
