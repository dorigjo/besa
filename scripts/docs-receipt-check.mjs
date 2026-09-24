/**
 * Installed-demo proof drift check.
 *
 * README.md, site/index.html, and docs/index.html must expose the same minimal
 * install, deny, allow, and evidence-verification path. The historical filename
 * is retained so the existing test:docs command remains stable.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const CANONICAL_DEMO_PROOF = [
  "npm install @dorigjo/besa",
  "npx besa demo",
  "DENY ACTION_NOT_GRANTED",
  "executor called: no",
  "ALLOW ACTION_ALLOWED",
  "evidence verification: EVIDENCE_VALID",
];

const SURFACES = ["README.md", "site/index.html", "docs/index.html"];

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
  const normalized = normalize(content);
  const missing = CANONICAL_DEMO_PROOF.filter(
    (marker) => !normalized.includes(normalize(marker)),
  );
  if (missing.length > 0) {
    failures.push({ surface, missing });
  }
}

if (failures.length > 0) {
  console.error("DEMO PROOF DRIFT: required markers are missing:");
  for (const failure of failures) {
    console.error(`  - ${failure.surface}: ${failure.missing.join(", ")}`);
  }
  process.exit(1);
}

console.log(
  `DOCS PROOF OK: installed demo is consistent across ${SURFACES.length} surfaces`,
);
