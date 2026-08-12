#!/usr/bin/env node
// Automated package-surface verification: asserts the exact file list npm
// would publish never contains local evidence, key material, or stray
// artifacts. `npm pack --dry-run` alone only prints a log a human has to
// eyeball; this makes the same check a hard CI failure.
import { execFileSync } from "node:child_process";

const FORBIDDEN_PATTERNS = [
  /^\.besa\//,
  /(^|\/)receipts\//,
  /(^|\/)rotations\//,
  /\.tgz$/,
  /(^|\/)key\.json$/,
  /(^|\/)\.env(\..+)?$/,
  /(^|\/)trust\.json$/,
];

// All arguments below are fixed literals, never derived from external input,
// so shell:true here carries none of the injection risk the option normally
// warns about — it is required because Windows cannot exec a plain "npm"
// (a .cmd shim) without a shell.
const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
  encoding: "utf8",
  shell: process.platform === "win32",
});

const [{ files }] = JSON.parse(output);
const paths = files.map((entry) => entry.path);

const violations = paths.filter((path) =>
  FORBIDDEN_PATTERNS.some((pattern) => pattern.test(path)),
);

if (violations.length > 0) {
  console.error("FAIL: forbidden paths would be published:");
  for (const path of violations) {
    console.error(`  - ${path}`);
  }
  process.exit(1);
}

console.log(`OK: package surface clean (${String(paths.length)} files, no forbidden paths)`);
