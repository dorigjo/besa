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

const REQUIRED_PATHS = [
  "dist/demo.js",
  "dist/index.js",
  "dist/sdk.js",
  "dist/sdk.d.ts",
  "Dockerfile",
  "ARCHITECTURE.md",
  "AUDIT_SCOPE.md",
  "SECURITY.md",
  "SPEC.md",
  "docs/AGENT_GATEWAY.md",
  "docs/BESA_VS_IAM.md",
  "docs/BESA_VS_MCP_AUTH.md",
  "docs/BESA_VS_OBSERVABILITY.md",
  "docs/BENCHMARKS.md",
  "docs/EVIDENCE_ENVELOPE.md",
  "docs/HOSTED_VERIFIER.md",
  "docs/RUNTIME_ADMISSION.md",
  "docs/SECURITY_CREDIBILITY.md",
  "docs/THREAT_MODEL.md",
  "docs/V1_1_SECURITY_REVIEW.md",
  "docs/adoption/DISCOVERY_AUDIT.md",
  "docs/adoption/DISTRIBUTION_PLAN.md",
  "docs/adoption/INTEGRATION_TARGETS.md",
  "docs/adoption/SHAREABLE_MEDIA.md",
  "docs/assets/besa-architecture.svg",
  "docs/launch/HN_V1_1.md",
  "docs/launch/LINKEDIN_V1_1.md",
  "docs/launch/REDDIT_V1_1.md",
  "docs/launch/TECHNICAL_BLOG_V1_1.md",
  "docs/launch/V1_1_RELEASE_NOTES.md",
  "docs/launch/X_V1_1.md",
  "examples/action-policy.yaml",
  "examples/consequential-mcp-middleware.ts",
  "examples/generic-tool-wrapper.ts",
  "examples/http-middleware.ts",
  "examples/hosted-verifier.env.example",
  "scripts/traction-report.mjs",
  "conformance/consequential-action-v1.json",
  "conformance/consequential-action-negative-v1.json",
];

// Windows needs cmd.exe for the npm.cmd shim. Invoke it explicitly rather than
// using shell:true, and keep the command a fixed literal with no external input.
const npmPack =
  process.platform === "win32"
    ? {
        file: process.env.ComSpec ?? "cmd.exe",
        args: ["/d", "/s", "/c", "npm pack --dry-run --json"],
      }
    : { file: "npm", args: ["pack", "--dry-run", "--json"] };

const output = execFileSync(npmPack.file, npmPack.args, {
  encoding: "utf8",
});

const [{ files }] = JSON.parse(output);
const paths = files.map((entry) => entry.path);

const violations = paths.filter((path) =>
  FORBIDDEN_PATTERNS.some((pattern) => pattern.test(path)),
);
const missing = REQUIRED_PATHS.filter((path) => !paths.includes(path));

let failed = false;
if (violations.length > 0) {
  console.error("FAIL: forbidden paths would be published:");
  for (const path of violations) {
    console.error(`  - ${path}`);
  }
  failed = true;
}

if (missing.length > 0) {
  console.error("FAIL: required release paths would be missing:");
  for (const path of missing) {
    console.error(`  - ${path}`);
  }
  failed = true;
}

if (failed) process.exit(1);

console.log(
  `OK: package surface clean (${String(paths.length)} files, ${String(REQUIRED_PATHS.length)} required paths, no forbidden paths)`,
);
