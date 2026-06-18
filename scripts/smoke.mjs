import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const node = process.execPath;
const repositoryRoot = resolve(".");
const tsc = resolve("node_modules/typescript/bin/tsc");
const cli = resolve("dist/index.js");
const workspace = mkdtempSync(join(tmpdir(), "besa-smoke-"));
const examplesDirectory = join(workspace, "examples");

function run(label, args, expectedCode, cwd = workspace) {
  console.log(`\n== ${label} (expect exit ${expectedCode}) ==`);

  const result = spawnSync(node, args, {
    cwd,
    stdio: "inherit",
  });

  const code = result.status ?? 1;

  if (code !== expectedCode) {
    console.error(
      `SMOKE FAIL: ${label} exited ${code}, expected ${expectedCode}`,
    );
    return false;
  }

  return true;
}

function latestReceiptPath() {
  const receiptsDirectory = join(workspace, ".besa", "receipts");
  const receipt = readdirSync(receiptsDirectory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .at(-1);

  if (!receipt) {
    throw new Error("receipt command did not create a receipt artifact");
  }

  return join(receiptsDirectory, receipt);
}

console.log("Besa smoke test");

if (!existsSync(tsc)) {
  console.error(
    "SMOKE FAIL: local TypeScript compiler not found. Run npm install first.",
  );
  process.exit(1);
}

mkdirSync(examplesDirectory, { recursive: true });

for (const name of ["manifest.yaml", "grants.yaml", "request.json"]) {
  copyFileSync(
    join(repositoryRoot, "examples", name),
    join(examplesDirectory, name),
  );
}

let ok = true;

try {
  if (!run("build (tsc)", [tsc], 0, repositoryRoot)) {
    process.exit(1);
  }

  const manifest = join("examples", "manifest.yaml");
  const signedManifest = join("examples", "manifest.signed.json");
  const grants = join("examples", "grants.yaml");
  const request = join("examples", "request.json");

  const steps = [
    ["load manifest", [cli, "load", manifest], 0],
    ["sign manifest", [cli, "sign", manifest], 0],
    ["verify signed manifest", [cli, "verify", signedManifest], 0],
    ["admit crm.lookup", [cli, "admit", signedManifest, "crm.lookup"], 0],
    ["admit crm.delete deny", [cli, "admit", signedManifest, "crm.delete"], 1],
    [
      "receipt crm.lookup",
      [cli, "receipt", "crm.lookup", signedManifest, "--request", request],
      0,
    ],
  ];

  for (const [label, args, expectedCode] of steps) {
    if (!run(label, args, expectedCode)) {
      ok = false;
    }
  }

  if (ok) {
    const receiptPath = latestReceiptPath();

    if (
      !run(
        "verify receipt trust chain",
        [cli, "verify-receipt", receiptPath, signedManifest],
        0,
      )
    ) {
      ok = false;
    }
  }

  const grantSteps = [
    [
      "grant admit allow agent-alpha/crm.lookup",
      [
        cli,
        "admit",
        signedManifest,
        "crm.lookup",
        "--agent",
        "agent-alpha",
        "--grants",
        grants,
      ],
      0,
    ],
    [
      "grant admit deny agent-alpha/crm.delete",
      [
        cli,
        "admit",
        signedManifest,
        "crm.delete",
        "--agent",
        "agent-alpha",
        "--grants",
        grants,
      ],
      1,
    ],
  ];

  for (const [label, args, expectedCode] of grantSteps) {
    if (!run(label, args, expectedCode)) {
      ok = false;
    }
  }
} finally {
  rmSync(workspace, { recursive: true, force: true });
}

if (!ok) {
  console.error("\nSMOKE FAILED");
  process.exit(1);
}

console.log("\nSMOKE OK: all steps behaved as expected");
