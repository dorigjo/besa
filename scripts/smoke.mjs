import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
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

function latestRotationPath() {
  const rotationsDirectory = join(workspace, ".besa", "rotations");
  const rotation = readdirSync(rotationsDirectory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .at(-1);

  if (!rotation) {
    throw new Error("keys rotate did not create a rotation artifact");
  }

  return join(rotationsDirectory, rotation);
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
  const historicalManifest = join("examples", "manifest.old.signed.json");
  const consumerTrust = "consumer-trust.json";

  writeFileSync(
    join(workspace, consumerTrust),
    JSON.stringify({ version: 1, keys: [] }, null, 2) + "\n",
    "utf8",
  );

  const initialSteps = [
    ["load manifest", [cli, "load", manifest], 0],
    ["sign manifest", [cli, "sign", manifest], 0],
    ["verify signed manifest", [cli, "verify", signedManifest], 0],
    [
      "deny consumer without trust anchor",
      [cli, "verify", signedManifest, "--trust", consumerTrust],
      1,
    ],
    [
      "pin consumer trust anchor",
      [cli, "trust", "add", signedManifest, "--trust", consumerTrust],
      0,
    ],
    [
      "verify with consumer trust anchor",
      [cli, "verify", signedManifest, "--trust", consumerTrust],
      0,
    ],
    ["admit crm.lookup", [cli, "admit", signedManifest, "crm.lookup"], 0],
    ["admit crm.delete deny", [cli, "admit", signedManifest, "crm.delete"], 1],
    [
      "receipt crm.lookup",
      [cli, "receipt", "crm.lookup", signedManifest, "--request", request],
      0,
    ],
  ];

  for (const [label, args, expectedCode] of initialSteps) {
    if (!run(label, args, expectedCode)) {
      ok = false;
    }
  }

  copyFileSync(
    join(workspace, signedManifest),
    join(workspace, historicalManifest),
  );

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

  if (!run("rotate signing key", [cli, "keys", "rotate"], 0)) {
    ok = false;
  }

  const rotationPath = latestRotationPath();
  const rotationSteps = [
    [
      "apply rotation to consumer trust store",
      [cli, "trust", "apply", rotationPath, "--trust", consumerTrust],
      0,
    ],
    [
      "verify historical manifest after rotation",
      [cli, "verify", historicalManifest, "--trust", consumerTrust],
      0,
    ],
    [
      "deny new admission under retired key",
      [cli, "admit", historicalManifest, "crm.lookup", "--trust", consumerTrust],
      1,
    ],
  ];

  for (const [label, args, expectedCode] of rotationSteps) {
    if (!run(label, args, expectedCode)) {
      ok = false;
    }
  }

  if (ok) {
    const receiptPath = latestReceiptPath();
    if (
      !run(
        "verify historical receipt after rotation",
        [cli, "verify-receipt", receiptPath, historicalManifest],
        0,
      )
    ) {
      ok = false;
    }
  }

  const resignSteps = [
    ["re-sign manifest with rotated key", [cli, "sign", manifest], 0],
    [
      "verify rotated manifest with consumer trust store",
      [cli, "verify", signedManifest, "--trust", consumerTrust],
      0,
    ],
  ];

  for (const [label, args, expectedCode] of resignSteps) {
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
