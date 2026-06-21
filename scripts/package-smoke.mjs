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

process.env.BESA_KEY_PASSPHRASE ??= "besa-package-smoke-test-passphrase-2026!!";

const repositoryRoot = resolve(".");
const workspace = mkdtempSync(join(tmpdir(), "besa-package-smoke-"));
const installRoot = join(workspace, "consumer");
const executionRoot = join(installRoot, "run");
const npmCli = process.env.npm_execpath;

if (!npmCli) {
  throw new Error("npm_execpath is unavailable; run this script through npm");
}

function run(label, command, args, cwd, expectedCode = 0) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: process.env,
  });
  const code = result.status ?? 1;

  if (code !== expectedCode) {
    throw new Error(
      [
        `${label} exited ${code}, expected ${expectedCode}`,
        result.error?.message,
        result.stdout,
        result.stderr,
      ]
        .filter(Boolean)
        .join("\n"),
    );
  }
}

function runNpm(label, args, cwd) {
  run(label, process.execPath, [npmCli, ...args], cwd);
}

function runBesa(label, args, expectedCode = 0) {
  run(
    label,
    process.execPath,
    [npmCli, "exec", "--offline", "--", "besa", ...args],
    executionRoot,
    expectedCode,
  );
}

function latestReceipt() {
  const directory = join(executionRoot, ".besa", "receipts");
  const name = readdirSync(directory)
    .filter((entry) => entry.endsWith(".json"))
    .sort()
    .at(-1);

  if (!name) {
    throw new Error("installed CLI did not create a receipt");
  }

  return join(directory, name);
}

console.log("Besa installed-package smoke test");

try {
  mkdirSync(installRoot, { recursive: true });
  mkdirSync(join(executionRoot, "examples"), { recursive: true });
  writeFileSync(
    join(installRoot, "package.json"),
    JSON.stringify({ private: true, type: "module" }, null, 2) + "\n",
    "utf8",
  );

  runNpm(
    "pack",
    ["pack", "--silent", "--pack-destination", workspace],
    repositoryRoot,
  );

  const tarball = readdirSync(workspace)
    .filter((entry) => entry.endsWith(".tgz"))
    .map((entry) => join(workspace, entry))
    .at(0);

  if (!tarball) {
    throw new Error("npm pack did not create a tarball");
  }

  runNpm(
    "install tarball",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
    installRoot,
  );

  const bin = join(
    installRoot,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "besa.cmd" : "besa",
  );

  if (!existsSync(bin)) {
    throw new Error("installed package did not expose the besa binary");
  }

  runBesa("binary help", ["--help"]);
  run(
    "SDK import",
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      "const b = await import('@dorigjo/besa'); " +
        "if (typeof b.signManifest !== 'function' || " +
        "typeof b.verifyTrustedSignedManifest !== 'function') process.exit(1);",
    ],
    installRoot,
  );

  const installedExamples = join(
    installRoot,
    "node_modules",
    "@dorigjo",
    "besa",
    "examples",
  );
  for (const name of ["manifest.yaml", "request.json"]) {
    copyFileSync(
      join(installedExamples, name),
      join(executionRoot, "examples", name),
    );
  }

  const manifest = join("examples", "manifest.yaml");
  const signed = join("examples", "manifest.signed.json");
  const request = join("examples", "request.json");

  runBesa("sign", ["sign", manifest]);
  runBesa("verify", ["verify", signed]);
  runBesa("reject unknown flag", ["verify", signed, "--bogus", "x"], 1);
  runBesa("reject missing flag value", ["verify", signed, "--trust"], 1);
  runBesa("reject extra argument", ["verify", signed, "extra"], 1);
  runBesa(
    "reject unsupported flag",
    ["load", manifest, "--trust", "unused.json"],
    1,
  );
  runBesa(
    "reject incomplete grant context",
    ["admit", signed, "crm.lookup", "--agent", "agent-alpha"],
    1,
  );
  runBesa("admit", ["admit", signed, "crm.lookup"]);
  runBesa(
    "receipt",
    ["receipt", "crm.lookup", signed, "--request", request],
  );
  runBesa(
    "verify receipt",
    ["verify-receipt", latestReceipt(), signed],
  );

  console.log("PACKAGE SMOKE OK: tarball SDK and CLI are installable");
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
