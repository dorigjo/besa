import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

process.env.BESA_KEY_PASSPHRASE ??= randomBytes(32).toString("base64url");

const repositoryRoot = resolve(".");
const UPGRADE_BASE_COMMIT = "082157830006d8497bf2ba5c162e8503772b4a9b";
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
  runBesa("binary demo", ["demo"]);
  run(
    "SDK import",
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      "const b = await import('@dorigjo/besa'); " +
        "if (typeof b.signManifest !== 'function' || " +
        "typeof b.verifyTrustedSignedManifest !== 'function' || " +
        "typeof b.withBesa !== 'function' || " +
        "typeof b.withBesaMcp !== 'function' || " +
        "typeof b.verifyActionCapability !== 'function') process.exit(1);",
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
  const installedPackage = join(installRoot, "node_modules", "@dorigjo", "besa");
  for (const relativePath of [
    "Dockerfile",
    "ARCHITECTURE.md",
    "AUDIT_SCOPE.md",
    "SECURITY.md",
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
    "docs/adoption/DISCOVERY_AUDIT.md",
    "docs/adoption/INTEGRATION_TARGETS.md",
    "docs/assets/besa-architecture.svg",
    "examples/action-policy.yaml",
    "examples/consequential-mcp-middleware.ts",
    "examples/generic-tool-wrapper.ts",
    "examples/http-middleware.ts",
    "examples/hosted-verifier.env.example",
    "scripts/traction-report.mjs",
    "conformance/golden-v1.json",
    "conformance/consequential-action-v1.json",
    "conformance/consequential-action-negative-v1.json",
  ]) {
    if (!existsSync(join(installedPackage, relativePath))) {
      throw new Error(`installed package is missing ${relativePath}`);
    }
  }
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

  const upgradeRoot = join(workspace, "upgrade");
  const v1Source = join(workspace, "v1-source");
  const v1Archive = join(workspace, "v1-source.tar");
  mkdirSync(v1Source, { recursive: true });
  run(
    "archive immutable Besa 1.0.1 source",
    "git",
    ["archive", "--format=tar", `--output=${v1Archive}`, UPGRADE_BASE_COMMIT],
    repositoryRoot,
  );
  run("extract immutable Besa 1.0.1 source", "tar", ["-xf", v1Archive, "-C", v1Source], repositoryRoot);
  runNpm(
    "install v1 build dependencies",
    ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    v1Source,
  );
  runNpm("pack immutable Besa 1.0.1 source", ["pack", "--silent", "--pack-destination", workspace], v1Source);
  const v1Tarball = readdirSync(workspace)
    .filter((entry) => entry.endsWith("-1.0.1.tgz"))
    .map((entry) => join(workspace, entry))
    .at(0);
  if (!v1Tarball) {
    throw new Error("pinned upgrade base did not produce a Besa 1.0.1 tarball");
  }

  mkdirSync(upgradeRoot, { recursive: true });
  writeFileSync(
    join(upgradeRoot, "package.json"),
    JSON.stringify({ private: true, type: "module" }, null, 2) + "\n",
    "utf8",
  );
  runNpm(
    "install repository v1 tarball",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", v1Tarball],
    upgradeRoot,
  );
  const upgradePackageJson = join(
    upgradeRoot,
    "node_modules",
    "@dorigjo",
    "besa",
    "package.json",
  );
  if (JSON.parse(readFileSync(upgradePackageJson, "utf8")).version !== "1.0.1") {
    throw new Error("upgrade fixture did not install Besa 1.0.1");
  }
  runNpm(
    "upgrade v1 to local tarball",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
    upgradeRoot,
  );
  if (JSON.parse(readFileSync(upgradePackageJson, "utf8")).version !== "1.1.1") {
    throw new Error("local tarball did not upgrade Besa to 1.1.1");
  }

  console.log("PACKAGE SMOKE OK: tarball SDK/CLI install and v1 upgrade passed");
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
