#!/usr/bin/env node

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type {
  AdmissionDecision,
  Receipt,
  SignedManifest,
} from "./types.js";
import {
  generateKeyPair,
  publicKeyId,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import { loadManifest } from "./manifest.js";
import {
  createReceipt,
  signManifest,
  validateReceipt,
  validateSignedManifest,
  verifyReceiptDetailed,
  verifySignedManifest,
} from "./signing.js";
import {
  admit,
  getCount,
  increment,
  loadMeter,
  meterKey,
  saveMeter,
} from "./admit.js";
import { checkGrant, loadGrants } from "./grant.js";

const BESA_DIR = ".besa";
const KEY_PATH = join(BESA_DIR, "key.json");
const METER_PATH = join(BESA_DIR, "meter.json");
const ACTIVE_MANIFEST_PATH = join(BESA_DIR, "active-manifest.json");
const RECEIPTS_DIR = join(BESA_DIR, "receipts");
const FLAGS_WITH_VALUES = new Set(["--agent", "--grants", "--request"]);

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function writeJson(path: string, value: unknown, mode?: number): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", {
    encoding: "utf8",
    mode,
  });
}

function ensureBesaDir(): void {
  mkdirSync(BESA_DIR, { recursive: true });
}

function protectKeyFile(): void {
  try {
    chmodSync(KEY_PATH, 0o600);
  } catch {
    // Windows does not apply POSIX file modes. The key remains excluded by .gitignore.
  }
}

function loadExistingKeyPair(): KeyPair {
  if (!existsSync(KEY_PATH)) {
    throw new Error(`no signing key found at ${KEY_PATH}; run besa keys first`);
  }

  const keypair = readJson<unknown>(KEY_PATH);

  if (!validateKeyPair(keypair)) {
    throw new Error(`invalid or mismatched Ed25519 key pair at ${KEY_PATH}`);
  }

  protectKeyFile();
  return keypair;
}

function loadOrCreateKeyPair(): KeyPair {
  ensureBesaDir();

  if (existsSync(KEY_PATH)) {
    return loadExistingKeyPair();
  }

  const keypair = generateKeyPair();
  writeJson(KEY_PATH, keypair, 0o600);
  protectKeyFile();
  return keypair;
}

function printJson(label: string, value: unknown): void {
  console.log("");
  console.log(label + ":");
  console.log(JSON.stringify(value, null, 2));
}

function signedOutPath(manifestPath: string): string {
  if (manifestPath.endsWith(".yaml")) {
    return manifestPath.slice(0, -5) + ".signed.json";
  }

  if (manifestPath.endsWith(".yml")) {
    return manifestPath.slice(0, -4) + ".signed.json";
  }

  if (manifestPath.endsWith(".json")) {
    return manifestPath.slice(0, -5) + ".signed.json";
  }

  return manifestPath + ".signed.json";
}

function flagValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function positionals(args: string[]): string[] {
  const values: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];

    if (value && FLAGS_WITH_VALUES.has(value)) {
      index += 1;
      continue;
    }

    if (value) {
      values.push(value);
    }
  }

  return values;
}

function requireSignedManifest(value: unknown): SignedManifest {
  const validation = validateSignedManifest(value);

  if (!validation.ok || !validation.signedManifest) {
    throw new Error(
      `invalid signed manifest:\n  - ${validation.errors.join("\n  - ")}`,
    );
  }

  return validation.signedManifest;
}

function cmdKeys(): void {
  const keypair = loadOrCreateKeyPair();

  printJson("keypair", {
    publicKeyDer: keypair.publicKeyDer,
    privateKeyDerPath: KEY_PATH,
  });

  console.log("");
  console.log("OK: keypair ready at " + KEY_PATH);
}

function cmdLoad(file: string): void {
  const manifest = loadManifest(file);
  printJson("manifest", manifest);
  console.log("");
  console.log(
    "OK: loaded " + String(manifest.tools.length) + " tool(s) from " + file,
  );
}

function cmdSign(file: string): void {
  const manifest = loadManifest(file);
  const keypair = loadOrCreateKeyPair();
  const signed = signManifest(manifest, keypair);
  const out = signedOutPath(file);

  writeJson(out, signed);
  ensureBesaDir();
  writeJson(ACTIVE_MANIFEST_PATH, signed);

  printJson("signedManifest", signed);
  console.log("");
  console.log(
    "OK: signed -> " + out + " with publicKeyId " + signed.publicKeyId,
  );
}

function cmdVerify(file: string): void {
  const signed = readJson<unknown>(file);
  const result = verifySignedManifest(signed);

  printJson("verify", result);

  if (!result.valid) {
    process.exitCode = 1;
    console.log("");
    console.log("DENY: " + result.reasonCode);
    return;
  }

  console.log("");
  console.log("OK: " + result.detail);
}

function denyFromVerification(
  toolName: string,
  reasonCode: string,
  detail: string,
): AdmissionDecision {
  return {
    decision: "deny",
    reasonCode,
    toolName,
    detail,
  };
}

export function grantGate(toolName: string): AdmissionDecision | undefined {
  const grantsPath = flagValue("--grants");

  if (!grantsPath) {
    return undefined;
  }

  const agentId = flagValue("--agent") ?? "";
  const grant = checkGrant(loadGrants(grantsPath), agentId, toolName);

  return {
    decision: grant.granted ? "allow" : "deny",
    reasonCode: grant.reasonCode,
    toolName,
    detail: grant.detail,
    agentId,
  };
}

function cmdAdmit(file: string, toolName: string): void {
  const raw = readJson<unknown>(file);
  const verified = verifySignedManifest(raw);

  if (!verified.valid) {
    const denied = denyFromVerification(
      toolName,
      verified.reasonCode,
      verified.detail,
    );
    printJson("admission", denied);
    process.exitCode = 1;
    return;
  }

  const signed = requireSignedManifest(raw);
  const grantDecision = grantGate(toolName);

  if (grantDecision && grantDecision.decision === "deny") {
    printJson("admission", grantDecision);
    process.exitCode = 1;
    return;
  }

  const meter = loadMeter(METER_PATH);
  const key = meterKey(signed.manifestHash, toolName);
  const decision = admit(signed.manifest, toolName, getCount(meter, key));

  if (grantDecision?.agentId) {
    decision.agentId = grantDecision.agentId;
  }

  printJson("admission", decision);

  if (decision.decision === "deny") {
    process.exitCode = 1;
  }
}

function readRequest(toolName: string): unknown {
  const requestPath = flagValue("--request");
  return requestPath ? readJson<unknown>(requestPath) : { toolName };
}

function cmdReceipt(toolName: string, file?: string): void {
  const signedPath = file ?? ACTIVE_MANIFEST_PATH;

  if (!existsSync(signedPath)) {
    throw new Error(
      "no signed manifest found at " +
        signedPath +
        "; run besa sign <manifest> first",
    );
  }

  const signed = requireSignedManifest(readJson<unknown>(signedPath));
  const keypair = loadExistingKeyPair();

  if (publicKeyId(keypair.publicKeyDer) !== signed.publicKeyId) {
    throw new Error(
      "local receipt key does not match the signed manifest publicKeyId",
    );
  }

  const verified = verifySignedManifest(signed);
  let decision: AdmissionDecision;
  let grantReasonCode: string | undefined;

  if (!verified.valid) {
    decision = denyFromVerification(
      toolName,
      verified.reasonCode,
      verified.detail,
    );
  } else {
    const grantDecision = grantGate(toolName);
    grantReasonCode = grantDecision?.reasonCode;

    if (grantDecision && grantDecision.decision === "deny") {
      decision = grantDecision;
    } else {
      const meter = loadMeter(METER_PATH);
      const key = meterKey(signed.manifestHash, toolName);
      decision = admit(signed.manifest, toolName, getCount(meter, key));

      if (grantDecision?.agentId) {
        decision.agentId = grantDecision.agentId;
      }

      if (decision.decision === "allow") {
        saveMeter(METER_PATH, increment(meter, key));
      }
    }
  }

  const receipt = createReceipt(
    {
      manifestHash: signed.manifestHash,
      toolName,
      decision: decision.decision,
      reasonCode: decision.reasonCode,
      request: readRequest(toolName),
      agentId: decision.agentId,
      grantReasonCode,
    },
    keypair,
  );

  mkdirSync(RECEIPTS_DIR, { recursive: true });

  const receiptPath = join(RECEIPTS_DIR, receipt.receiptId + ".json");
  writeJson(receiptPath, receipt);

  printJson("receipt", receipt);
  console.log("");
  console.log(
    decision.decision.toUpperCase() +
      ": " +
      decision.reasonCode +
      " -> " +
      receiptPath,
  );

  if (decision.decision === "deny") {
    process.exitCode = 1;
  }
}

function cmdVerifyReceipt(receiptFile: string, manifestFile?: string): void {
  const signedPath = manifestFile ?? ACTIVE_MANIFEST_PATH;

  if (!existsSync(signedPath)) {
    throw new Error(
      "no signed manifest found at " +
        signedPath +
        "; provide one or run besa sign <manifest> first",
    );
  }

  const signedRaw = readJson<unknown>(signedPath);
  const manifestVerification = verifySignedManifest(signedRaw);

  if (!manifestVerification.valid) {
    printJson("verifyReceipt", manifestVerification);
    process.exitCode = 1;
    return;
  }

  const signed = requireSignedManifest(signedRaw);
  const receiptRaw = readJson<unknown>(receiptFile);
  const receiptValidation = validateReceipt(receiptRaw);

  if (!receiptValidation.ok || !receiptValidation.receipt) {
    const result = {
      valid: false,
      reasonCode: "E_RECEIPT_INVALID",
      detail: receiptValidation.errors.join("; "),
    };
    printJson("verifyReceipt", result);
    process.exitCode = 1;
    return;
  }

  const receipt: Receipt = receiptValidation.receipt;

  if (receipt.manifestHash !== signed.manifestHash) {
    const result = {
      valid: false,
      reasonCode: "E_RECEIPT_MANIFEST_MISMATCH",
      detail: "receipt manifestHash does not match the signed manifest",
    };
    printJson("verifyReceipt", result);
    process.exitCode = 1;
    return;
  }

  const result = verifyReceiptDetailed(receipt, signed.publicKey);
  printJson("verifyReceipt", result);

  if (!result.valid) {
    process.exitCode = 1;
    return;
  }

  console.log("");
  console.log("OK: receipt and signed manifest form a valid trust chain");
}

function usage(): void {
  console.log(
    [
      "Besa - signed trust infrastructure for AI-agent tools",
      "",
      "Usage:",
      "  besa keys",
      "  besa load           <manifest.yaml>",
      "  besa sign           <manifest.yaml>",
      "  besa verify         <manifest.signed.json>",
      "  besa admit          <manifest.signed.json> <tool-name> [--agent <agent-id> --grants <grants.yaml>]",
      "  besa receipt        <tool-name> [manifest.signed.json] [--request <request.json>] [--agent <agent-id> --grants <grants.yaml>]",
      "  besa verify-receipt <receipt.json> [manifest.signed.json]",
      "",
      "Examples:",
      "  besa keys",
      "  besa load examples/manifest.yaml",
      "  besa sign examples/manifest.yaml",
      "  besa verify examples/manifest.signed.json",
      "  besa admit examples/manifest.signed.json crm.lookup",
      "  besa admit examples/manifest.signed.json crm.lookup --agent agent-alpha --grants examples/grants.yaml",
      "  besa receipt crm.lookup examples/manifest.signed.json",
      "  besa receipt crm.lookup examples/manifest.signed.json --request examples/request.json",
      "  besa verify-receipt .besa/receipts/<receipt-id>.json examples/manifest.signed.json",
    ].join("\n"),
  );
}

function requireArgs(args: string[], expected: number, command: string): void {
  if (args.length < expected) {
    throw new Error(
      command + " requires " + String(expected) + " argument(s)",
    );
  }
}

function main(argv: string[]): void {
  const command = argv[0] ?? "";
  const args = positionals(argv.slice(1));

  try {
    switch (command) {
      case "keys":
        cmdKeys();
        break;

      case "load":
        requireArgs(args, 1, command);
        cmdLoad(args[0] ?? "");
        break;

      case "sign":
        requireArgs(args, 1, command);
        cmdSign(args[0] ?? "");
        break;

      case "verify":
        requireArgs(args, 1, command);
        cmdVerify(args[0] ?? "");
        break;

      case "admit":
        requireArgs(args, 2, command);
        cmdAdmit(args[0] ?? "", args[1] ?? "");
        break;

      case "receipt":
        requireArgs(args, 1, command);
        cmdReceipt(args[0] ?? "", args[1]);
        break;

      case "verify-receipt":
        requireArgs(args, 1, command);
        cmdVerifyReceipt(args[0] ?? "", args[1]);
        break;

      case "":
      case "help":
      case "--help":
      case "-h":
        usage();
        break;

      default:
        console.error("Unknown command: " + command);
        usage();
        process.exitCode = 1;
        break;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Error: " + message);
    process.exitCode = 1;
  }
}

main(process.argv.slice(2));
