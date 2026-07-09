#!/usr/bin/env node

import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  AdmissionDecision,
  KeyRotation,
  Receipt,
  SignedManifest,
  TrustStore,
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
  hashRequest,
  signManifest,
  validateReceipt,
  validateSignedManifest,
  verifyReceiptDetailed,
  verifySignedManifest,
} from "./signing.js";
import {
  admit,
  admitAndConsume,
  getCount,
  loadMeter,
  meterKey,
} from "./admit.js";
import { checkGrant, loadGrants } from "./grant.js";
import {
  addTrustAnchor,
  applyKeyRotation,
  checkTrustedKey,
  createKeyRotation,
  emptyTrustStore,
  revokeTrustAnchor,
  validateTrustStore,
  verifyKeyRotation,
  verifyTrustedSignedManifest,
} from "./trust.js";
import {
  readJsonFile,
  writeJsonAtomic,
  writeJsonExclusive,
} from "./io.js";
import {
  isStoredKeyPair,
  openKeyPair,
  sealKeyPair,
} from "./keystore.js";

const BESA_DIR = ".besa";
const KEY_PATH = join(BESA_DIR, "key.json");
const KEYS_DIR = join(BESA_DIR, "keys");
const METER_PATH = join(BESA_DIR, "meter.json");
const ACTIVE_MANIFEST_PATH = join(BESA_DIR, "active-manifest.json");
const RECEIPTS_DIR = join(BESA_DIR, "receipts");
const ROTATIONS_DIR = join(BESA_DIR, "rotations");
const TRUST_PATH = join(BESA_DIR, "trust.json");
const FLAGS_WITH_VALUES = new Set([
  "--agent",
  "--grants",
  "--request",
  "--trust",
]);
const COMMAND_FLAGS: Record<string, ReadonlySet<string>> = {
  keys: new Set(["--trust"]),
  trust: new Set(["--trust"]),
  load: new Set(),
  sign: new Set(["--trust"]),
  verify: new Set(["--trust"]),
  admit: new Set(["--trust", "--agent", "--grants"]),
  receipt: new Set([
    "--trust",
    "--request",
    "--agent",
    "--grants",
  ]),
  "verify-receipt": new Set(["--trust"]),
};

function readJson<T>(path: string): T {
  return readJsonFile(path) as T;
}

function writeJson(path: string, value: unknown, mode?: number): void {
  writeJsonAtomic(path, value, mode ?? 0o600);
}

function ensureBesaDir(): void {
  mkdirSync(BESA_DIR, { recursive: true, mode: 0o700 });
  const stats = lstatSync(BESA_DIR);

  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error(`${BESA_DIR} must be a real private directory, not a link`);
  }

  if (process.platform !== "win32") chmodSync(BESA_DIR, 0o700);
}

function protectKeyFile(path = KEY_PATH): void {
  if (lstatSync(path).isSymbolicLink()) {
    throw new Error(`refusing to use symbolic-link key file at ${path}`);
  }

  if (process.platform !== "win32") chmodSync(path, 0o600);
}

function keyPassphrase(): string {
  const passphrase = process.env.BESA_KEY_PASSPHRASE;
  if (!passphrase) {
    throw new Error(
      "BESA_KEY_PASSPHRASE is required and must contain at least 16 UTF-8 bytes",
    );
  }
  return passphrase;
}

function loadExistingKeyPair(): KeyPair {
  if (!existsSync(KEY_PATH)) {
    throw new Error(`no signing key found at ${KEY_PATH}; run besa keys first`);
  }

  ensureBesaDir();
  protectKeyFile();

  const stored = readJson<unknown>(KEY_PATH);
  const passphrase = keyPassphrase();

  if (isStoredKeyPair(stored)) {
    return openKeyPair(stored, passphrase);
  }

  if (!validateKeyPair(stored)) {
    throw new Error(`invalid or mismatched Ed25519 key pair at ${KEY_PATH}`);
  }

  writeJson(KEY_PATH, sealKeyPair(stored, passphrase), 0o600);
  return stored;
}

function loadOrCreateKeyPair(): KeyPair {
  ensureBesaDir();

  if (existsSync(KEY_PATH)) {
    return loadExistingKeyPair();
  }

  const keypair = generateKeyPair();
  try {
    writeJsonExclusive(
      KEY_PATH,
      sealKeyPair(keypair, keyPassphrase()),
      0o600,
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return loadExistingKeyPair();
    }
    throw error;
  }
  protectKeyFile();
  return keypair;
}

function terminalText(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");
}

function selectedTrustPath(): string {
  const path = flagValue("--trust") ?? TRUST_PATH;
  if (!path.endsWith(".json")) {
    throw new Error(`trust store path must end in .json: ${terminalText(path)}`);
  }
  return path;
}

function loadTrustStore(path = selectedTrustPath()): TrustStore {
  if (!existsSync(path)) {
    throw new Error(
      `no trust store found at ${path}; run besa trust add <signed-manifest> first`,
    );
  }

  if (lstatSync(path).isSymbolicLink()) {
    throw new Error(`refusing to use symbolic-link trust store at ${path}`);
  }

  const validation = validateTrustStore(readJson<unknown>(path));

  if (!validation.ok || !validation.trustStore) {
    throw new Error(
      `invalid trust store at ${path}:\n  - ${validation.errors.join("\n  - ")}`,
    );
  }

  return validation.trustStore;
}

function loadOrCreateTrustStore(path = selectedTrustPath()): TrustStore {
  return existsSync(path) ? loadTrustStore(path) : emptyTrustStore();
}

function saveTrustStore(store: TrustStore, path = selectedTrustPath()): void {
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) {
    throw new Error(`refusing to write to symbolic-link trust store at ${path}`);
  }

  const validation = validateTrustStore(store);

  if (!validation.ok) {
    throw new Error(`refusing to save invalid trust store: ${validation.errors.join("; ")}`);
  }

  writeJson(path, store, 0o600);
}

function trustSignedManifestKey(signed: SignedManifest): void {
  const path = selectedTrustPath();
  const store = addTrustAnchor(loadOrCreateTrustStore(path), signed.publicKey);
  saveTrustStore(store, path);
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
  if (index < 0) {
    return undefined;
  }

  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }

  return value;
}

function positionals(
  args: string[],
  allowedFlags: ReadonlySet<string>,
): string[] {
  const values: string[] = [];
  const seenFlags = new Set<string>();

  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];

    if (value?.startsWith("-")) {
      if (!FLAGS_WITH_VALUES.has(value)) {
        throw new Error(`unknown flag '${value}'`);
      }

      if (!allowedFlags.has(value)) {
        throw new Error(`flag '${value}' is not supported by this command`);
      }

      if (seenFlags.has(value)) {
        throw new Error(`duplicate flag '${value}'`);
      }

      const flagArgument = args[index + 1];
      if (!flagArgument || flagArgument.startsWith("--")) {
        throw new Error(`${value} requires a value`);
      }

      seenFlags.add(value);
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

function cmdRotateKeys(): void {
  const previous = loadExistingKeyPair();
  const next = generateKeyPair();
  const rotation = createKeyRotation(previous, next);
  const previousId = rotation.previousPublicKeyId;
  const archivePath = join(KEYS_DIR, `${previousId}.json`);
  const rotationPath = join(
    ROTATIONS_DIR,
    `${previousId}-to-${rotation.newPublicKeyId}.json`,
  );
  const path = selectedTrustPath();
  const anchored = addTrustAnchor(
    loadOrCreateTrustStore(path),
    previous.publicKeyDer,
  );
  const rotatedStore = applyKeyRotation(anchored, rotation);

  const passphrase = keyPassphrase();

  // Pre-compute all crypto before touching the filesystem.
  // If scrypt or key derivation throws, no files are written.
  const sealedPrevious = sealKeyPair(previous, passphrase);
  const sealedNext = sealKeyPair(next, passphrase);

  writeJson(archivePath, sealedPrevious, 0o600);
  protectKeyFile(archivePath);
  writeJson(rotationPath, rotation);
  writeJson(KEY_PATH, sealedNext, 0o600);
  protectKeyFile();
  saveTrustStore(rotatedStore, path);

  printJson("keyRotation", rotation);
  console.log("");
  console.log(`OK: active key rotated to ${rotation.newPublicKeyId}`);
  console.log(`OK: previous private key archived at ${terminalText(archivePath)}`);
  console.log(`OK: rotation proof written to ${terminalText(rotationPath)}`);
  console.log("NEXT: re-sign active manifests with the new key");
}

function cmdKeys(action?: string): void {
  if (action === "rotate") {
    cmdRotateKeys();
    return;
  }

  if (action) {
    throw new Error(`unknown keys action '${action}'`);
  }

  if (flagValue("--trust")) {
    throw new Error("--trust is only supported by keys rotate");
  }

  const keypair = loadOrCreateKeyPair();

  printJson("keypair", {
    publicKeyDer: keypair.publicKeyDer,
    privateKeyDerPath: KEY_PATH,
  });

  console.log("");
  console.log("OK: keypair ready at " + KEY_PATH);
}

function cmdTrustAdd(file: string): void {
  const raw = readJson<unknown>(file);
  const verification = verifySignedManifest(raw);

  if (!verification.valid) {
    throw new Error(`${verification.reasonCode}: ${verification.detail}`);
  }

  const signed = requireSignedManifest(raw);
  const path = selectedTrustPath();
  const store = addTrustAnchor(
    loadOrCreateTrustStore(path),
    signed.publicKey,
  );
  saveTrustStore(store, path);

  console.log(
    `OK: trusted public key ${signed.publicKeyId} in ${terminalText(path)}`,
  );
}

function cmdTrustApply(file: string): void {
  const rotation = readJson<KeyRotation>(file);
  const verification = verifyKeyRotation(rotation);

  if (!verification.valid) {
    throw new Error(`${verification.reasonCode}: ${verification.detail}`);
  }

  const path = selectedTrustPath();
  const store = applyKeyRotation(loadTrustStore(path), rotation);
  saveTrustStore(store, path);

  console.log(
    `OK: retired ${rotation.previousPublicKeyId} and trusted ${rotation.newPublicKeyId}`,
  );
}

function cmdTrustRevoke(keyId: string): void {
  const path = selectedTrustPath();
  const store = revokeTrustAnchor(loadTrustStore(path), keyId);
  saveTrustStore(store, path);
  console.log(`OK: revoked public key ${keyId} in ${terminalText(path)}`);
}

function cmdTrustList(): void {
  const path = selectedTrustPath();
  const store = loadTrustStore(path);
  printJson("trustStore", store);
  console.log("");
  console.log(`OK: loaded ${String(store.keys.length)} trust anchor(s) from ${terminalText(path)}`);
}

function cmdTrust(action: string, value?: string): void {
  switch (action) {
    case "add":
      if (!value) {
        throw new Error("trust add requires a signed manifest path");
      }
      cmdTrustAdd(value);
      break;
    case "apply":
      if (!value) {
        throw new Error("trust apply requires a key rotation path");
      }
      cmdTrustApply(value);
      break;
    case "revoke":
      if (!value) {
        throw new Error("trust revoke requires a public key id");
      }
      cmdTrustRevoke(value);
      break;
    case "list":
      if (value) {
        throw new Error("trust list does not accept a positional value");
      }
      cmdTrustList();
      break;
    default:
      throw new Error(`unknown trust action '${action}'`);
  }
}

function cmdLoad(file: string): void {
  const manifest = loadManifest(file);
  printJson("manifest", manifest);
  console.log("");
  console.log(
    "OK: loaded " + String(manifest.tools.length) + " tool(s) from " + terminalText(file),
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
  trustSignedManifestKey(signed);

  printJson("signedManifest", signed);
  console.log("");
  console.log(
    "OK: signed -> " + terminalText(out) + " with publicKeyId " + signed.publicKeyId,
  );
  console.log("OK: public key anchored in " + terminalText(selectedTrustPath()));
}

function cmdVerify(file: string): void {
  const signed = readJson<unknown>(file);
  const result = verifyTrustedSignedManifest(signed, loadTrustStore());

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
  const agentId = flagValue("--agent");

  if (Boolean(grantsPath) !== Boolean(agentId)) {
    throw new Error("--agent and --grants must be provided together");
  }

  if (!grantsPath) {
    return undefined;
  }

  const grant = checkGrant(loadGrants(grantsPath), agentId ?? "", toolName);

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
  const verified = verifyTrustedSignedManifest(
    raw,
    loadTrustStore(),
    "admit",
  );

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
  console.log("");
  console.log(
    "[dry-run: budget not consumed — use 'besa receipt' to enforce and record]",
  );

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
  const request = readRequest(toolName);
  void hashRequest(request);

  if (publicKeyId(keypair.publicKeyDer) !== signed.publicKeyId) {
    throw new Error(
      "local receipt key does not match the signed manifest publicKeyId",
    );
  }

  const verified = verifyTrustedSignedManifest(
    signed,
    loadTrustStore(),
    "admit",
  );
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
      decision = admitAndConsume(
        METER_PATH,
        signed.manifestHash,
        signed.manifest,
        toolName,
      );

      if (grantDecision?.agentId) {
        decision.agentId = grantDecision.agentId;
      }
    }
  }

  const receipt = createReceipt(
    {
      manifestHash: signed.manifestHash,
      toolName,
      decision: decision.decision,
      reasonCode: decision.reasonCode,
      request,
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
  const trustStore = loadTrustStore();
  const manifestVerification = verifyTrustedSignedManifest(
    signedRaw,
    trustStore,
  );

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

  const signatureResult = verifyReceiptDetailed(receipt, signed.publicKey);
  const result = signatureResult.valid
    ? checkTrustedKey(trustStore, signed.publicKey, receipt.timestamp)
    : signatureResult;
  printJson("verifyReceipt", result);

  if (!result.valid) {
    process.exitCode = 1;
    return;
  }

  console.log("");
  console.log("OK: receipt and signed manifest form a valid trust chain");
}

function readVersion(): string {
  try {
    const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
    const pkg = readJsonFile(join(packageRoot, "package.json")) as {
      version?: unknown;
    };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

function usage(): void {
  console.log(
    [
      "Besa - signed trust infrastructure for AI-agent tools",
      "",
      "Usage:",
      "  besa <command> [arguments] [options]",
      "  besa --help | --version",
      "",
      "Commands:",
      "  keys                 Show the local signing key, generating one if absent",
      "  keys rotate          Rotate the signing key and emit a signed rotation proof",
      "  trust add            Anchor a signed manifest's public key in a trust store",
      "  trust apply          Apply a signed rotation proof to a trust store",
      "  trust revoke         Revoke a public key in a trust store",
      "  trust list           List trusted, retired, and revoked keys",
      "  load                 Load and validate a manifest (YAML or JSON)",
      "  sign                 Sign a manifest and anchor the publisher key",
      "  verify               Verify a signed manifest against a trust store",
      "  admit                Check whether a tool call is allowed (dry-run)",
      "  receipt              Enforce budget and issue a signed execution receipt",
      "  verify-receipt       Verify a receipt and its manifest trust chain",
      "",
      "Options:",
      "  --trust <file>       Trust store path (default: .besa/trust.json)",
      "  --agent <id>         Scope admission to a named agent (admit, receipt)",
      "  --grants <file>      Grant set for agent-scoped admission (admit, receipt)",
      "  --request <file>     Request payload hashed into the receipt (receipt)",
      "",
      "Examples:",
      "  besa keys",
      "  besa sign examples/manifest.yaml",
      "  besa trust add examples/manifest.signed.json --trust consumer-trust.json",
      "  besa verify examples/manifest.signed.json",
      "  besa admit examples/manifest.signed.json crm.lookup",
      "  besa admit examples/manifest.signed.json crm.lookup --agent agent-alpha --grants examples/grants.yaml",
      "  besa receipt crm.lookup examples/manifest.signed.json --request examples/request.json",
      "  besa verify-receipt .besa/receipts/<receipt-id>.json examples/manifest.signed.json",
      "",
      "Security:",
      "  Local early-access developer preview. Private keys are encrypted at rest (AES-256-GCM + scrypt).",
      "  Never commit the .besa/ directory. Not hardened for production use yet.",
    ].join("\n"),
  );
}

function requireArgs(
  args: string[],
  minimum: number,
  command: string,
  maximum = minimum,
): void {
  if (args.length < minimum || args.length > maximum) {
    const expected =
      minimum === maximum
        ? String(minimum)
        : `${String(minimum)}-${String(maximum)}`;
    throw new Error(
      `${command} requires ${expected} argument(s), received ${String(args.length)}`,
    );
  }
}

function main(argv: string[]): void {
  const command = argv[0] ?? "";

  try {
    const allowedFlags = COMMAND_FLAGS[command] ?? new Set<string>();
    const args = positionals(argv.slice(1), allowedFlags);

    switch (command) {
      case "keys":
        requireArgs(args, 0, command, 1);
        cmdKeys(args[0]);
        break;

      case "trust":
        requireArgs(args, 1, command, 2);
        cmdTrust(args[0] ?? "", args[1]);
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
        requireArgs(args, 1, command, 2);
        cmdReceipt(args[0] ?? "", args[1]);
        break;

      case "verify-receipt":
        requireArgs(args, 1, command, 2);
        cmdVerifyReceipt(args[0] ?? "", args[1]);
        break;

      case "version":
      case "--version":
      case "-v":
        console.log("besa " + readVersion());
        break;

      case "":
      case "help":
      case "--help":
      case "-h":
        usage();
        break;

      default:
        console.error("Unknown command: " + terminalText(command));
        usage();
        process.exitCode = 1;
        break;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Error: " + terminalText(message));
    process.exitCode = 1;
  }
}

main(process.argv.slice(2));
