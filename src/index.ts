#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import { userInfo } from "node:os";
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
  createHostedVerifierServer,
  type HostedVerifierAdmissionOptions,
  type HostedVerifierRateLimitOptions,
} from "./server/hosted-verifier.js";
import {
  createReceipt,
  hashRequest,
  signManifest,
  validateReceipt,
  validateSignedManifest,
  verifyReceiptDetailed,
  verifySignedManifest,
} from "./signing.js";
import { createEvidenceEnvelope } from "./evidence.js";
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
  readUtf8File,
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
  "--key-file",
  "--passphrase-file",
  "--port",
  "--meter",
  "--rate-limit",
  "--host",
]);
const COMMAND_FLAGS: Record<string, ReadonlySet<string>> = {
  keys: new Set(["--trust", "--key-file", "--passphrase-file"]),
  trust: new Set(["--trust"]),
  load: new Set(),
  sign: new Set(["--trust", "--key-file", "--passphrase-file"]),
  verify: new Set(["--trust"]),
  admit: new Set(["--trust", "--agent", "--grants"]),
  receipt: new Set([
    "--trust",
    "--request",
    "--agent",
    "--grants",
    "--key-file",
    "--passphrase-file",
  ]),
  "verify-receipt": new Set(["--trust", "--request"]),
  "export-evidence": new Set(["--trust"]),
  serve: new Set([
    "--port",
    "--host",
    "--trust",
    "--key-file",
    "--passphrase-file",
    "--meter",
    "--rate-limit",
  ]),
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

  if (process.platform !== "win32") {
    chmodSync(path, 0o600);
    return;
  }

  // POSIX chmod has no effect on Windows; restrict the ACL to the current
  // user instead. Best-effort: a failure here (no icacls, exotic filesystem)
  // must not block key operations, since the file is still scrypt+AES-GCM
  // sealed at rest — but it is surfaced, not swallowed silently.
  try {
    const { username } = userInfo();
    execFileSync(
      "icacls",
      [path, "/inheritance:r", "/grant:r", `${username}:F`],
      { stdio: "ignore" },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(
      `WARNING: could not restrict Windows ACL on ${terminalText(path)}: ${terminalText(message)}`,
    );
  }
}

function selectedKeyPath(): string {
  const path = flagValue("--key-file") ?? KEY_PATH;
  if (!path.endsWith(".json")) {
    throw new Error(`key file path must end in .json: ${terminalText(path)}`);
  }
  return path;
}

// Reads a passphrase from a file, stripping exactly one trailing line
// terminator (as a text editor or `echo` would add). Never logs the path's
// contents; a symbolic link is rejected the same way protectKeyFile() rejects
// one for the key file itself.
function readPassphraseFile(path: string): string {
  if (lstatSync(path).isSymbolicLink()) {
    throw new Error(`refusing to read passphrase through symbolic link at ${path}`);
  }
  return readUtf8File(path).replace(/\r?\n$/, "");
}

function readPassphraseStdin(): string {
  return readFileSync(0, "utf8").replace(/\r?\n$/, "");
}

// Priority order: --passphrase-file <path> (or "-" for stdin), then the
// BESA_KEY_PASSPHRASE environment variable as a fallback. The passphrase
// value itself is never logged, printed, or included in any error message.
function keyPassphrase(): string {
  const passphraseFile = flagValue("--passphrase-file");

  const passphrase =
    passphraseFile === "-"
      ? readPassphraseStdin()
      : (passphraseFile ? readPassphraseFile(passphraseFile) : undefined) ??
        process.env.BESA_KEY_PASSPHRASE;

  if (!passphrase) {
    throw new Error(
      "a key passphrase is required: pass --passphrase-file <path>, --passphrase-file - (stdin), " +
        "or set BESA_KEY_PASSPHRASE (at least 16 UTF-8 bytes)",
    );
  }

  return passphrase;
}

function loadExistingKeyPair(path = selectedKeyPath()): KeyPair {
  if (!existsSync(path)) {
    throw new Error(`no signing key found at ${path}; run besa keys first`);
  }

  ensureBesaDir();
  protectKeyFile(path);

  const stored = readJson<unknown>(path);
  const passphrase = keyPassphrase();

  if (isStoredKeyPair(stored)) {
    return openKeyPair(stored, passphrase);
  }

  if (!validateKeyPair(stored)) {
    throw new Error(`invalid or mismatched Ed25519 key pair at ${path}`);
  }

  writeJson(path, sealKeyPair(stored, passphrase), 0o600);
  return stored;
}

function loadOrCreateKeyPair(): KeyPair {
  ensureBesaDir();
  const path = selectedKeyPath();

  if (existsSync(path)) {
    return loadExistingKeyPair(path);
  }

  const keypair = generateKeyPair();
  try {
    writeJsonExclusive(
      path,
      sealKeyPair(keypair, keyPassphrase()),
      0o600,
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return loadExistingKeyPair(path);
    }
    throw error;
  }
  protectKeyFile(path);
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
  const keyPath = selectedKeyPath();
  const previous = loadExistingKeyPair(keyPath);
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
  writeJson(keyPath, sealedNext, 0o600);
  protectKeyFile(keyPath);
  saveTrustStore(rotatedStore, path);

  printJson("keyRotation", rotation);
  console.log("");
  console.log(`OK: active key rotated to ${rotation.newPublicKeyId}`);
  console.log(`OK: previous private key archived at ${terminalText(archivePath)}`);
  console.log(`OK: rotation proof written to ${terminalText(rotationPath)}`);
  console.log("NEXT: re-sign active manifests with the new key");
}

function formatFingerprint(hex: string): string {
  const pairs: string[] = [];
  for (let index = 0; index < hex.length; index += 2) {
    pairs.push(hex.slice(index, index + 2));
  }
  return pairs.join(":");
}

function cmdKeyFingerprint(): void {
  if (flagValue("--trust")) {
    throw new Error("--trust is only supported by keys rotate");
  }

  const keypair = loadExistingKeyPair();
  console.log(formatFingerprint(publicKeyId(keypair.publicKeyDer)));
}

function cmdExportPublicKey(): void {
  if (flagValue("--trust")) {
    throw new Error("--trust is only supported by keys rotate");
  }

  const keypair = loadExistingKeyPair();
  console.log(keypair.publicKeyDer);
}

function cmdKeys(action?: string): void {
  if (action === "rotate") {
    cmdRotateKeys();
    return;
  }

  if (action === "fingerprint") {
    cmdKeyFingerprint();
    return;
  }

  if (action === "export-public") {
    cmdExportPublicKey();
    return;
  }

  if (action) {
    throw new Error(`unknown keys action '${action}'`);
  }

  if (flagValue("--trust")) {
    throw new Error("--trust is only supported by keys rotate");
  }

  const path = selectedKeyPath();
  const keypair = loadOrCreateKeyPair();

  printJson("keypair", {
    publicKeyDer: keypair.publicKeyDer,
    privateKeyDerPath: path,
  });

  console.log("");
  console.log("OK: keypair ready at " + path);
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

const DEFAULT_SERVE_PORT = 8787;
const DEFAULT_SERVE_HOST = "127.0.0.1";

function cmdServe(): void {
  const portFlag = flagValue("--port");
  const port = portFlag !== undefined ? Number(portFlag) : DEFAULT_SERVE_PORT;

  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) {
    throw new Error(`--port must be an integer between 0 and 65535, got '${portFlag ?? ""}'`);
  }

  // Bind to loopback only by default: Node's http.Server.listen(port) with
  // no host argument binds every interface, which silently exposed this
  // server to the local network even though the startup banner below says
  // "localhost." --host opts in to a wider bind explicitly.
  const host = flagValue("--host") ?? DEFAULT_SERVE_HOST;

  // Admission is opt-in: only enabled when --trust is explicitly given.
  // Without it, `besa serve` is byte-identical to Phase 5 behavior (no key
  // ever loaded, no trust store ever touched). loadExistingKeyPair() is
  // used deliberately instead of loadOrCreateKeyPair() — a server process
  // must never silently mint a new signing identity on startup.
  const trustFlag = flagValue("--trust");
  let admission: HostedVerifierAdmissionOptions | undefined;

  if (trustFlag !== undefined) {
    const trustStore = loadTrustStore(trustFlag);
    const keypair = loadExistingKeyPair();
    const meterPath = flagValue("--meter") ?? METER_PATH;
    admission = { trustStore, meterPath, keyPair: keypair };
  }

  const rateLimitFlag = flagValue("--rate-limit");
  let rateLimit: HostedVerifierRateLimitOptions | undefined;
  if (rateLimitFlag !== undefined) {
    const limit = Number(rateLimitFlag);
    if (!Number.isSafeInteger(limit) || limit <= 0) {
      throw new Error(`--rate-limit must be a positive integer, got '${rateLimitFlag}'`);
    }
    rateLimit = { limit };
  }

  const server = createHostedVerifierServer({ admission, rateLimit });

  server.listen(port, host, () => {
    const address = server.address();
    const boundPort = typeof address === "object" && address !== null ? address.port : port;
    console.log(`Besa hosted verifier listening on http://${host}:${String(boundPort)}`);
    if (host !== DEFAULT_SERVE_HOST) {
      console.log(`WARNING: bound to ${host}, not loopback-only — reachable beyond this machine.`);
    }
    console.log("");

    if (admission) {
      console.log("Admission attestation ENABLED: POST /v1/admit issues signed,");
      console.log("non-consuming AdmissionAttestations. This process holds signing");
      console.log("key material in memory for the lifetime of the server.");
      console.log("See docs/RUNTIME_ADMISSION.md for the guarantee/non-guarantee statement.");
    } else {
      console.log("Signature verification only: no trust-store check, no admission,");
      console.log("no receipt issuance. Never loads a signing key.");
    }

    if (rateLimit) {
      console.log(`Rate limiting ENABLED: ${String(rateLimit.limit)} requests/min per client.`);
    }
    console.log("GET /metrics exposes aggregate request counters.");
    console.log("See docs/HOSTED_VERIFIER.md for the endpoint reference and limitations.");
  });

  // Ensure Ctrl+C / a process manager's SIGTERM closes listening sockets
  // cleanly instead of the process dying mid-request; also stops the event
  // loop from lingering on an open server handle.
  const shutdown = (): void => {
    server.close(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
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

function grantGate(toolName: string): AdmissionDecision | undefined {
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

  // A receipt is issued for BOTH outcomes. When manifest/trust verification
  // fails, the deny below is intentional and load-bearing: it produces a
  // tamper-evident, signed record that the call was refused, carrying the
  // verification failure code as its reasonCode. Verify-receipt later replays
  // the same manifest/trust chain, so a deny receipt is durable evidence of a
  // refusal — not a soft error to be swallowed.
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

  // An allow receipt asserts a tool the signed manifest actually declares. A
  // deny receipt may legitimately name an undeclared tool (that is exactly what
  // a TOOL_NOT_FOUND deny records), so this binding applies to allows only.
  if (
    receipt.decision === "allow" &&
    !signed.manifest.tools.some((tool) => tool.name === receipt.toolName)
  ) {
    const result = {
      valid: false,
      reasonCode: "E_RECEIPT_TOOL_NOT_DECLARED",
      detail:
        "allow receipt references a tool not declared in the signed manifest",
    };
    printJson("verifyReceipt", result);
    process.exitCode = 1;
    return;
  }

  // Optional request binding: when the caller supplies the original request
  // payload, prove it hashes to the requestHash sealed inside the receipt. Not
  // required by default, so existing verify-receipt invocations are unchanged.
  const requestPath = flagValue("--request");
  if (requestPath !== undefined) {
    const boundRequest = readJson<unknown>(requestPath);
    if (hashRequest(boundRequest) !== receipt.requestHash) {
      const result = {
        valid: false,
        reasonCode: "E_RECEIPT_REQUEST_MISMATCH",
        detail: "supplied request does not hash to the receipt requestHash",
      };
      printJson("verifyReceipt", result);
      process.exitCode = 1;
      return;
    }
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

// Exports an already-signed manifest + receipt as a structured, auditor-
// facing document (see docs/EVIDENCE_ENVELOPE.md). Reuses the same
// verification path as `verify`/`verify-receipt`; issues no new signature
// and mints no new trust decision — it is a read-only formatting step over
// already-verifiable evidence.
function cmdExportEvidence(manifestFile: string, receiptFile: string): void {
  const signed = requireSignedManifest(readJson<unknown>(manifestFile));
  const receiptValidation = validateReceipt(readJson<unknown>(receiptFile));

  if (!receiptValidation.ok || !receiptValidation.receipt) {
    throw new Error(
      `invalid receipt:\n  - ${receiptValidation.errors.join("\n  - ")}`,
    );
  }

  const trustStore = loadTrustStore();
  const envelope = createEvidenceEnvelope(
    signed,
    receiptValidation.receipt,
    trustStore,
  );
  const outPath = receiptFile.endsWith(".json")
    ? receiptFile.slice(0, -5) + ".evidence.json"
    : receiptFile + ".evidence.json";

  writeJson(outPath, envelope);
  printJson("evidenceEnvelope", envelope);
  console.log("");
  console.log("OK: evidence envelope written to " + terminalText(outPath));

  if (!envelope.verification.manifestTrusted || !envelope.verification.receiptSignatureValid) {
    console.log(
      "WARNING: this envelope's verification block reports a FAILURE — inspect it before relying on this export.",
    );
    process.exitCode = 1;
  }
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
      "Besa - cryptographic admission and evidence infrastructure for AI-agent execution",
      "",
      "Usage:",
      "  besa <command> [arguments] [options]",
      "  besa --help | --version",
      "",
      "Commands:",
      "  keys                 Show the local signing key, generating one if absent",
      "  keys rotate          Rotate the signing key and emit a signed rotation proof",
      "  keys fingerprint     Print the local public key's SHA-256 fingerprint",
      "  keys export-public   Print the local public key (base64 DER) alone",
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
      "  export-evidence      Export a signed manifest + receipt as an audit-facing",
      "                       evidence envelope (see docs/EVIDENCE_ENVELOPE.md)",
      "  serve                Run the hosted verifier (signature checks only by default;",
      "                       pass --trust to also enable POST /v1/admit)",
      "",
      "Options:",
      "  --trust <file>       Trust store path (default: .besa/trust.json)",
      "  --agent <id>         Scope admission to a named agent (admit, receipt)",
      "  --grants <file>      Grant set for agent-scoped admission (admit, receipt)",
      "  --request <file>     Request payload hashed into the receipt (receipt);",
      "                       re-checked against receipt.requestHash (verify-receipt)",
      "  --key-file <file>    Signing key path (default: .besa/key.json)",
      "                       (keys, sign, receipt)",
      "  --passphrase-file <file>",
      "                       Read the key passphrase from a file, or from stdin",
      "                       if <file> is '-' (keys, sign, receipt); falls back",
      "                       to BESA_KEY_PASSPHRASE if omitted",
      "  --port <n>           Port for the hosted verifier (default: 8787) (serve)",
      "  --host <addr>        Bind address for the hosted verifier (default: 127.0.0.1,",
      "                       loopback-only; serve)",
      "  --meter <file>       Meter state path for admission checks (serve; default: .besa/meter.json)",
      "                       (serve, requires --trust to take effect)",
      "  --rate-limit <n>     Max requests per minute per client address (serve)",
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
      "  besa verify-receipt .besa/receipts/<receipt-id>.json examples/manifest.signed.json --request examples/request.json",
      "  besa export-evidence examples/manifest.signed.json .besa/receipts/<receipt-id>.json",
      "  besa serve --port 8787",
      "  besa serve --port 8787 --trust .besa/trust.json",
      "  besa serve --port 8787 --rate-limit 60",
      "",
      "Security:",
      "  Private keys are encrypted at rest (AES-256-GCM + scrypt).",
      "  Never commit the .besa/ directory.",
      "  Review SECURITY.md and the trust model before production deployment.",
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

      case "export-evidence":
        requireArgs(args, 2, command);
        cmdExportEvidence(args[0] ?? "", args[1] ?? "");
        break;

      case "serve":
        requireArgs(args, 0, command, 0);
        cmdServe();
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
