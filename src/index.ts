#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AdmissionDecision, SignedManifest } from "./types.js";
import { generateKeyPair, type KeyPair } from "./crypto.js";
import { loadManifest } from "./manifest.js";
import { createReceipt, signManifest, verifySignedManifest } from "./signing.js";
import { admit, getCount, increment, loadMeter, saveMeter } from "./admit.js";
import { checkGrant, loadGrants } from "./grant.js";

const BESA_DIR = ".besa";
const KEY_PATH = join(BESA_DIR, "key.json");
const METER_PATH = join(BESA_DIR, "meter.json");
const ACTIVE_MANIFEST_PATH = join(BESA_DIR, "active-manifest.json");
const RECEIPTS_DIR = join(BESA_DIR, "receipts");

function readJson<T>(path: string): T {
return JSON.parse(readFileSync(path, "utf8")) as T;
}

function writeJson(path: string, value: unknown): void {
writeFileSync(path, JSON.stringify(value, null, 2) + "\n", "utf8");
}

function ensureBesaDir(): void {
mkdirSync(BESA_DIR, { recursive: true });
}

function loadOrCreateKeyPair(): KeyPair {
ensureBesaDir();

if (existsSync(KEY_PATH)) {
return readJson<KeyPair>(KEY_PATH);
}

const keypair = generateKeyPair();
writeJson(KEY_PATH, keypair);
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
const flagsWithValues = new Set(["--agent", "--grants"]);

for (let index = 0; index < args.length; index += 1) {
const value = args[index];

if (value && flagsWithValues.has(value)) {
  index += 1;
  continue;
}

if (value) {
  values.push(value);
}

}

return values;
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
console.log("OK: loaded " + String(manifest.tools.length) + " tool(s) from " + file);
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
console.log("OK: signed -> " + out + " with publicKeyId " + signed.publicKeyId);
}

function cmdVerify(file: string): void {
const signed = readJson<SignedManifest>(file);
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
const signed = readJson<SignedManifest>(file);
const verified = verifySignedManifest(signed);

if (!verified.valid) {
const denied = denyFromVerification(toolName, verified.reasonCode, verified.detail);
printJson("admission", denied);
process.exitCode = 1;
return;
}

const grantDecision = grantGate(toolName);

if (grantDecision && grantDecision.decision === "deny") {
printJson("admission", grantDecision);
process.exitCode = 1;
return;
}

const meter = loadMeter(METER_PATH);
const count = getCount(meter, toolName);
const decision = admit(signed.manifest, toolName, count);

if (grantDecision?.agentId) {
decision.agentId = grantDecision.agentId;
}

printJson("admission", decision);

if (decision.decision === "deny") {
process.exitCode = 1;
}
}

function cmdReceipt(toolName: string, file?: string): void {
const signedPath = file ?? ACTIVE_MANIFEST_PATH;

if (!existsSync(signedPath)) {
throw new Error("no signed manifest found at " + signedPath + "; run besa sign <manifest> first");
}

const signed = readJson<SignedManifest>(signedPath);
const keypair = loadOrCreateKeyPair();
const verified = verifySignedManifest(signed);

let decision: AdmissionDecision;
let grantReasonCode: string | undefined;

if (!verified.valid) {
decision = denyFromVerification(toolName, verified.reasonCode, verified.detail);
} else {
const grantDecision = grantGate(toolName);
grantReasonCode = grantDecision?.reasonCode;

if (grantDecision && grantDecision.decision === "deny") {
  decision = grantDecision;
} else {
  const meter = loadMeter(METER_PATH);
  decision = admit(signed.manifest, toolName, getCount(meter, toolName));

  if (grantDecision?.agentId) {
    decision.agentId = grantDecision.agentId;
  }

  if (decision.decision === "allow") {
    saveMeter(METER_PATH, increment(meter, toolName));
  }
}

}

const receipt = createReceipt(
{
manifestHash: signed.manifestHash,
toolName,
decision: decision.decision,
reasonCode: decision.reasonCode,
request: {
toolName,
signedManifest: signedPath,
},
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
console.log(decision.decision.toUpperCase() + ": " + decision.reasonCode + " -> " + receiptPath);

if (decision.decision === "deny") {
process.exitCode = 1;
}
}

function usage(): void {
console.log(
[
"Besa - signed trust infrastructure for AI-agent tools",
"",
"Usage:",
"  besa keys",
"  besa load    <manifest.yaml>",
"  besa sign    <manifest.yaml>",
"  besa verify  <manifest.signed.json>",
"  besa admit   <manifest.signed.json> <tool-name> [--agent <agent-id> --grants <grants.yaml>]",
"  besa receipt <tool-name> [manifest.signed.json] [--agent <agent-id> --grants <grants.yaml>]",
"",
"Examples:",
"  besa keys",
"  besa load examples/manifest.yaml",
"  besa sign examples/manifest.yaml",
"  besa verify examples/manifest.signed.json",
"  besa admit examples/manifest.signed.json crm.lookup",
"  besa admit examples/manifest.signed.json crm.lookup --agent agent-alpha --grants examples/grants.yaml",
"  besa admit examples/manifest.signed.json crm.delete --agent agent-alpha --grants examples/grants.yaml",
"  besa receipt crm.lookup examples/manifest.signed.json",
"  besa receipt crm.lookup examples/manifest.signed.json --agent agent-alpha --grants examples/grants.yaml",
].join("\n"),
);
}

function requireArgs(args: string[], expected: number, command: string): void {
if (args.length < expected) {
throw new Error(command + " requires " + String(expected) + " argument(s)");
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
