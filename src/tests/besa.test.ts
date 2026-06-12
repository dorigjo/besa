import { test } from "node:test";
import assert from "node:assert/strict";
import {
REASON,
admit,
createReceipt,
generateKeyPair,
hashManifest,
loadManifest,
signManifest,
validateManifest,
verifyReceipt,
verifySignedManifest,
type Manifest
} from "../sdk.js";

function sampleManifest(): Manifest {
return {
serverName: "acme-crm",
serverVersion: "1.0.0",
serverUrl: "https://tools.example.com/mcp",
createdAt: "2026-06-12T00:00:00Z",
tools: [
{
name: "crm.lookup",
description: "Look up a customer.",
capability: "read",
risk: "low",
scopes: ["crm:read"],
budgetLimit: 100,
inputSchema: {
type: "object",
properties: {
customerId: {
type: "string"
}
},
required: ["customerId"]
}
},
{
name: "crm.update",
description: "Update a customer.",
capability: "write",
risk: "medium",
scopes: ["crm:write"],
budgetLimit: 10,
inputSchema: {
type: "object"
}
},
{
name: "crm.delete",
description: "Delete a customer.",
capability: "destructive",
risk: "high",
scopes: ["crm:admin"],
budgetLimit: 5,
inputSchema: {
type: "object"
}
}
]
};
}

test("validateManifest accepts a well-formed manifest", () => {
const result = validateManifest(sampleManifest());

assert.equal(result.ok, true);
assert.deepEqual(result.errors, []);
});

test("validateManifest rejects missing fields and bad enums", () => {
const result = validateManifest({
serverName: "x",
tools: [
{
name: "bad-tool",
description: "Bad tool.",
capability: "explode",
risk: "nuclear",
scopes: ["x"],
budgetLimit: -1,
inputSchema: {}
}
]
});

assert.equal(result.ok, false);
assert.ok(result.errors.length > 0);
});

test("loadManifest reads the example manifest", () => {
const manifest = loadManifest("examples/manifest.yaml");

assert.ok(manifest.serverName.length > 0);
assert.ok(manifest.tools.length > 0);
});

test("hashManifest is stable for equivalent manifests", () => {
assert.equal(hashManifest(sampleManifest()), hashManifest(sampleManifest()));
});

test("signManifest then verifySignedManifest succeeds", () => {
const keypair = generateKeyPair();
const signed = signManifest(sampleManifest(), keypair);
const result = verifySignedManifest(signed);

assert.equal(result.valid, true);
assert.equal(result.reasonCode, "OK");
});

test("tampering with the manifest breaks verification", () => {
const keypair = generateKeyPair();
const signed = signManifest(sampleManifest(), keypair);

signed.manifest.serverName = "evil-corp";

const result = verifySignedManifest(signed);

assert.equal(result.valid, false);
assert.equal(result.reasonCode, "E_MANIFEST_HASH_MISMATCH");
});

test("tampering with the signature breaks verification", () => {
const keypair = generateKeyPair();
const signed = signManifest(sampleManifest(), keypair);

const signature = Buffer.from(signed.signature, "base64");
signature[0] = signature[0] ^ 0xff;
signed.signature = signature.toString("base64");

const result = verifySignedManifest(signed);

assert.equal(result.valid, false);
});

test("admit allows a low-risk read tool under budget", () => {
const decision = admit(sampleManifest(), "crm.lookup", 0);

assert.equal(decision.decision, "allow");
assert.equal(decision.reasonCode, REASON.ALLOWED);
});

test("admit denies an unknown tool", () => {
const decision = admit(sampleManifest(), "unknown.tool", 0);

assert.equal(decision.decision, "deny");
assert.equal(decision.reasonCode, REASON.TOOL_NOT_FOUND);
});

test("admit denies a destructive high-risk tool by default", () => {
const decision = admit(sampleManifest(), "crm.delete", 0);

assert.equal(decision.decision, "deny");
assert.equal(decision.reasonCode, REASON.RISK_BLOCKED);
});

test("admit denies when the budget is exceeded", () => {
const decision = admit(sampleManifest(), "crm.lookup", 100);

assert.equal(decision.decision, "deny");
assert.equal(decision.reasonCode, REASON.BUDGET_EXCEEDED);
});

test("receipt is signed and tamper-evident", () => {
const keypair = generateKeyPair();

const receipt = createReceipt(
{
manifestHash: "abc123",
toolName: "crm.lookup",
decision: "allow",
reasonCode: REASON.ALLOWED,
request: {
tool: "crm.lookup",
customerId: "cus_123"
}
},
keypair
);

assert.ok(receipt.receiptId.startsWith("rcpt_"));
assert.equal(receipt.decision, "allow");
assert.equal(verifyReceipt(receipt, keypair.publicKeyDer), true);

receipt.decision = "deny";

assert.equal(verifyReceipt(receipt, keypair.publicKeyDer), false);
});