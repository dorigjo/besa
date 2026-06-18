import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
REASON,
admit,
createReceipt,
generateKeyPair,
hashManifest,
loadManifest,
loadMeter,
meterKey,
signManifest,
validateKeyPair,
validateManifest,
verifyReceipt,
verifyReceiptDetailed,
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
manifestHash: "a".repeat(64),
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

test("verifySignedManifest rejects malformed input without throwing", () => {
  const result = verifySignedManifest({
    algorithm: "ed25519",
    manifest: null,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_SIGNED_MANIFEST_INVALID");
});

test("signManifest rejects an invalid runtime manifest", () => {
  const keypair = generateKeyPair();
  const manifest = sampleManifest();
  manifest.tools = [];

  assert.throws(() => signManifest(manifest, keypair), /Invalid manifest/);
});

test("key pair validation rejects mismatched Ed25519 keys", () => {
  const first = generateKeyPair();
  const second = generateKeyPair();

  assert.equal(validateKeyPair(first), true);
  assert.equal(
    validateKeyPair({
      publicKeyDer: first.publicKeyDer,
      privateKeyDer: second.privateKeyDer,
    }),
    false,
  );
});

test("receipt verification returns a reason code for malformed input", () => {
  const keypair = generateKeyPair();
  const result = verifyReceiptDetailed({ algorithm: "ed25519" }, keypair.publicKeyDer);

  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_RECEIPT_INVALID");
});

test("meter keys isolate usage by manifest hash", () => {
  assert.notEqual(
    meterKey("a".repeat(64), "crm.lookup"),
    meterKey("b".repeat(64), "crm.lookup"),
  );
});

test("loadMeter fails closed on corrupt state", () => {
  const directory = mkdtempSync(join(tmpdir(), "besa-meter-"));
  const path = join(directory, "meter.json");

  try {
    writeFileSync(path, "{not-json", "utf8");
    assert.throws(() => loadMeter(path), /invalid meter state/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
test("validateManifest rejects an invalid serverUrl", () => {
  const manifest = sampleManifest();
  manifest.serverUrl = "not-a-url";

  const result = validateManifest(manifest);

  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes("serverUrl")));
});

test("validateManifest rejects an invalid createdAt", () => {
  const manifest = sampleManifest();
  manifest.createdAt = "June 14 2026";

  const result = validateManifest(manifest);

  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes("createdAt")));
});

test("validateManifest rejects duplicate tool names", () => {
  const manifest = sampleManifest();
  manifest.tools[1].name = manifest.tools[0].name;

  const result = validateManifest(manifest);

  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes("duplicate")));
});

test("validateManifest rejects empty scope strings", () => {
  const manifest = sampleManifest();
  manifest.tools[0].scopes = ["crm:read", ""];

  const result = validateManifest(manifest);

  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes("scopes")));
});

test("validateManifest rejects an unsafe budgetLimit", () => {
  const manifest = sampleManifest();
  manifest.tools[0].budgetLimit = Number.MAX_SAFE_INTEGER + 1;

  const result = validateManifest(manifest);

  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes("budgetLimit")));
});

test("verifySignedManifest fails on publicKeyId mismatch", () => {
  const keypair = generateKeyPair();
  const signed = signManifest(sampleManifest(), keypair);
  signed.publicKeyId = "0000000000000000";

  const result = verifySignedManifest(signed);

  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_PUBLIC_KEY_ID_MISMATCH");
});

test("verifySignedManifest fails on unsupported algorithm", () => {
  const keypair = generateKeyPair();
  const signed = signManifest(sampleManifest(), keypair);
  const tampered = {
    ...signed,
    algorithm: "rsa" as unknown as "ed25519",
  };

  const result = verifySignedManifest(tampered);

  assert.equal(result.valid, false);
  assert.equal(result.reasonCode, "E_ALGORITHM_UNSUPPORTED");
});
