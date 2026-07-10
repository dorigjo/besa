import { spawnSync } from "node:child_process";
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  addTrustAnchor,
  createReceipt,
  emptyTrustStore,
  generateKeyPair,
  signManifest,
  validateReceipt,
  type Manifest,
} from "../sdk.js";

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), "..", "index.js");
const MANIFEST_HASH = "a".repeat(64);

function manifest(): Manifest {
  return {
    serverName: "receipt-hardening",
    serverVersion: "1.0.0",
    serverUrl: "https://tools.example.test/mcp",
    createdAt: "2026-06-19T00:00:00Z",
    tools: [
      {
        name: "crm.lookup",
        description: "Read one CRM record.",
        capability: "read",
        risk: "low",
        scopes: ["crm:read"],
        budgetLimit: 5,
        inputSchema: { type: "object" },
      },
    ],
  };
}

// --- Unit tests: createReceipt fails closed on malformed semantics ---

test("createReceipt rejects a toolName with control characters", () => {
  const keypair = generateKeyPair();
  assert.throws(
    () =>
      createReceipt(
        {
          manifestHash: MANIFEST_HASH,
          toolName: "crm lookup",
          decision: "allow",
          reasonCode: "ALLOWED",
          request: {},
        },
        keypair,
      ),
    /toolName must match/,
  );
});

test("createReceipt rejects whitespace, path-like, empty, and oversize toolNames", () => {
  const keypair = generateKeyPair();

  for (const bad of ["crm lookup", "../etc/passwd", "", "a".repeat(257)]) {
    assert.throws(
      () =>
        createReceipt(
          {
            manifestHash: MANIFEST_HASH,
            toolName: bad,
            decision: "allow",
            reasonCode: "ALLOWED",
            request: {},
          },
          keypair,
        ),
      /toolName must match/,
    );
  }
});

test("createReceipt requires ALLOWED for allow decisions", () => {
  const keypair = generateKeyPair();
  assert.throws(
    () =>
      createReceipt(
        {
          manifestHash: MANIFEST_HASH,
          toolName: "crm.lookup",
          decision: "allow",
          reasonCode: "RISK_BLOCKED",
          request: {},
        },
        keypair,
      ),
    /allow receipts must carry reasonCode ALLOWED/,
  );
});

test("createReceipt rejects ALLOWED for deny decisions", () => {
  const keypair = generateKeyPair();
  assert.throws(
    () =>
      createReceipt(
        {
          manifestHash: MANIFEST_HASH,
          toolName: "crm.lookup",
          decision: "deny",
          reasonCode: "ALLOWED",
          request: {},
        },
        keypair,
      ),
    /deny receipts must not carry reasonCode ALLOWED/,
  );
});

test("createReceipt rejects grantReasonCode without agentId", () => {
  const keypair = generateKeyPair();
  assert.throws(
    () =>
      createReceipt(
        {
          manifestHash: MANIFEST_HASH,
          toolName: "crm.lookup",
          decision: "allow",
          reasonCode: "ALLOWED",
          request: {},
          grantReasonCode: "GRANT_OK",
        },
        keypair,
      ),
    /grantReasonCode may only be present when agentId is present/,
  );
});

// --- Unit tests: validateReceipt catches tampered evidence ---

test("validateReceipt rejects a toolName with control characters", () => {
  const keypair = generateKeyPair();
  const receipt = createReceipt(
    {
      manifestHash: MANIFEST_HASH,
      toolName: "crm.lookup",
      decision: "allow",
      reasonCode: "ALLOWED",
      request: {},
    },
    keypair,
  ) as unknown as Record<string, unknown>;
  receipt.toolName = "crm\tlookup";
  assert.equal(validateReceipt(receipt).ok, false);
});

test("validateReceipt rejects an allow receipt whose reasonCode was tampered", () => {
  const keypair = generateKeyPair();
  const receipt = createReceipt(
    {
      manifestHash: MANIFEST_HASH,
      toolName: "crm.lookup",
      decision: "allow",
      reasonCode: "ALLOWED",
      request: {},
    },
    keypair,
  ) as unknown as Record<string, unknown>;
  receipt.reasonCode = "RISK_BLOCKED";
  assert.equal(validateReceipt(receipt).ok, false);
});

test("validateReceipt rejects a deny receipt masquerading as ALLOWED", () => {
  const keypair = generateKeyPair();
  const receipt = createReceipt(
    {
      manifestHash: MANIFEST_HASH,
      toolName: "crm.lookup",
      decision: "deny",
      reasonCode: "RISK_BLOCKED",
      request: {},
    },
    keypair,
  ) as unknown as Record<string, unknown>;
  receipt.reasonCode = "ALLOWED";
  assert.equal(validateReceipt(receipt).ok, false);
});

test("validateReceipt rejects a grantReasonCode without an agentId", () => {
  const keypair = generateKeyPair();
  const receipt = createReceipt(
    {
      manifestHash: MANIFEST_HASH,
      toolName: "crm.lookup",
      decision: "allow",
      reasonCode: "ALLOWED",
      request: {},
    },
    keypair,
  ) as unknown as Record<string, unknown>;
  receipt.grantReasonCode = "GRANT_OK";
  assert.equal(validateReceipt(receipt).ok, false);
});

// --- CLI tests: verify-receipt request binding and declared-tool checks ---

interface CliFixture {
  keypair: ReturnType<typeof generateKeyPair>;
  signedManifestHash: string;
  dir: string;
  manifestPath: string;
  trustPath: string;
}

function cliFixture(): CliFixture {
  const keypair = generateKeyPair();
  const signed = signManifest(manifest(), keypair);
  const trust = addTrustAnchor(
    emptyTrustStore(),
    keypair.publicKeyDer,
    new Date(Date.now() - 60_000).toISOString(),
  );
  const dir = mkdtempSync(join(tmpdir(), "besa-receipt-cli-"));
  const manifestPath = join(dir, "manifest.signed.json");
  const trustPath = join(dir, "trust.json");
  writeFileSync(manifestPath, JSON.stringify(signed, null, 2) + "\n", "utf8");
  writeFileSync(trustPath, JSON.stringify(trust, null, 2) + "\n", "utf8");

  return {
    keypair,
    signedManifestHash: signed.manifestHash,
    dir,
    manifestPath,
    trustPath,
  };
}

function runCli(args: string[], cwd: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
}

test("verify-receipt --request passes on a matching request", () => {
  const fixture = cliFixture();
  try {
    const request = { tool: "crm.lookup", customerId: "cus_123" };
    const receipt = createReceipt(
      {
        manifestHash: fixture.signedManifestHash,
        toolName: "crm.lookup",
        decision: "allow",
        reasonCode: "ALLOWED",
        request,
      },
      fixture.keypair,
    );
    const receiptPath = join(fixture.dir, "receipt.json");
    const requestPath = join(fixture.dir, "request.json");
    writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + "\n", "utf8");
    writeFileSync(requestPath, JSON.stringify(request, null, 2) + "\n", "utf8");

    const result = runCli(
      [
        "verify-receipt",
        receiptPath,
        fixture.manifestPath,
        "--trust",
        fixture.trustPath,
        "--request",
        requestPath,
      ],
      fixture.dir,
    );
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("verify-receipt --request fails closed on a mismatched request", () => {
  const fixture = cliFixture();
  try {
    const receipt = createReceipt(
      {
        manifestHash: fixture.signedManifestHash,
        toolName: "crm.lookup",
        decision: "allow",
        reasonCode: "ALLOWED",
        request: { tool: "crm.lookup", customerId: "cus_123" },
      },
      fixture.keypair,
    );
    const receiptPath = join(fixture.dir, "receipt.json");
    const requestPath = join(fixture.dir, "request.json");
    writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + "\n", "utf8");
    writeFileSync(
      requestPath,
      JSON.stringify({ tool: "crm.lookup", customerId: "cus_999" }, null, 2) +
        "\n",
      "utf8",
    );

    const result = runCli(
      [
        "verify-receipt",
        receiptPath,
        fixture.manifestPath,
        "--trust",
        fixture.trustPath,
        "--request",
        requestPath,
      ],
      fixture.dir,
    );
    assert.equal(result.status, 1);
    assert.match(String(result.stdout), /E_RECEIPT_REQUEST_MISMATCH/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("verify-receipt fails closed when an allow receipt names an undeclared tool", () => {
  const fixture = cliFixture();
  try {
    const receipt = createReceipt(
      {
        manifestHash: fixture.signedManifestHash,
        toolName: "crm.export",
        decision: "allow",
        reasonCode: "ALLOWED",
        request: {},
      },
      fixture.keypair,
    );
    const receiptPath = join(fixture.dir, "receipt.json");
    writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + "\n", "utf8");

    const result = runCli(
      [
        "verify-receipt",
        receiptPath,
        fixture.manifestPath,
        "--trust",
        fixture.trustPath,
      ],
      fixture.dir,
    );
    assert.equal(result.status, 1);
    assert.match(String(result.stdout), /E_RECEIPT_TOOL_NOT_DECLARED/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("verify-receipt still passes without --request (backward compatible)", () => {
  const fixture = cliFixture();
  try {
    const receipt = createReceipt(
      {
        manifestHash: fixture.signedManifestHash,
        toolName: "crm.lookup",
        decision: "allow",
        reasonCode: "ALLOWED",
        request: { toolName: "crm.lookup" },
      },
      fixture.keypair,
    );
    const receiptPath = join(fixture.dir, "receipt.json");
    writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + "\n", "utf8");

    const result = runCli(
      [
        "verify-receipt",
        receiptPath,
        fixture.manifestPath,
        "--trust",
        fixture.trustPath,
      ],
      fixture.dir,
    );
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});
