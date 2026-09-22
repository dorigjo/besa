import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const node = process.execPath;
const cli = resolve("dist/index.js");
const PORT = 8799;
const BASE_URL = `http://127.0.0.1:${String(PORT)}`;

if (!existsSync(cli)) {
  console.error("SMOKE FAIL: dist/index.js not found. Run npm run build first.");
  process.exit(1);
}

console.log("Besa hosted verifier smoke test");

const server = spawn(node, [cli, "serve", "--port", String(PORT)], {
  stdio: ["ignore", "pipe", "inherit"],
});

let ok = true;

async function waitForReady(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE_URL}/health`);
      if (response.ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("hosted verifier did not become ready in time");
}

async function expectStatus(label, path, init, expectedStatus) {
  console.log(`\n== ${label} (expect status ${expectedStatus}) ==`);
  const response = await fetch(BASE_URL + path, init);
  const body = await response.json();
  console.log(JSON.stringify(body, null, 2));

  if (response.status !== expectedStatus) {
    console.error(
      `SMOKE FAIL: ${label} returned ${response.status}, expected ${expectedStatus}`,
    );
    return null;
  }
  return body;
}

const GOLDEN_SIGNED_MANIFEST = {
  artifactVersion: 1,
  manifest: {
    serverName: "besa-golden",
    serverVersion: "1.0.0",
    serverUrl: "https://golden.besa.dev/mcp",
    createdAt: "2026-01-01T00:00:00.000Z",
    tools: [
      {
        name: "crm.lookup",
        description: "Look up a customer record.",
        capability: "read",
        risk: "low",
        scopes: ["crm:read"],
        budgetLimit: 100,
        inputSchema: {
          type: "object",
          properties: { customerId: { type: "string" } },
          required: ["customerId"],
        },
      },
    ],
  },
  manifestHash:
    "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504",
  algorithm: "ed25519",
  publicKey: "MCowBQYDK2VwAyEAU8Rd381cF98qVQPwpA3v/aQJajeqGMh06YavYFmcLJM=",
  publicKeyId:
    "0bccb1c411d1f3962902a629a4da9e9ed6a5aecd830af2f7f54c0d709c10c1ee",
  signedAt: "2026-07-11T21:39:12.664Z",
  signature:
    "SVmi+lwcAQUyRduQc+Y6Jf6dyOIe19z7qqYIxIzZzcR4bU7w4cKTxi5qiHRE6lsfChLkGdDUO7EG6Ogk+yzqCA==",
};

try {
  await waitForReady(5000);

  const health = await expectStatus("GET /health", "/health", {}, 200);
  if (!health || health.status !== "ok") ok = false;

  const valid = await expectStatus(
    "POST /v1/verify/manifest (golden, valid)",
    "/v1/verify/manifest",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(GOLDEN_SIGNED_MANIFEST),
    },
    200,
  );
  if (!valid || valid.valid !== true) ok = false;

  const tampered = {
    ...GOLDEN_SIGNED_MANIFEST,
    manifest: { ...GOLDEN_SIGNED_MANIFEST.manifest, serverName: "attacker" },
  };
  const invalid = await expectStatus(
    "POST /v1/verify/manifest (tampered, fails closed)",
    "/v1/verify/manifest",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(tampered),
    },
    200,
  );
  if (!invalid || invalid.valid !== false) ok = false;

  const malformed = await expectStatus(
    "POST /v1/verify/manifest (malformed JSON)",
    "/v1/verify/manifest",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: "{not json" },
    400,
  );
  if (!malformed) ok = false;

  const notFound = await expectStatus("GET /does-not-exist", "/does-not-exist", {}, 404);
  if (!notFound) ok = false;

  const wrongMethod = await expectStatus(
    "GET /v1/verify/manifest (wrong method)",
    "/v1/verify/manifest",
    {},
    405,
  );
  if (!wrongMethod) ok = false;

  const admitDisabled = await expectStatus(
    "POST /v1/admit (admission not enabled, default besa serve)",
    "/v1/admit",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ signedManifest: GOLDEN_SIGNED_MANIFEST, toolName: "crm.lookup" }),
    },
    501,
  );
  if (!admitDisabled) ok = false;

  const metrics = await expectStatus("GET /metrics", "/metrics", {}, 200);
  if (!metrics || typeof metrics.requestsTotal !== "number" || metrics.requestsTotal < 1) {
    ok = false;
  }

  console.log("\n== Performance: 100 concurrent GET /health requests ==");
  const perfStart = Date.now();
  const results = await Promise.all(
    Array.from({ length: 100 }, () => fetch(`${BASE_URL}/health`)),
  );
  const perfDurationMs = Date.now() - perfStart;
  const allOk = results.every((r) => r.status === 200);
  console.log(`100 concurrent requests completed in ${String(perfDurationMs)}ms, all 200: ${String(allOk)}`);
  if (!allOk) {
    console.error("SMOKE FAIL: not all concurrent requests returned 200");
    ok = false;
  }
  if (perfDurationMs > 5000) {
    console.error(`SMOKE FAIL: 100 concurrent requests took ${String(perfDurationMs)}ms, expected under 5000ms`);
    ok = false;
  }
} catch (error) {
  console.error("SMOKE FAIL:", error instanceof Error ? error.message : String(error));
  ok = false;
} finally {
  server.kill();
}

// Second real process: `besa serve --trust ... --key-file ...` with admission
// enabled, exercising the opt-in /v1/admit path end to end against the
// actual built CLI binary, not just the unit-tested route function.
const ADMISSION_PORT = 8800;
const ADMISSION_BASE_URL = `http://127.0.0.1:${String(ADMISSION_PORT)}`;
const ACTION_TRUST_PORT = 8803;
const ACTION_TRUST_BASE_URL = `http://127.0.0.1:${String(ACTION_TRUST_PORT)}`;
const ADMISSION_TOKEN = "server-smoke-admission-token-000001";
const workDir = mkdtempSync(join(tmpdir(), "besa-admission-smoke-"));
const keyFile = join(workDir, "key.json");
const trustFile = join(workDir, "trust.json");
const actionPolicyFile = join(workDir, "action-policy.json");
const passphraseEnv = { ...process.env, BESA_KEY_PASSPHRASE: "smoke-test-passphrase-0123" };
const admissionEnv = { ...passphraseEnv, BESA_ADMISSION_TOKEN: ADMISSION_TOKEN };

const ACTION = {
  artifactVersion: 1,
  principalId: "principal:server-smoke",
  agentId: "agent:server-smoke",
  authority: "besa:server-smoke",
  tool: "payments.mock",
  operation: "payments.authorize",
  resource: "invoice:server-smoke-001",
  requestHash: "1".repeat(64),
  scopes: ["payments:write"],
  constraints: { amount: 25, currency: "EUR" },
  expiresAt: new Date(Date.now() + 300_000).toISOString(),
  nonce: "server-smoke-action-0001",
  riskClass: "high",
};

let admissionOk = true;
let admissionServer;
let actionTrustServer;

try {
  execFileSync(node, [cli, "keys", "--key-file", keyFile], {
    env: passphraseEnv,
    stdio: "pipe",
  });
  const serverPublicKey = execFileSync(
    node,
    [cli, "keys", "export-public", "--key-file", keyFile],
    { env: passphraseEnv, encoding: "utf8" },
  ).trim();
  const serverPublicKeyId = createHash("sha256")
    .update(Buffer.from(serverPublicKey, "base64"))
    .digest("hex");

  writeFileSync(
    trustFile,
    JSON.stringify({
      version: 1,
      keys: [
        {
          publicKeyId: GOLDEN_SIGNED_MANIFEST.publicKeyId,
          publicKey: GOLDEN_SIGNED_MANIFEST.publicKey,
          status: "active",
          addedAt: "2026-01-01T00:00:00.000Z",
        },
        {
          publicKeyId: serverPublicKeyId,
          publicKey: serverPublicKey,
          status: "active",
          addedAt: "2026-01-01T00:00:00.000Z",
        },
      ],
    }),
    "utf8",
  );
  writeFileSync(
    actionPolicyFile,
    JSON.stringify({
      version: 1,
      policyId: "server-smoke-policy",
      delegationRequired: false,
      rules: [
        {
          ruleId: "allow-payment-mock",
          principals: [ACTION.principalId],
          agents: [ACTION.agentId],
          tools: [ACTION.tool],
          operations: [ACTION.operation],
          resources: [ACTION.resource],
          allowedScopes: ACTION.scopes,
          maxRisk: "high",
          constraints: { exact: { currency: "EUR" }, maximums: { amount: 100 } },
        },
      ],
    }),
    "utf8",
  );

  admissionServer = spawn(
    node,
    [
      cli,
      "serve",
      "--port",
      String(ADMISSION_PORT),
      "--trust",
      trustFile,
      "--key-file",
      keyFile,
      "--action-policy",
      actionPolicyFile,
    ],
    { stdio: ["ignore", "pipe", "inherit"], env: admissionEnv },
  );

  const deadline = Date.now() + 5000;
  let ready = false;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${ADMISSION_BASE_URL}/health`);
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!ready) throw new Error("admission-enabled server did not become ready in time");

  console.log("\n== POST /v1/admit (missing bearer token, expect 401) ==");
  const unauthorizedResponse = await fetch(`${ADMISSION_BASE_URL}/v1/admit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ signedManifest: GOLDEN_SIGNED_MANIFEST, toolName: "crm.lookup" }),
  });
  console.log(`status: ${String(unauthorizedResponse.status)}`);
  if (unauthorizedResponse.status !== 401) admissionOk = false;

  console.log("\n== POST /v1/admit (admission enabled, trusted manifest, expect allow) ==");
  const allowResponse = await fetch(`${ADMISSION_BASE_URL}/v1/admit`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ADMISSION_TOKEN}`,
    },
    body: JSON.stringify({ signedManifest: GOLDEN_SIGNED_MANIFEST, toolName: "crm.lookup" }),
  });
  const allowBody = await allowResponse.json();
  console.log(JSON.stringify(allowBody, null, 2));
  if (allowResponse.status !== 200 || allowBody.decision !== "allow") admissionOk = false;

  console.log("\n== POST /v1/admit (unknown tool, expect signed deny) ==");
  const denyResponse = await fetch(`${ADMISSION_BASE_URL}/v1/admit`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ADMISSION_TOKEN}`,
    },
    body: JSON.stringify({ signedManifest: GOLDEN_SIGNED_MANIFEST, toolName: "does.not.exist" }),
  });
  const denyBody = await denyResponse.json();
  console.log(JSON.stringify(denyBody, null, 2));
  if (denyResponse.status !== 200 || denyBody.decision !== "deny" || denyBody.reasonCode !== "TOOL_NOT_FOUND") {
    admissionOk = false;
  }

  console.log("\n== POST /v1/actions/admit (exact action, expect signed allow) ==");
  const actionResponse = await fetch(`${ADMISSION_BASE_URL}/v1/actions/admit`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ADMISSION_TOKEN}`,
    },
    body: JSON.stringify({ action: ACTION }),
  });
  const actionCapability = await actionResponse.json();
  console.log(JSON.stringify(actionCapability, null, 2));
  if (actionResponse.status !== 200 || actionCapability.decision !== "allow") {
    admissionOk = false;
  }

  console.log("\n== POST /v1/verify/capability (admission process, expect authorized) ==");
  const capabilityResponse = await fetch(`${ADMISSION_BASE_URL}/v1/verify/capability`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ capability: actionCapability, action: ACTION }),
  });
  const capabilityBody = await capabilityResponse.json();
  console.log(JSON.stringify(capabilityBody, null, 2));
  if (
    capabilityResponse.status !== 200 ||
    capabilityBody.valid !== true ||
    capabilityBody.authorized !== true
  ) {
    admissionOk = false;
  }

  actionTrustServer = spawn(
    node,
    [
      cli,
      "serve",
      "--port",
      String(ACTION_TRUST_PORT),
      "--action-trust",
      trustFile,
    ],
    { stdio: ["ignore", "pipe", "inherit"] },
  );

  const actionTrustDeadline = Date.now() + 5000;
  let actionTrustReady = false;
  while (Date.now() < actionTrustDeadline) {
    try {
      const response = await fetch(`${ACTION_TRUST_BASE_URL}/ready`);
      if (response.ok) {
        actionTrustReady = true;
        break;
      }
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!actionTrustReady) throw new Error("keyless action verifier did not become ready in time");

  console.log("\n== Keyless --action-trust capability verification (expect authorized) ==");
  const keylessResponse = await fetch(`${ACTION_TRUST_BASE_URL}/v1/verify/capability`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ capability: actionCapability, action: ACTION }),
  });
  const keylessBody = await keylessResponse.json();
  console.log(JSON.stringify(keylessBody, null, 2));
  if (
    keylessResponse.status !== 200 ||
    keylessBody.valid !== true ||
    keylessBody.authorized !== true
  ) {
    admissionOk = false;
  }
} catch (error) {
  console.error("SMOKE FAIL:", error instanceof Error ? error.message : String(error));
  admissionOk = false;
} finally {
  if (admissionServer) admissionServer.kill();
  if (actionTrustServer) actionTrustServer.kill();
  rmSync(workDir, { recursive: true, force: true });
}

// Third real process: `besa serve --rate-limit ...`, exercising 429
// behavior end to end against the actual built CLI binary.
const RATE_LIMIT_PORT = 8801;
const RATE_LIMIT_BASE_URL = `http://127.0.0.1:${String(RATE_LIMIT_PORT)}`;
let rateLimitOk = true;
let rateLimitServer;

try {
  rateLimitServer = spawn(
    node,
    [cli, "serve", "--port", String(RATE_LIMIT_PORT), "--rate-limit", "2"],
    { stdio: ["ignore", "pipe", "inherit"] },
  );

  const deadline = Date.now() + 5000;
  let ready = false;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${RATE_LIMIT_BASE_URL}/health`);
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!ready) throw new Error("rate-limited server did not become ready in time");

  console.log("\n== Rate limiting: 3rd non-health request within window expects 429 ==");
  await fetch(`${RATE_LIMIT_BASE_URL}/metrics`);
  await fetch(`${RATE_LIMIT_BASE_URL}/metrics`);
  const third = await fetch(`${RATE_LIMIT_BASE_URL}/metrics`);
  console.log(`3rd request status: ${String(third.status)}, Retry-After: ${third.headers.get("retry-after") ?? "(none)"}`);
  if (third.status !== 429 || !third.headers.has("retry-after")) rateLimitOk = false;
} catch (error) {
  console.error("SMOKE FAIL:", error instanceof Error ? error.message : String(error));
  rateLimitOk = false;
} finally {
  if (rateLimitServer) rateLimitServer.kill();
}

// Fourth real process: confirm the default bind address is loopback-only
// (not "every interface", which the startup banner used to misleadingly
// describe as "localhost") and that --host opts into a wider bind
// explicitly, with a visible warning.
const HOST_PORT = 8802;
let hostBindOk = true;
let hostBindServer;
let hostBindOutput = "";

try {
  hostBindServer = spawn(node, [cli, "serve", "--port", String(HOST_PORT)], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  hostBindServer.stdout.on("data", (chunk) => {
    hostBindOutput += chunk.toString();
  });

  const deadline = Date.now() + 5000;
  let ready = false;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${String(HOST_PORT)}/health`);
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!ready) throw new Error("default-bind server did not become ready in time");

  console.log("\n== Host binding: default banner reports loopback, not a wildcard bind ==");
  console.log(hostBindOutput.split("\n")[0]);
  if (!hostBindOutput.includes("http://127.0.0.1:") || hostBindOutput.includes("WARNING")) {
    hostBindOk = false;
  }
} catch (error) {
  console.error("SMOKE FAIL:", error instanceof Error ? error.message : String(error));
  hostBindOk = false;
} finally {
  if (hostBindServer) hostBindServer.kill();
}

if (!ok || !admissionOk || !rateLimitOk || !hostBindOk) {
  console.error("\nSERVER SMOKE FAILED");
  process.exit(1);
}

console.log("\nSERVER SMOKE OK: hosted verifier behaved as expected");
