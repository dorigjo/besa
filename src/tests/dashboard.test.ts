import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { createDashboardServer } from "../server/dashboard.js";
import { addTrustAnchor, admitPreExecution, createExternalAuthority, emptyTrustStore,
  generateKeyPair, hashActionPolicy, hashAuthorityAssertion, hashRequest,
  type ActionPolicyV1 } from "../sdk.js";

function preExecutionBundle(): Record<string, unknown> {
  const now = new Date();
  const before = new Date(now.getTime() - 60_000).toISOString();
  const expiresAt = new Date(now.getTime() + 300_000).toISOString();
  const issuer = generateKeyPair();
  const normalizer = generateKeyPair();
  const policy: ActionPolicyV1 = {
    version: 1,
    policyId: "dashboard-refund-v1",
    delegationRequired: false,
    rules: [{
      ruleId: "refund-demo",
      principals: ["principal:dashboard"],
      agents: ["agent:dashboard"],
      tools: ["refund.issue"],
      operations: ["refund"],
      resources: ["customer:demo"],
      allowedScopes: ["refund:write"],
      maxRisk: "high",
      constraints: { exact: { amount: 100, currency: "EUR" }, maximums: {} },
    }],
  };
  const parameters = { amount: 100, currency: "EUR", reason: "test fixture" };
  const context = { executorId: "executor:refund-demo", tenant: "tenant:demo" };
  const audience = "https://refund.example.test";
  const request = {
    requestVersion: 1 as const,
    parameters,
    context,
    audience,
    requestedAt: now.toISOString(),
    policy: { id: policy.policyId, version: 1, hash: hashActionPolicy(policy) },
    action: {
      artifactVersion: 1 as const,
      principalId: "principal:dashboard",
      agentId: "agent:dashboard",
      authority: "https://identity.example.test",
      tool: "refund.issue",
      operation: "refund",
      resource: "customer:demo",
      requestHash: hashRequest(parameters),
      contextHash: hashRequest(context),
      scopes: ["refund:write"],
      constraints: parameters,
      expiresAt,
      nonce: "dashboard_nonce_0123456789",
      riskClass: "high" as const,
    },
  };
  const claims = {
    artifactVersion: 1 as const,
    mechanism: "oauth-access-token" as const,
    issuer: "https://identity.example.test",
    audience,
    principalId: "principal:dashboard",
    agentId: "agent:dashboard",
    tools: ["refund.issue"],
    operations: ["refund"],
    resources: ["customer:demo"],
    scopes: ["refund:write"],
    constraints: { exact: {}, maximums: {} },
    notBefore: before,
    expiresAt,
    assertionDigest: hashAuthorityAssertion("synthetic-dashboard-assertion"),
    delegationChainHash: null,
  };
  const authority = createExternalAuthority(claims, {
    id: "normalizer:dashboard-demo", keyPair: normalizer, issuedAt: before,
  });
  const input = { request, authority };
  const trustStore = addTrustAnchor(emptyTrustStore(), issuer.publicKeyDer, before);
  const authorityTrustStore = addTrustAnchor(emptyTrustStore(), normalizer.publicKeyDer, before);
  const config = {
    policy,
    audience,
    trustStore,
    authorityTrustStore,
    issuerId: "admission:dashboard-demo",
    keyPair: issuer,
  };
  const receipt = admitPreExecution(input, config, now);
  return {
    format: "besa-pre-execution-bundle-v1",
    input,
    receipt,
    policy,
    audience,
    trustStore,
    authorityTrustStore,
  };
}

test("local Dashboard verifies bundles with the SDK and fails closed on ambiguity", async (t) => {
  const server = createDashboardServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const base = `http://127.0.0.1:${String(address.port)}`;
  const post = (raw: string, headers: Record<string, string> = { "Content-Type": "application/json" }) =>
    fetch(`${base}/api/verify`, { method: "POST", headers, body: raw });

  try {
    const health = await fetch(`${base}/api/health`);
    assert.deepEqual(await health.json(), { status: "ok", storage: "none", telemetry: "disabled" });
    assert.equal(health.headers.get("content-security-policy")?.includes("default-src 'self'"), true);

    await t.test("simulates existing SDK allow and deny paths without external effects", async () => {
      const response = await fetch(`${base}/api/simulate`, { method: "POST" });
      const result = await response.json() as Record<string, any>;
      assert.equal(response.status, 200);
      assert.equal(result.persisted, false);
      assert.equal(result.telemetry, false);
      assert.deepEqual(result.scenarios.map((scenario: Record<string, unknown>) => [
        scenario.decision, scenario.executorCalled,
      ]), [["DENY", false], ["ALLOW", true]]);
      assert.equal(result.scenarios[1].evidenceVerified, true);
      assert.match(result.limitation, /no external system/);
    });

    const sampleResponse = await fetch(`${base}/api/sample`);
    const sample = await sampleResponse.json() as Record<string, unknown>;
    assert.equal(sampleResponse.status, 200);
    assert.equal(((sample.signedManifest as Record<string, unknown>).manifest as Record<string, unknown>).serverUrl,
      "https://golden.example.com/mcp");

    await t.test("accepts exact signed sample and trust context", async () => {
      const response = await post(JSON.stringify(sample));
      const report = await response.json() as Record<string, any>;
      assert.equal(response.status, 200);
      assert.equal(report.overall, "VERIFIED");
      assert.equal(report.verification.manifestSignature.valid, true);
      assert.equal(report.verification.receiptSignature.valid, true);
      assert.equal(report.verification.manifestHashMatches, true);
      assert.equal(report.verification.requestBinding, "MATCH");
      assert.equal(report.verification.issuerTrust.status, "TRUSTED");
    });

    await t.test("rejects a changed request binding", async () => {
      const changed = structuredClone(sample);
      (changed.request as Record<string, unknown>).customerId = "cust_other";
      const response = await post(JSON.stringify(changed));
      const report = await response.json() as Record<string, any>;
      assert.equal(report.overall, "INVALID");
      assert.equal(report.verification.requestBinding, "MISMATCH");
    });

    await t.test("rejects a mutated manifest signature", async () => {
      const changed = structuredClone(sample);
      ((changed.signedManifest as Record<string, unknown>).manifest as Record<string, unknown>).serverName = "<script>bad()</script>";
      const response = await post(JSON.stringify(changed));
      const report = await response.json() as Record<string, any>;
      assert.equal(report.overall, "INVALID");
      assert.equal(report.verification.manifestSignature.valid, false);
      assert.equal(report.action.serverName, "<script>bad()</script>");
    });

    await t.test("reports missing issuer trust as partial, not trusted", async () => {
      const untrusted = { ...sample, trustStore: { version: 1, keys: [] } };
      const response = await post(JSON.stringify(untrusted));
      const report = await response.json() as Record<string, any>;
      assert.equal(report.overall, "PARTIAL");
      assert.equal(report.verification.receiptSignature.valid, true);
      assert.equal(report.verification.issuerTrust.status, "UNTRUSTED");
    });

    await t.test("verifies exact pre-execution action, authority and policy", async () => {
      const sampleResponse = await fetch(`${base}/api/sample-admission`);
      assert.equal(sampleResponse.status, 200);
      const bundle = await sampleResponse.json() as Record<string, unknown>;
      const response = await post(JSON.stringify(bundle));
      const report = await response.json() as Record<string, any>;
      assert.equal(response.status, 200);
      assert.equal(report.format, "PRE_EXECUTION_ADMISSION_V1");
      assert.equal(report.overall, "VERIFIED");
      assert.equal(report.verification.admissionVerification.valid, true);
      assert.equal(report.verification.issuerTrust.status, "TRUSTED");
      assert.equal(report.verification.requestBinding, "MATCH");
      assert.equal(report.verification.actionBinding, "MATCH");
      assert.equal(report.verification.policyBinding, "MATCH");
      assert.equal(report.verification.authority, "VERIFIED");
      assert.equal(report.verification.currentAdmission.authorized, true);
      assert.equal(report.action.resource, "customer:demo");
      assert.deepEqual(report.action.parameters, { amount: 100, currency: "EUR", reason: "local dashboard sample" });
    });

    await t.test("rejects parameter mutation against a signed admission", async () => {
      const bundle = preExecutionBundle();
      const input = bundle.input as Record<string, any>;
      input.request.parameters.amount = 4_800;
      const response = await post(JSON.stringify(bundle));
      const report = await response.json() as Record<string, any>;
      assert.equal(report.overall, "INVALID");
      assert.equal(report.verification.requestBinding, "MISMATCH");
      assert.equal(report.verification.actionBinding, "MISMATCH");
      assert.equal(report.action.parameters.amount, 4_800);
    });

    await t.test("malformed nested evidence fails as an invalid result without crashing the verifier", async () => {
      const bundle = preExecutionBundle();
      bundle.actionEvidence = { unsupported: true };
      bundle.result = { ok: true };
      bundle.receipt = { capability: {} };
      const response = await post(JSON.stringify(bundle));
      const report = await response.json() as Record<string, any>;
      assert.equal(response.status, 200);
      assert.equal(report.overall, "INVALID");
      assert.equal(report.verification.executionEvidence.status, "INVALID");
    });

    await t.test("rejects duplicate keys and unknown bundle fields", async () => {
      const raw = JSON.stringify(sample).replace(
        '"receipt":',
        `"signedManifest":${JSON.stringify(sample.signedManifest)},"receipt":`,
      );
      const duplicate = await post(raw);
      assert.equal(duplicate.status, 400);
      assert.equal((await duplicate.json() as Record<string, unknown>).error, "ARTIFACT_JSON_INVALID");
      const unknown = await post(JSON.stringify({ ...sample, bypass: true }));
      assert.equal(unknown.status, 400);
      assert.equal((await unknown.json() as Record<string, unknown>).error, "ARTIFACT_BUNDLE_INVALID");
    });

    await t.test("enforces body limit and local Host boundary", async () => {
      const tooLarge = await post(JSON.stringify({ payload: "x".repeat(262_200) }));
      assert.equal(tooLarge.status, 413);
      const hostileStatus = await new Promise<number>((resolve, reject) => {
        const req = httpRequest({ hostname: "127.0.0.1", port: address.port, path: "/api/health",
          headers: { Host: "attacker.example" } }, (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        });
        req.on("error", reject);
        req.end();
      });
      assert.equal(hostileStatus, 403);
    });

    await t.test("serves static UI that avoids HTML injection and browser storage", async () => {
      const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
      const app = readFileSync(join(root, "dashboard", "app.js"), "utf8");
      const page = await fetch(base);
      assert.equal(page.status, 200);
      assert.equal(page.headers.get("x-content-type-options"), "nosniff");
      const html = await page.text();
      assert.doesNotMatch(html, /class="brand"[^>]*aria-label=/);
      assert.match(html, /class="metrics" role="group" aria-label=/);
      assert.match(html, /id="checks" class="checks" role="group" aria-label=/);
      assert.equal(app.includes("innerHTML"), false);
      assert.equal(app.includes("localStorage"), false);
      assert.equal(app.includes("sessionStorage"), false);
      assert.equal(app.includes("PRE_EXECUTION_ADMISSION_V1"), true);
      assert.match(app, /element\("dl", "detail-row"\)/);
      assert.equal(app.includes("/api/simulate"), true);
      assert.equal(app.includes("new Date().toISOString()"), false);
      assert.match(app, /parameters: state\.report\.action\.parameters[\s\S]*OMITTED_FROM_EXPORT/);
      assert.match(app, /context: state\.report\.action\.context[\s\S]*OMITTED_FROM_EXPORT/);
    });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("besa dashboard CLI serves the packaged local workspace", async () => {
  const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
  const child = spawn(process.execPath, [join(root, "dist", "index.js"), "dashboard", "--port", "0"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (value: string) => { stdout += value; });
  child.stderr.setEncoding("utf8").on("data", (value: string) => { stderr += value; });
  try {
    const port = await new Promise<number>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`dashboard startup timed out: ${stderr}`)), 5_000);
    child.stdout.on("data", () => {
      const match = /BESA Dashboard listening on http:\/\/127\.0\.0\.1:(\d+)/.exec(stdout);
      if (match && stdout.includes("Local-only verification")) { clearTimeout(timeout); resolve(Number(match[1])); }
    });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("exit", (code) => {
      if (code !== null && code !== 0) { clearTimeout(timeout); reject(new Error(`dashboard exited ${code}: ${stderr}`)); }
    });
  });
    assert.match(stdout, /Local-only verification/);
    const page = await fetch(`http://127.0.0.1:${String(port)}/`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /BESA Dashboard/);
    const sample = await fetch(`http://127.0.0.1:${String(port)}/api/sample`);
    assert.equal(sample.status, 200);
  } finally {
    child.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null) resolve();
      else child.once("exit", () => resolve());
    });
  }
});
