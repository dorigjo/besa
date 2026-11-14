import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hashRequest, verifyReceiptDetailed, verifySignedManifest } from "../signing.js";
import { parseArtifactJson } from "../json.js";
import { addTrustAnchor, checkTrustedKey, emptyTrustStore, validateTrustStore, verifyTrustedSignedManifest } from "../trust.js";
import { hashActionEnvelope } from "../action.js";
import type { ActionPolicyV1 } from "../action-policy.js";
import { verifyActionEvidence } from "../action-evidence.js";
import { hashActionPolicy, hashPreExecutionReceipt, hashPreExecutionRequest,
  verifyPreExecutionAdmission } from "../pre-execution.js";
import type { PreExecutionAdmissionInput, PreExecutionAdmissionReceiptV1,
  PreExecutionVerificationConfig } from "../pre-execution.js";
import type { Receipt, SignedManifest, TrustStore } from "../types.js";
import { simulateDemo } from "../demo.js";
import { generateKeyPair } from "../crypto.js";
import { createExternalAuthority, hashAuthorityAssertion } from "../external-authority.js";
import { admitPreExecution } from "../pre-execution.js";

const MAX_BODY_BYTES = 262_144;
const ASSET_TYPES: Record<string, string> = {
  "/": "text/html; charset=utf-8",
  "/app.js": "text/javascript; charset=utf-8",
  "/styles.css": "text/css; charset=utf-8",
};

interface DashboardBundle extends Record<string, unknown> {
  format?: string;
  signedManifest?: unknown;
  receipt?: unknown;
  request?: unknown;
  trustStore?: unknown;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function headers(res: ServerResponse): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  headers(res);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<Buffer | "too-large"> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > MAX_BODY_BYTES) tooLarge = true;
      else if (!tooLarge) chunks.push(bytes);
    });
    req.on("end", () => resolve(tooLarge ? "too-large" : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function validateBundle(value: unknown): DashboardBundle | undefined {
  if (!isObject(value)) return undefined;
  if (value.format === "besa-pre-execution-bundle-v1") {
    const admissionFields = new Set([
      "format", "input", "receipt", "policy", "audience", "trustStore",
      "authorityTrustStore", "delegationTrustStore", "actionEvidence", "result",
    ]);
    if (Object.keys(value).some((key) => !admissionFields.has(key)) ||
        !Object.hasOwn(value, "input") || !Object.hasOwn(value, "receipt") ||
        !Object.hasOwn(value, "policy") || !Object.hasOwn(value, "audience") ||
        !Object.hasOwn(value, "trustStore") || !Object.hasOwn(value, "authorityTrustStore")) return undefined;
    return value as unknown as DashboardBundle;
  }
  const allowed = new Set(["signedManifest", "receipt", "request", "trustStore"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) ||
      !Object.hasOwn(value, "signedManifest") || !Object.hasOwn(value, "receipt")) return undefined;
  return value as unknown as DashboardBundle;
}

function verifyPreExecutionBundle(bundle: DashboardBundle): unknown {
  const rawInput = isObject(bundle.input) ? bundle.input : {};
  const request = isObject(rawInput.request) ? rawInput.request : {};
  const input = rawInput as unknown as PreExecutionAdmissionInput;
  const config: PreExecutionVerificationConfig = {
    policy: bundle.policy as ActionPolicyV1,
    audience: bundle.audience as string,
    trustStore: bundle.trustStore as TrustStore,
    authorityTrustStore: bundle.authorityTrustStore as TrustStore,
    ...(bundle.delegationTrustStore === undefined ? {} : {
      delegationTrustStore: bundle.delegationTrustStore as TrustStore,
    }),
  };
  const checkedAt = new Date();
  const historical = verifyPreExecutionAdmission(bundle.receipt, input, config, checkedAt, "audit");
  const current = verifyPreExecutionAdmission(bundle.receipt, input, config, checkedAt, "execute");
  const receipt = isObject(bundle.receipt) ? bundle.receipt : {};
  const signerTrust = typeof receipt.issuerPublicKey === "string" && typeof receipt.issuedAt === "string"
    ? checkTrustedKey(config.trustStore, receipt.issuerPublicKey, receipt.issuedAt, "verify", checkedAt)
    : { valid: false, reasonCode: "TRUST_ADMISSION_ISSUER_UNTRUSTED" };
  const action = isObject(request.action) ? request.action : {};
  const parameters = request.parameters;
  const context = request.context;

  let requestBinding = "MISMATCH";
  let policyBinding = "MISMATCH";
  let actionBinding = "MISMATCH";
  try {
    requestBinding = receipt.requestDigest === hashPreExecutionRequest(request as never) ? "MATCH" : "MISMATCH";
    policyBinding = receipt.policyHash === hashActionPolicy(config.policy) &&
      receipt.policyId === config.policy.policyId ? "MATCH" : "MISMATCH";
    actionBinding = receipt.actionHash === hashActionEnvelope(action as never) ? "MATCH" : "MISMATCH";
  } catch { /* The verifier's reason code below reports malformed inputs. */ }

  let evidence: { status: string; reasonCode: string } = {
    status: "NOT_PROVIDED", reasonCode: "EXECUTION_EVIDENCE_NOT_PROVIDED",
  };
  if (Object.hasOwn(bundle, "actionEvidence") && Object.hasOwn(bundle, "result") && receipt.capability) {
    try {
      const evidenceResult = verifyActionEvidence(bundle.actionEvidence, {
        action,
        capability: receipt.capability,
        result: bundle.result,
        trustStore: config.trustStore,
        receiptHash: hashPreExecutionReceipt(bundle.receipt as PreExecutionAdmissionReceiptV1),
      });
      evidence = {
        status: evidenceResult.valid ? "SIGNED_SUPPLIED_RESULT" : "INVALID",
        reasonCode: evidenceResult.reasonCode,
      };
    } catch {
      evidence = { status: "INVALID", reasonCode: "ACTION_EVIDENCE_INVALID" };
    }
  }

  const decision = receipt.decision === "allow" || receipt.decision === "deny" ? receipt.decision : null;
  const overall = !historical.valid ? "INVALID" : decision === "deny" ? "DENIED" :
    current.valid && current.authorized ? "VERIFIED" : "PARTIAL";
  return {
    format: "PRE_EXECUTION_ADMISSION_V1",
    overall,
    verification: {
      admissionVerification: { valid: historical.valid, reasonCode: historical.reasonCode },
      manifestHashMatches: actionBinding === "MATCH",
      toolDeclared: true,
      requestBinding,
      issuerTrust: {
        status: signerTrust.valid ? "TRUSTED" : "UNTRUSTED",
        reasonCode: signerTrust.reasonCode,
      },
      currentAdmission: { valid: current.valid, authorized: current.authorized, reasonCode: current.reasonCode },
      actionBinding,
      policyBinding,
      authority: historical.valid ? "VERIFIED" : "UNVERIFIED",
      delegation: receipt.delegationChainHash === null ? "NOT_USED" : historical.valid ? "VERIFIED" : "UNVERIFIED",
      expiry: typeof receipt.expiresAt === "string" && Date.parse(receipt.expiresAt) > checkedAt.getTime()
        ? "ACTIVE" : "EXPIRED",
      executionEvidence: evidence,
    },
    action: {
      serverName: null,
      toolName: typeof action.tool === "string" ? action.tool : null,
      decision,
      reasonCode: typeof receipt.reasonCode === "string" ? receipt.reasonCode : historical.reasonCode,
      agentId: typeof action.agentId === "string" ? action.agentId : null,
      principalId: typeof action.principalId === "string" ? action.principalId : null,
      operation: typeof action.operation === "string" ? action.operation : null,
      resource: typeof action.resource === "string" ? action.resource : null,
      receiptId: typeof receipt.receiptId === "string" ? receipt.receiptId : null,
      timestamp: typeof receipt.issuedAt === "string" ? receipt.issuedAt : null,
      manifestHash: null,
      requestHash: requestBinding === "MATCH" ? receipt.requestDigest : null,
      publicKeyId: typeof receipt.issuerPublicKeyId === "string" ? receipt.issuerPublicKeyId : null,
      parameters: parameters ?? null,
      context: context ?? null,
      audience: typeof request.audience === "string" ? request.audience : null,
      policyId: typeof receipt.policyId === "string" ? receipt.policyId : null,
      policyVersion: receipt.policyVersion ?? null,
      policyHash: typeof receipt.policyHash === "string" ? receipt.policyHash : null,
      delegationHash: typeof receipt.delegationChainHash === "string" ? receipt.delegationChainHash : null,
      expiresAt: typeof receipt.expiresAt === "string" ? receipt.expiresAt : null,
    },
    disclaimer: "An admission receipt proves the signed authorization decision, not execution. Signed action evidence links a recorder-supplied result but does not independently prove an external side effect.",
  };
}

function verifyBundle(bundle: DashboardBundle): unknown {
  if (bundle.format === "besa-pre-execution-bundle-v1") return verifyPreExecutionBundle(bundle);
  const manifestResult = verifySignedManifest(bundle.signedManifest);
  const manifest = isObject(bundle.signedManifest) ? bundle.signedManifest : {};
  const receipt = isObject(bundle.receipt) ? bundle.receipt : {};
  const publicKey = typeof manifest.publicKey === "string" ? manifest.publicKey : "";
  const receiptResult = verifyReceiptDetailed(bundle.receipt, publicKey);
  const manifestHashMatches = receipt.manifestHash === manifest.manifestHash;
  const declaredTool = Array.isArray(manifest.manifest && (manifest.manifest as Record<string, unknown>).tools)
    ? ((manifest.manifest as Record<string, unknown>).tools as unknown[]).some(
      (tool) => isObject(tool) && tool.name === receipt.toolName,
    )
    : false;
  const requestStatus = Object.hasOwn(bundle, "request")
    ? hashRequest(bundle.request) === receipt.requestHash ? "MATCH" : "MISMATCH"
    : "NOT_PROVIDED";

  let issuerTrust: { status: string; reasonCode: string } = {
    status: "NOT_CONFIGURED",
    reasonCode: "TRUST_STORE_NOT_PROVIDED",
  };
  if (Object.hasOwn(bundle, "trustStore")) {
    const trustCheck = validateTrustStore(bundle.trustStore);
    if (!trustCheck.ok) {
      issuerTrust = { status: "INVALID_CONFIGURATION", reasonCode: "TRUST_STORE_INVALID" };
    } else {
      const trusted = verifyTrustedSignedManifest(
        bundle.signedManifest,
        bundle.trustStore as TrustStore,
      );
      issuerTrust = {
        status: trusted.valid ? "TRUSTED" : "UNTRUSTED",
        reasonCode: trusted.reasonCode,
      };
    }
  }

  const artifactValid = manifestResult.valid && receiptResult.valid && manifestHashMatches &&
    declaredTool && requestStatus !== "MISMATCH";
  const overall = !artifactValid ? "INVALID" :
    issuerTrust.status === "TRUSTED" && requestStatus === "MATCH" ? "VERIFIED" : "PARTIAL";

  return {
    overall,
    verification: {
      manifestSignature: { valid: manifestResult.valid, reasonCode: manifestResult.reasonCode },
      receiptSignature: { valid: receiptResult.valid, reasonCode: receiptResult.reasonCode },
      manifestHashMatches,
      toolDeclared: declaredTool,
      requestBinding: requestStatus,
      issuerTrust,
    },
    action: {
      serverName: typeof (manifest.manifest as Record<string, unknown> | undefined)?.serverName === "string"
        ? (manifest.manifest as Record<string, unknown>).serverName : null,
      toolName: typeof receipt.toolName === "string" ? receipt.toolName : null,
      decision: receipt.decision === "allow" || receipt.decision === "deny" ? receipt.decision : null,
      reasonCode: typeof receipt.reasonCode === "string" ? receipt.reasonCode : null,
      agentId: typeof receipt.agentId === "string" ? receipt.agentId : null,
      receiptId: typeof receipt.receiptId === "string" ? receipt.receiptId : null,
      timestamp: typeof receipt.timestamp === "string" ? receipt.timestamp : null,
      manifestHash: typeof receipt.manifestHash === "string" ? receipt.manifestHash : null,
      requestHash: typeof receipt.requestHash === "string" ? receipt.requestHash : null,
      publicKeyId: typeof receipt.publicKeyId === "string" ? receipt.publicKeyId : null,
      request: Object.hasOwn(bundle, "request") ? bundle.request : null,
    },
    disclaimer: "Signature verification proves the signed artifact's integrity, not that the issuer is trusted or that an external side effect occurred.",
  };
}

function createAdmissionSample(): Record<string, unknown> {
  const now = new Date();
  const issuedAt = new Date(now.getTime() - 60_000).toISOString();
  const expiresAt = new Date(now.getTime() + 300_000).toISOString();
  const issuer = generateKeyPair();
  const normalizer = generateKeyPair();
  const parameters = { amount: 100, currency: "EUR", reason: "local dashboard sample" };
  const context = { tenant: "tenant:demo", executorId: "executor:refund-demo" };
  const audience = "https://refund.example.test";
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
      nonce: `dashboard_${randomNonce()}`,
      riskClass: "high" as const,
    },
  };
  const authority = createExternalAuthority({
    artifactVersion: 1,
    mechanism: "oauth-access-token",
    issuer: "https://identity.example.test",
    audience,
    principalId: "principal:dashboard",
    agentId: "agent:dashboard",
    tools: ["refund.issue"],
    operations: ["refund"],
    resources: ["customer:demo"],
    scopes: ["refund:write"],
    constraints: { exact: {}, maximums: {} },
    notBefore: issuedAt,
    expiresAt,
    assertionDigest: hashAuthorityAssertion(`dashboard-sample-${now.toISOString()}`),
    delegationChainHash: null,
  }, { id: "normalizer:dashboard-demo", keyPair: normalizer, issuedAt });
  const trustStore = addTrustAnchor(emptyTrustStore(), issuer.publicKeyDer, issuedAt);
  const authorityTrustStore = addTrustAnchor(emptyTrustStore(), normalizer.publicKeyDer, issuedAt);
  const input = { request, authority };
  const receipt = admitPreExecution(input, {
    policy,
    audience,
    trustStore,
    authorityTrustStore,
    issuerId: "admission:dashboard-demo",
    keyPair: issuer,
  }, now);
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

function randomNonce(): string {
  return randomBytes(18).toString("base64url");
}

export function createDashboardServer(): Server {
  const packageRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
  const assetRoot = join(packageRoot, "dashboard");
  return createServer(async (req, res) => {
    headers(res);
    const host = req.headers.host?.toLowerCase() ?? "";
    if (!/^(localhost|127\.0\.0\.1)(:\d{1,5})?$/.test(host)) {
      sendJson(res, 403, { error: "LOCAL_HOST_REQUIRED" });
      return;
    }

    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname === "/api/health") {
      sendJson(res, 200, { status: "ok", storage: "none", telemetry: "disabled" });
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/simulate") {
      try {
        const scenarios = await simulateDemo();
        sendJson(res, 200, {
          source: "local-sdk-demo",
          persisted: false,
          telemetry: false,
          scenarios: scenarios.map(({ action, outcome }) => ({
            operation: action.operation,
            resource: action.resource,
            constraints: action.constraints,
            decision: outcome.decision.toUpperCase(),
            reasonCode: outcome.reasonCode,
            executorCalled: outcome.executorCalled,
            evidenceVerified: outcome.verification === "EVIDENCE_VALID",
          })),
          limitation: "In-memory test keys and mock callbacks only; no external system or real side effect is contacted.",
        });
      } catch {
        sendJson(res, 500, { error: "LOCAL_SIMULATION_FAILED" });
      }
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/sample") {
      try {
        const sample = JSON.parse(readFileSync(join(packageRoot, "conformance/golden-v1.json"), "utf8")) as {
          signedManifest: SignedManifest;
          receipt: Receipt;
          request: unknown;
        };
        sendJson(res, 200, {
          signedManifest: sample.signedManifest,
          receipt: sample.receipt,
          request: sample.request,
          trustStore: {
            version: 1,
            keys: [{
              publicKeyId: sample.signedManifest.publicKeyId,
              publicKey: sample.signedManifest.publicKey,
              status: "active",
              addedAt: "2026-01-01T00:00:00.000Z",
            }],
          },
        });
      } catch {
        sendJson(res, 503, { error: "SAMPLE_FIXTURE_UNAVAILABLE" });
      }
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/sample-admission") {
      try { sendJson(res, 200, createAdmissionSample()); }
      catch { sendJson(res, 503, { error: "ADMISSION_SAMPLE_UNAVAILABLE" }); }
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/verify") {
      if (!req.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
        sendJson(res, 415, { error: "CONTENT_TYPE_JSON_REQUIRED" });
        return;
      }
      let raw: Buffer | "too-large";
      try { raw = await readBody(req); } catch {
        sendJson(res, 400, { error: "REQUEST_BODY_INVALID" });
        return;
      }
      if (raw === "too-large") {
        sendJson(res, 413, { error: "ARTIFACT_BUNDLE_TOO_LARGE" });
        return;
      }
      let parsed: unknown;
      try { parsed = parseArtifactJson(raw); } catch {
        sendJson(res, 400, { error: "ARTIFACT_JSON_INVALID" });
        return;
      }
      const bundle = validateBundle(parsed);
      if (!bundle) {
        sendJson(res, 400, { error: "ARTIFACT_BUNDLE_INVALID" });
        return;
      }
      try { sendJson(res, 200, verifyBundle(bundle)); }
      catch { sendJson(res, 422, { error: "ARTIFACT_VERIFICATION_FAILED" }); }
      return;
    }
    if (req.method === "GET" && Object.hasOwn(ASSET_TYPES, url.pathname)) {
      try {
        const body = readFileSync(join(assetRoot, url.pathname === "/" ? "index.html" : url.pathname.slice(1)));
        res.writeHead(200, { "Content-Type": ASSET_TYPES[url.pathname] });
        res.end(body);
      } catch {
        sendJson(res, 503, { error: "DASHBOARD_ASSET_UNAVAILABLE" });
      }
      return;
    }
    sendJson(res, 404, { error: "NOT_FOUND" });
  });
}
