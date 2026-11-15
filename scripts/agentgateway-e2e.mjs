import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { once } from "node:events";
import { pathToFileURL } from "node:url";
import {
  addTrustAnchor,
  admitPreExecution,
  createExternalAuthority,
  emptyTrustStore,
  generateKeyPair,
  hashActionPolicy,
  hashPreExecutionReceipt,
  hashRequest,
  InMemoryReplayStore,
  verifyActionEvidence,
  verifyPreExecutionAdmission,
  withBesaExecutor,
} from "../dist/sdk.js";

const IMAGE = "cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b";
const NOW = new Date("2026-11-01T12:00:00.000Z");
const BEFORE = "2026-11-01T11:00:00.000Z";
const EXPIRY = "2026-11-01T13:00:00.000Z";
const copy = (value) => JSON.parse(JSON.stringify(value));

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

async function verifyEvidenceBundleFromStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    expect(size <= 1_048_576, "evidence bundle exceeds 1 MiB");
    chunks.push(chunk);
  }
  const bundle = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const config = {
    policy: bundle.policy,
    audience: bundle.audience,
    trustStore: bundle.trustStore,
    authorityTrustStore: bundle.authorityTrustStore,
  };
  const at = new Date(bundle.verificationTime);
  const admission = verifyPreExecutionAdmission(bundle.receipt, bundle.input, config, at, "audit");
  const evidenceInput = {
    action: bundle.input.request.action,
    capability: bundle.receipt.capability,
    result: bundle.result,
    trustStore: bundle.trustStore,
    receiptHash: hashPreExecutionReceipt(bundle.receipt),
  };
  const evidence = verifyActionEvidence(bundle.evidence, evidenceInput, at);
  const changedInput = copy(bundle.input);
  changedInput.request.parameters.amountCents += 1;
  const changedAction = verifyPreExecutionAdmission(bundle.receipt, changedInput, config, at, "audit");
  const changedResult = verifyActionEvidence(bundle.evidence, {
    ...evidenceInput,
    result: { ...bundle.result, status: "forged" },
  }, at);
  return {
    admissionValid: admission.valid && admission.receipt?.decision === "allow",
    executionEvidenceValid: evidence.valid,
    changedParametersRejected: !changedAction.valid,
    changedResultRejected: !changedResult.valid,
  };
}

function verifyEvidenceBundleInSeparateProcess(bundle) {
  const encoded = JSON.stringify(bundle);
  expect(!/privateKeyDer|privateKey|BEGIN PRIVATE KEY/i.test(encoded),
    "verification bundle unexpectedly contains private-key material");
  const childEnv = Object.fromEntries(
    ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"]
      .filter((name) => process.env[name] !== undefined)
      .map((name) => [name, process.env[name]]),
  );
  const child = spawnSync(process.execPath, [process.argv[1], "--verify-evidence-bundle"], {
    input: encoded,
    encoding: "utf8",
    env: childEnv,
    timeout: 10_000,
    maxBuffer: 1_048_576,
  });
  expect(child.status === 0, `independent verifier process failed: ${child.stderr || child.error || child.stdout}`);
  const result = JSON.parse(child.stdout);
  expect(result.admissionValid, "separate verifier rejected the valid admission");
  expect(result.executionEvidenceValid, "separate verifier rejected execution evidence");
  expect(result.changedParametersRejected, "separate verifier accepted modified action parameters");
  expect(result.changedResultRejected, "separate verifier accepted a modified execution result");
  return result;
}

function createFixture() {
  const issuer = generateKeyPair();
  const normalizer = generateKeyPair();
  const recorder = generateKeyPair();
  const caller = { principalId: "principal:support", agentId: "agent:refunds" };
  const tenantId = "tenant:e2e";
  const customerId = "customer_123";
  const recipientAccount = "account:original-payment";
  const resource = `refund:${tenantId}:${customerId}`;
  const policy = {
    version: 1,
    policyId: "agentgateway-refund-e2e-v1",
    delegationRequired: false,
    rules: [{
      ruleId: "refund",
      principals: [caller.principalId],
      agents: [caller.agentId],
      tools: ["payments.refund"],
      operations: ["refund"],
      resources: [resource],
      allowedScopes: ["refund:write"],
      maxRisk: "high",
      constraints: {
        exact: { tenantId, recipientAccount, currency: "EUR" },
        maximums: { amountCents: 480_000 },
      },
    }],
  };
  const parameters = {
    admissionId: "allow-1",
    tenantId,
    customerId,
    recipientAccount,
    amountCents: 480_000,
    currency: "EUR",
  };
  const context = {
    executorId: "executor:agentgateway-refunds",
    gateway: { product: "agentgateway", version: "1.7.0", routeId: "refund-e2e" },
  };
  const action = {
    artifactVersion: 1,
    ...caller,
    authority: "authority:support-platform",
    tool: "payments.refund",
    operation: "refund",
    resource,
    requestHash: hashRequest(parameters),
    contextHash: hashRequest(context),
    scopes: ["refund:write"],
    constraints: { tenantId, recipientAccount, currency: "EUR", amountCents: 480_000 },
    expiresAt: EXPIRY,
    nonce: "agentgateway_refund_0001",
    riskClass: "high",
  };
  const request = {
    requestVersion: 1,
    action,
    parameters,
    context,
    audience: "https://refunds.internal.example/mcp",
    policy: { id: policy.policyId, version: 1, hash: hashActionPolicy(policy) },
    requestedAt: NOW.toISOString(),
  };
  const authority = createExternalAuthority({
    artifactVersion: 1,
    mechanism: "mcp-ema-access-token",
    ...caller,
    issuer: action.authority,
    audience: request.audience,
    tools: [action.tool],
    operations: [action.operation],
    resources: [resource],
    scopes: ["refund:write"],
    constraints: {
      exact: { tenantId, recipientAccount, currency: "EUR" },
      maximums: { amountCents: 480_000 },
    },
    notBefore: BEFORE,
    expiresAt: EXPIRY,
    assertionDigest: "a".repeat(64),
    delegationChainHash: null,
  }, { id: "normalizer:gateway-e2e", keyPair: normalizer, issuedAt: BEFORE });
  const input = { request, authority };
  const trustStore = addTrustAnchor(
    addTrustAnchor(emptyTrustStore(), issuer.publicKeyDer, BEFORE),
    recorder.publicKeyDer,
    BEFORE,
  );
  const authorityTrustStore = addTrustAnchor(
    emptyTrustStore(),
    normalizer.publicKeyDer,
    BEFORE,
  );
  const admission = {
    policy,
    audience: request.audience,
    trustStore,
    authorityTrustStore,
    issuerId: "admission:gateway-e2e",
    keyPair: issuer,
  };
  const receipt = admitPreExecution(input, admission, NOW);
  expect(receipt.decision === "allow", `fixture admission denied: ${receipt.reasonCode}`);
  const admissions = [];
  const evidence = [];
  const config = {
    policy,
    audience: request.audience,
    trustStore,
    authorityTrustStore,
    executorId: context.executorId,
    recorderId: "recorder:gateway-e2e",
    evidenceKeyPair: recorder,
    replayStore: new InMemoryReplayStore(),
    admissionSink: { async append(value) { admissions.push(value); } },
    evidenceSink: { async append(value) { evidence.push(value); } },
    clock: () => new Date(NOW),
  };
  return { caller, input, receipt, admission, config, admissions, evidence };
}

function actualInput(template, parameters) {
  const input = copy(template);
  input.request.parameters = copy(parameters);
  input.request.action.requestHash = hashRequest(input.request.parameters);
  input.request.action.resource = `refund:${parameters.tenantId}:${parameters.customerId}`;
  input.request.action.constraints = {
    tenantId: parameters.tenantId,
    recipientAccount: parameters.recipientAccount,
    currency: parameters.currency,
    amountCents: parameters.amountCents,
  };
  return input;
}

async function readJsonBody(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > 1_048_576) throw new Error("request too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(response, status, value, headers = {}) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json",
    ...headers,
  });
  response.end(body);
}

function createProtectedBackend(fixture, state, backendToken) {
  const execute = withBesaExecutor(fixture.config, (input) => {
    state.handlerCalls++;
    const amountCents = input.request.parameters.amountCents;
    return { refundId: `refund-${amountCents}`, status: "accepted" };
  });
  return createServer(async (request, response) => {
    state.backendRequests++;
    try {
      const presented = request.headers["x-besa-e2e-backend-token"];
      const actual = typeof presented === "string" ? Buffer.from(presented, "utf8") : Buffer.alloc(0);
      const expected = Buffer.from(backendToken, "utf8");
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        state.backendAuthRejected++;
        request.resume();
        sendJson(response, 401, { error: "gateway authentication required" });
        return;
      }
      if (request.method !== "POST" || request.url !== "/mcp") {
        sendJson(response, 404, { error: "not found" });
        return;
      }
      const message = await readJsonBody(request);
      if (message.method === "notifications/initialized") {
        response.writeHead(202).end();
        return;
      }
      if (message.method === "initialize") {
        sendJson(response, 200, {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: "2025-06-18",
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "besa-refund-e2e", version: "1.0.0" },
          },
        }, { "mcp-session-id": "besa-backend-session" });
        return;
      }
      if (message.method === "tools/list") {
        sendJson(response, 200, {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            tools: [{
              name: "refund",
              description: "Issue an exact admitted refund",
              inputSchema: {
                type: "object",
                required: ["admissionId", "tenantId", "customerId", "recipientAccount", "amountCents", "currency"],
                properties: {
                  admissionId: { type: "string" },
                  tenantId: { type: "string" },
                  customerId: { type: "string" },
                  recipientAccount: { type: "string" },
                  amountCents: { type: "integer" },
                  currency: { type: "string" },
                },
              },
            }],
          },
        });
        return;
      }
      if (message.method !== "tools/call" || message.params?.name !== "refund") {
        sendJson(response, 200, {
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32601, message: "method or tool not found" },
        });
        return;
      }
      state.toolCalls++;
      const argumentsValue = message.params.arguments ?? {};
      const input = actualInput(fixture.input, argumentsValue);
      const receipt = argumentsValue.admissionId === "allow-1" ? fixture.receipt : undefined;
      const caller = {
        principalId: String(request.headers["x-authenticated-user"] ?? ""),
        agentId: String(request.headers["x-authenticated-agent"] ?? ""),
      };
      state.observedCallers.push(caller);
      try {
        const result = await execute(input, receipt, caller);
        state.lastExecution = { input, result };
        sendJson(response, 200, {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            content: [{ type: "text", text: JSON.stringify(result.result) }],
            structuredContent: result.result,
          },
        });
      } catch (error) {
        sendJson(response, 200, {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            isError: true,
            content: [{ type: "text", text: error instanceof Error ? error.message : "denied" }],
          },
        });
      }
    } catch (error) {
      sendJson(response, 400, { error: error instanceof Error ? error.message : "bad request" });
    }
  });
}

async function freePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForGateway(url, child, logs) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`agentgateway exited early (${child.exitCode}): ${logs()}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.status > 0) return;
    } catch {
      // Retry while the pinned container starts.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`agentgateway did not become ready: ${logs()}`);
}

function parseRpc(text) {
  if (text.trim().startsWith("{")) return JSON.parse(text);
  const data = text.split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trim())
    .filter(Boolean)
    .at(-1);
  if (!data) throw new Error(`MCP response contained no JSON-RPC data: ${text.slice(0, 200)}`);
  return JSON.parse(data);
}

async function readRpcResponse(response) {
  if (response.status === 202 || response.status === 204) return undefined;
  if (!response.headers.get("content-type")?.includes("text/event-stream")) {
    const text = await response.text();
    return text ? parseRpc(text) : undefined;
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("MCP event stream has no readable body");
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += Buffer.from(value).toString("utf8");
      if (Buffer.byteLength(text) > 1_048_576) throw new Error("MCP response too large");
      const eventEnd = text.search(/\r?\n\r?\n/);
      if (eventEnd >= 0) return parseRpc(text.slice(0, eventEnd));
    }
    return text ? parseRpc(text) : undefined;
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

async function rpc(url, apiKey, message, sessionId, extraHeaders = {}) {
  const headers = {
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
    ...extraHeaders,
  };
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(message),
    signal: AbortSignal.timeout(10_000),
  });
  const body = response.status === 401 || response.status === 403
    ? undefined
    : await readRpcResponse(response);
  return {
    status: response.status,
    sessionId: response.headers.get("mcp-session-id") ?? sessionId,
    body,
  };
}

export async function runBackendAuthSelfTest() {
  const fixture = createFixture();
  const backendToken = randomBytes(32).toString("base64url");
  const state = { handlerCalls: 0, toolCalls: 0, observedCallers: [], lastExecution: undefined,
    backendAuthRejected: 0, backendRequests: 0 };
  const backend = createProtectedBackend(fixture, state, backendToken);
  backend.listen(0, "127.0.0.1");
  await once(backend, "listening");
  const address = backend.address();
  const url = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}/mcp`;
  const request = {
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "refund", arguments: copy(fixture.input.request.parameters) },
  };
  try {
    const unauthenticated = await rpc(url, undefined, request, undefined, {
      "x-authenticated-user": fixture.caller.principalId,
      "x-authenticated-agent": fixture.caller.agentId,
    });
    expect(unauthenticated.status === 401, "forged caller headers bypassed backend authentication");
    expect(state.toolCalls === 0 && state.handlerCalls === 0,
      "unauthenticated direct request reached the protected handler");

    const forwarded = await rpc(url, undefined, request, undefined, {
      "x-besa-e2e-backend-token": backendToken,
      "x-authenticated-user": fixture.caller.principalId,
      "x-authenticated-agent": fixture.caller.agentId,
    });
    expect(forwarded.status === 200 && forwarded.body?.result?.isError !== true,
      "authorized forwarded request did not execute");
    expect(state.handlerCalls === 1, "authorized forwarded request did not execute exactly once");
    return {
      unauthenticatedDirectCallStatus: unauthenticated.status,
      forgedIdentityHeadersRejected: true,
      authorizedForwardedCallExecutedOnce: true,
      backendAuthRejections: state.backendAuthRejected,
      backendRequests: state.backendRequests,
    };
  } finally {
    backend.closeIdleConnections();
    await new Promise((resolve) => backend.close(resolve));
  }
}

function classifyUnauthenticatedTransportError(error) {
  if (error instanceof TypeError && error.cause?.name === "HTTPParserError" &&
      error.cause?.data === "uthentication failed") {
    return "malformed-auth-failure-response";
  }
  return undefined;
}

export async function runAgentgatewayE2E() {
  const versionProbe = spawnSync("docker", [
    "run", "--rm", "--pull=never", IMAGE, "--version",
  ], { encoding: "utf8", timeout: 30_000 });
  expect(versionProbe.status === 0, `agentgateway version probe failed: ${versionProbe.stderr}`);
  const gatewayBuild = JSON.parse(versionProbe.stdout);
  expect(gatewayBuild.version === "1.7.0", `unexpected agentgateway version: ${gatewayBuild.version}`);

  const fixture = createFixture();
  const backendToken = randomBytes(32).toString("base64url");
  const gatewayApiKey = randomBytes(32).toString("base64url");
  const state = { handlerCalls: 0, toolCalls: 0, observedCallers: [], lastExecution: undefined,
    backendAuthRejected: 0, backendRequests: 0 };
  const backend = createProtectedBackend(fixture, state, backendToken);
  backend.listen(0, "127.0.0.1");
  await once(backend, "listening");
  const backendAddress = backend.address();
  const backendPort = typeof backendAddress === "object" && backendAddress ? backendAddress.port : 0;
  let gatewayPort;
  try { gatewayPort = await freePort(); }
  catch (error) {
    await new Promise((resolve) => backend.close(resolve));
    throw error;
  }
  const containerName = `besa-agentgateway-e2e-${randomUUID()}`;
  const config = JSON.stringify({
    mcp: {
      port: 3000,
      policies: {
        apiKey: {
          mode: "strict",
          keys: [{
            key: gatewayApiKey,
            metadata: { user: fixture.caller.principalId, agent: fixture.caller.agentId },
          }],
        },
        transformations: {
          request: {
            set: {
              "x-authenticated-user": "apiKey.user",
              "x-authenticated-agent": "apiKey.agent",
              "x-besa-e2e-backend-token": `'${backendToken}'`,
            },
          },
        },
      },
      targets: [{
        name: "besa",
        mcp: { host: `http://host.docker.internal:${backendPort}/mcp` },
      }],
    },
  });
  const validation = spawnSync("docker", [
    "run", "--rm", "--pull=never", IMAGE, "--validate-only", "-c", config,
  ], { encoding: "utf8", timeout: 30_000 });
  if (validation.status !== 0) {
    backend.closeIdleConnections();
    await new Promise((resolve) => backend.close(resolve));
    throw new Error(`agentgateway config invalid: ${validation.stderr || validation.stdout}`);
  }
  const child = spawn("docker", [
    "run", "--rm", "--name", containerName, "--pull=never",
    "--add-host", "host.docker.internal:host-gateway",
    "-p", `127.0.0.1:${gatewayPort}:3000`, IMAGE, "-c", config,
  ], { stdio: ["ignore", "pipe", "pipe"] });
  let containerLogs = "";
  const capture = (chunk) => {
    containerLogs = `${containerLogs}${chunk.toString("utf8")}`.slice(-65_536);
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  const url = `http://127.0.0.1:${gatewayPort}/mcp`;
  try {
    const directBypass = await rpc(`http://127.0.0.1:${backendPort}/mcp`, undefined, {
      jsonrpc: "2.0", id: 0, method: "tools/call",
      params: { name: "refund", arguments: copy(fixture.input.request.parameters) },
    }, undefined, {
      "x-authenticated-user": fixture.caller.principalId,
      "x-authenticated-agent": fixture.caller.agentId,
    });
    expect(directBypass.status === 401, "direct backend bypass was not rejected");
    expect(state.toolCalls === 0 && state.handlerCalls === 0,
      "direct backend bypass reached the protected tool");

    await waitForGateway(url, child, () => containerLogs);
    let unauthenticatedStatus;
    let unauthenticatedTransportFailure;
    const backendCallsBeforeUnauthenticated = state.backendRequests;
    try {
      const unauthenticated = await rpc(url, undefined, {
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "besa-e2e", version: "1" } },
      });
      expect(unauthenticated.status === 401 || unauthenticated.status === 403,
        `gateway accepted unauthenticated MCP request (${unauthenticated.status})`);
      unauthenticatedStatus = String(unauthenticated.status);
    } catch (error) {
      unauthenticatedTransportFailure = classifyUnauthenticatedTransportError(error);
      expect(unauthenticatedTransportFailure !== undefined,
        `unexpected unauthenticated transport failure: ${error instanceof Error ? error.message : String(error)}`);
      unauthenticatedStatus = "transport-rejected";
    }
    expect(unauthenticatedStatus === "401" || unauthenticatedStatus === "403" ||
      (unauthenticatedStatus === "transport-rejected" &&
        unauthenticatedTransportFailure === "malformed-auth-failure-response"),
    "unauthenticated request did not receive a recognized rejection");
    expect(state.backendRequests === backendCallsBeforeUnauthenticated,
      "gateway forwarded an unauthenticated request to the backend");
    expect(state.toolCalls === 0 && state.handlerCalls === 0,
      "unauthenticated request reached the protected backend");

    const initialized = await rpc(url, gatewayApiKey, {
      jsonrpc: "2.0", id: 2, method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "besa-e2e", version: "1" } },
    });
    expect(initialized.status === 200, `initialize failed: ${initialized.status}`);
    const sessionId = initialized.sessionId;
    expect(typeof sessionId === "string" && sessionId.length > 0, "gateway returned no MCP session id");
    await rpc(url, gatewayApiKey, { jsonrpc: "2.0", method: "notifications/initialized" }, sessionId);
    const listed = await rpc(url, gatewayApiKey, { jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }, sessionId);
    const tools = listed.body?.result?.tools;
    expect(Array.isArray(tools), "gateway tools/list returned no tools");
    const tool = tools.find((candidate) => typeof candidate.name === "string" && candidate.name.includes("refund"));
    expect(tool, "gateway did not expose the protected refund tool");

    const exact = copy(fixture.input.request.parameters);
    const missing = await rpc(url, gatewayApiKey, {
      jsonrpc: "2.0", id: 4, method: "tools/call",
      params: { name: tool.name, arguments: { ...exact, admissionId: "missing" } },
    }, sessionId);
    expect(missing.body?.result?.isError === true, "gateway-authenticated request bypassed missing Besa admission");
    expect(state.handlerCalls === 0, "missing admission reached refund handler");

    const tampered = await rpc(url, gatewayApiKey, {
      jsonrpc: "2.0", id: 5, method: "tools/call",
      params: { name: tool.name, arguments: { ...exact, amountCents: 479_999 } },
    }, sessionId);
    expect(tampered.body?.result?.isError === true, "tampered arguments were accepted");
    expect(state.handlerCalls === 0, "tampered arguments reached refund handler");

    const allowed = await rpc(url, gatewayApiKey, {
      jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: tool.name, arguments: exact },
    }, sessionId, {
      "x-authenticated-user": "principal:attacker",
      "x-authenticated-agent": "agent:attacker",
    });
    expect(allowed.body?.result?.isError !== true, "exact admitted action was denied");
    expect(state.handlerCalls === 1, `expected one handler call, got ${state.handlerCalls}`);
    const observed = state.observedCallers.at(-1);
    expect(observed?.principalId === fixture.caller.principalId && observed?.agentId === fixture.caller.agentId,
      "agent-controlled identity headers were not replaced by gateway metadata");

    const replay = await rpc(url, gatewayApiKey, {
      jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: tool.name, arguments: exact },
    }, sessionId);
    expect(replay.body?.result?.isError === true, "replayed admission was accepted");
    expect(state.handlerCalls === 1, "replay caused a second refund handler call");

    const execution = state.lastExecution;
    expect(execution, "successful execution result was not recorded by the harness");
    const independentVerification = verifyEvidenceBundleInSeparateProcess({
      input: execution.input,
      receipt: execution.result.receipt,
      result: execution.result.result,
      evidence: execution.result.evidence,
      policy: fixture.config.policy,
      audience: fixture.config.audience,
      trustStore: fixture.config.trustStore,
      authorityTrustStore: fixture.config.authorityTrustStore,
      verificationTime: NOW.toISOString(),
    });

    return {
      image: IMAGE,
      gatewayVersion: gatewayBuild.version,
      gatewayRevision: gatewayBuild.git_revision,
      backendVersion: initialized.body?.result?.serverInfo?.version,
      directBackendBypassBlocked: true,
      backendAuthRejections: state.backendAuthRejected,
      backendRequests: state.backendRequests,
      unauthenticatedStatus,
      unauthenticatedTransportFailure: unauthenticatedTransportFailure ?? null,
      protectedTool: tool.name,
      gatewayToolCalls: state.toolCalls,
      handlerCalls: state.handlerCalls,
      missingAdmissionBlocked: true,
      tamperedArgumentsBlocked: true,
      replayBlocked: true,
      offlineAdmissionVerified: independentVerification.admissionValid,
      offlineExecutionEvidenceVerified: independentVerification.executionEvidenceValid,
      independentVerifierProcess: true,
      verifierRejectedChangedParameters: independentVerification.changedParametersRejected,
      verifierRejectedChangedResult: independentVerification.changedResultRejected,
    };
  } finally {
    spawnSync("docker", ["rm", "--force", containerName], { encoding: "utf8", timeout: 15_000 });
    child.kill();
    backend.closeIdleConnections();
    await new Promise((resolve) => backend.close(resolve));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = process.argv[2] === "--verify-evidence-bundle"
    ? await verifyEvidenceBundleFromStdin()
    : process.argv[2] === "--test-backend-auth"
      ? await runBackendAuthSelfTest()
      : await runAgentgatewayE2E();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
