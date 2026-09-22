import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { ActionEnvelopeV1 } from "../action.js";
import type { ActionPolicyV1 } from "../action-policy.js";
import {
  createActionCapability,
  verifyActionCapability,
  type ActionCapabilityV1,
} from "../action-capability.js";
import { generateKeyPair } from "../crypto.js";
import {
  createHostedVerifierServer,
  type HostedVerifierOptions,
} from "../server/hosted-verifier.js";
import { addTrustAnchor, emptyTrustStore } from "../trust.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");
const API_TOKEN = "hosted-verifier-test-token-000001";

function action(overrides: Partial<ActionEnvelopeV1> = {}): ActionEnvelopeV1 {
  return {
    artifactVersion: 1,
    principalId: "principal:platform",
    agentId: "agent:release",
    authority: "iam:example:release-engineers",
    tool: "deployment.release",
    operation: "deploy",
    resource: "environment:staging",
    requestHash: "1".repeat(64),
    scopes: ["deployment:write"],
    constraints: {
      environment: "staging",
      repository: "dorigjo/besa",
      riskScore: 20,
    },
    expiresAt: "2026-09-21T12:05:00.000Z",
    nonce: "server_0123456789abcdef",
    riskClass: "high",
    ...overrides,
  };
}

function policy(): ActionPolicyV1 {
  return {
    version: 1,
    policyId: "policy:deployment-v1",
    delegationRequired: false,
    rules: [
      {
        ruleId: "allow-staging-deploy",
        principals: ["principal:platform"],
        agents: ["agent:release"],
        tools: ["deployment.release"],
        operations: ["deploy"],
        resources: ["environment:staging"],
        allowedScopes: ["deployment:write"],
        maxRisk: "high",
        constraints: {
          exact: {
            environment: "staging",
            repository: "dorigjo/besa",
          },
          maximums: { riskScore: 50 },
        },
      },
    ],
  };
}

function configuredOptions(): HostedVerifierOptions {
  const keyPair = generateKeyPair();
  const trustStore = addTrustAnchor(
    emptyTrustStore(),
    keyPair.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );
  return {
    actionAdmission: {
      apiToken: API_TOKEN,
      issuerId: "authority:hosted-verifier",
      keyPair,
      policy: policy(),
      trustStore,
    },
    clock: () => new Date(NOW),
    rateLimit: false,
  };
}

async function withConfiguredServer(
  options: HostedVerifierOptions,
  run: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const server = createHostedVerifierServer(options);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${String(address.port)}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

async function postJson(
  baseUrl: string,
  path: string,
  body: unknown,
  token?: string,
): Promise<{ response: Response; body: unknown }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(baseUrl + path, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

test("hosted verifier applies bounded HTTP defaults", () => {
  const server = createHostedVerifierServer({ rateLimit: false });
  assert.equal(server.requestTimeout, 10_000);
  assert.equal(server.headersTimeout, 5_000);
  assert.equal(server.keepAliveTimeout, 5_000);
  assert.equal(server.maxHeadersCount, 100);
});

test("health and readiness expose secure operational responses", async () => {
  await withConfiguredServer({ rateLimit: false }, async (baseUrl) => {
    const health = await fetch(baseUrl + "/health");
    const ready = await fetch(baseUrl + "/ready");
    assert.equal(health.status, 200);
    assert.equal(ready.status, 200);
    assert.equal(health.headers.get("cache-control"), "no-store");
    assert.equal(health.headers.get("x-content-type-options"), "nosniff");
  });
  await withConfiguredServer(
    { readiness: () => false, rateLimit: false },
    async (baseUrl) => {
      assert.equal((await fetch(baseUrl + "/ready")).status, 503);
    },
  );
});

test("POST routes require application/json", async () => {
  await withConfiguredServer({ rateLimit: false }, async (baseUrl) => {
    const response = await fetch(baseUrl + "/v1/verify/manifest", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "{}",
    });
    assert.equal(response.status, 415);
  });
});

test("POST routes reject malformed UTF-8 instead of decoding replacement text", async () => {
  await withConfiguredServer({ rateLimit: false }, async (baseUrl) => {
    const prefix = Buffer.from('{"value":"', "utf8");
    const invalidUtf8 = Buffer.from([0xc3, 0x28]);
    const suffix = Buffer.from('"}', "utf8");
    const response = await fetch(baseUrl + "/v1/verify/manifest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: Buffer.concat([prefix, invalidUtf8, suffix]),
    });

    assert.equal(response.status, 400);
  });
});

test("action admission requires a bearer token and issues verifiable decisions", async () => {
  const options = configuredOptions();
  await withConfiguredServer(options, async (baseUrl) => {
    const missing = await postJson(baseUrl, "/v1/actions/admit", { action: action() });
    assert.equal(missing.response.status, 401);
    const wrong = await postJson(
      baseUrl,
      "/v1/actions/admit",
      { action: action() },
      "wrong-token-wrong-token-wrong-token",
    );
    assert.equal(wrong.response.status, 401);

    const allowed = await postJson(
      baseUrl,
      "/v1/actions/admit",
      { action: action() },
      API_TOKEN,
    );
    assert.equal(allowed.response.status, 200);
    const capability = allowed.body as ActionCapabilityV1;
    assert.equal(capability.decision, "allow");

    const actionOptions = options.actionAdmission!;
    assert.equal(
      verifyActionCapability(
        capability,
        action(),
        actionOptions.trustStore,
        NOW,
      ).authorized,
      true,
    );

    const verified = await postJson(baseUrl, "/v1/verify/capability", {
      capability,
      action: action(),
    });
    assert.equal(verified.response.status, 200);
    assert.equal((verified.body as { valid: boolean }).valid, true);

    const denied = await postJson(
      baseUrl,
      "/v1/actions/admit",
      { action: action({ resource: "environment:production" }) },
      API_TOKEN,
    );
    assert.equal(denied.response.status, 200);
    assert.equal((denied.body as ActionCapabilityV1).decision, "deny");
    assert.equal(
      (denied.body as ActionCapabilityV1).reasonCode,
      "RESOURCE_NOT_GRANTED",
    );
  });
});

test("invalid admission tokens are covered by the per-client rate limit", async () => {
  await withConfiguredServer(
    {
      ...configuredOptions(),
      rateLimit: { limit: 2, windowMs: 60_000 },
    },
    async (baseUrl) => {
      const first = await postJson(
        baseUrl,
        "/v1/actions/admit",
        { action: action() },
        "wrong-token-wrong-token-wrong-token-1",
      );
      const second = await postJson(
        baseUrl,
        "/v1/actions/admit",
        { action: action() },
        "wrong-token-wrong-token-wrong-token-2",
      );
      const third = await postJson(
        baseUrl,
        "/v1/actions/admit",
        { action: action() },
        "wrong-token-wrong-token-wrong-token-3",
      );

      assert.equal(first.response.status, 401);
      assert.equal(second.response.status, 401);
      assert.equal(third.response.status, 429);
      assert.equal(third.response.headers.has("retry-after"), true);
    },
  );
});

test("action verification accepts a public trust store without a signing key", async () => {
  const issuer = generateKeyPair();
  const trustStore = addTrustAnchor(
    emptyTrustStore(),
    issuer.publicKeyDer,
    "2026-09-21T11:00:00.000Z",
  );
  const requested = action();
  const capability = createActionCapability(
    {
      action: requested,
      decision: "allow",
      reasonCode: "ACTION_ALLOWED",
      policyId: "policy:public-verification-v1",
      delegationChainHash: null,
      issuerId: "authority:separate-admission-service",
      issuedAt: "2026-09-21T11:00:00.000Z",
    },
    issuer,
  );

  await withConfiguredServer(
    { actionTrustStore: trustStore, clock: () => new Date(NOW), rateLimit: false },
    async (baseUrl) => {
      const verified = await postJson(baseUrl, "/v1/verify/capability", {
        capability,
        action: requested,
      });
      assert.equal(verified.response.status, 200);
      assert.equal((verified.body as { valid: boolean }).valid, true);
      assert.equal((await postJson(baseUrl, "/v1/actions/admit", { action: requested })).response.status, 501);
    },
  );

  assert.throws(
    () => createHostedVerifierServer({ actionTrustStore: { version: 1, keys: [{}] } as never }),
    /invalid actionTrustStore/,
  );
});

test("hosted verifier rejects invalid nested admission security configuration", () => {
  const options = configuredOptions();
  const admission = options.actionAdmission!;

  assert.throws(
    () =>
      createHostedVerifierServer({
        ...options,
        actionAdmission: {
          ...admission,
          keyPair: { publicKeyDer: "", privateKeyDer: "" },
        },
      }),
    /actionAdmission\.keyPair/,
  );
  assert.throws(
    () =>
      createHostedVerifierServer({
        ...options,
        actionAdmission: { ...admission, issuerId: "" },
      }),
    /actionAdmission\.issuerId/,
  );
  assert.throws(
    () =>
      createHostedVerifierServer({
        ...options,
        actionAdmission: {
          ...admission,
          trustStore: { version: 1, keys: [{}] } as never,
        },
      }),
    /invalid actionAdmission\.trustStore/,
  );
});
