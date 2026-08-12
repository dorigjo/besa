import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import {
  createHostedVerifierServer,
  type HostedVerifierAdmissionOptions,
} from "../server/hosted-verifier.js";
import { generateKeyPair, type KeyPair } from "../crypto.js";
import { createKeyRotation } from "../trust.js";
import { verifyAdmissionAttestationDetailed } from "../attestation.js";
import type { TrustStore } from "../types.js";
import { GOLDEN_RECEIPT, GOLDEN_SIGNED_MANIFEST } from "./fixtures/golden-v1.js";

async function withServer(
  run: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const server = createHostedVerifierServer();
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address() as AddressInfo;

  try {
    await run(`http://127.0.0.1:${String(address.port)}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

function trustedManifestKeyStore(): TrustStore {
  return {
    version: 1,
    keys: [
      {
        publicKeyId: GOLDEN_SIGNED_MANIFEST.publicKeyId,
        publicKey: GOLDEN_SIGNED_MANIFEST.publicKey,
        status: "active",
        addedAt: "2026-01-01T00:00:00.000Z",
      },
    ],
  };
}

async function withAdmissionServer(
  admission: HostedVerifierAdmissionOptions,
  run: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const server = createHostedVerifierServer({ admission });
  await new Promise<void>((resolve) => server.listen(0, resolve));
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
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(baseUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

test("GET /health returns ok and a version string", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(baseUrl + "/health");
    const body = (await response.json()) as { status: string; version: string };

    assert.equal(response.status, 200);
    assert.equal(body.status, "ok");
    assert.equal(typeof body.version, "string");
  });
});

test("POST /v1/verify/manifest accepts a valid golden signed manifest", async () => {
  await withServer(async (baseUrl) => {
    const { status, body } = await postJson(
      baseUrl,
      "/v1/verify/manifest",
      GOLDEN_SIGNED_MANIFEST,
    );

    assert.equal(status, 200);
    assert.deepEqual(body, {
      valid: true,
      reasonCode: "OK",
      detail: "manifest signature is valid",
    });
  });
});

test("POST /v1/verify/manifest rejects a tampered manifest, fails closed", async () => {
  await withServer(async (baseUrl) => {
    const tampered = {
      ...GOLDEN_SIGNED_MANIFEST,
      manifest: { ...GOLDEN_SIGNED_MANIFEST.manifest, serverName: "attacker-controlled" },
    };
    const { status, body } = await postJson(baseUrl, "/v1/verify/manifest", tampered);

    assert.equal(status, 200);
    assert.equal((body as { valid: boolean }).valid, false);
  });
});

test("POST /v1/verify/receipt accepts a valid golden receipt against its public key", async () => {
  await withServer(async (baseUrl) => {
    const { status, body } = await postJson(baseUrl, "/v1/verify/receipt", {
      receipt: GOLDEN_RECEIPT,
      publicKey: GOLDEN_SIGNED_MANIFEST.publicKey,
    });

    assert.equal(status, 200);
    assert.equal((body as { valid: boolean }).valid, true);
  });
});

test("POST /v1/verify/receipt rejects a receipt checked against the wrong public key", async () => {
  await withServer(async (baseUrl) => {
    const wrongKey = generateKeyPair().publicKeyDer;
    const { status, body } = await postJson(baseUrl, "/v1/verify/receipt", {
      receipt: GOLDEN_RECEIPT,
      publicKey: wrongKey,
    });

    assert.equal(status, 200);
    assert.equal((body as { valid: boolean }).valid, false);
  });
});

test("POST /v1/verify/receipt rejects a body missing publicKey", async () => {
  await withServer(async (baseUrl) => {
    const { status } = await postJson(baseUrl, "/v1/verify/receipt", {
      receipt: GOLDEN_RECEIPT,
    });

    assert.equal(status, 400);
  });
});

test("POST /v1/verify/rotation accepts a valid rotation and rejects a tampered one", async () => {
  await withServer(async (baseUrl) => {
    const previous = generateKeyPair();
    const next = generateKeyPair();
    const rotation = createKeyRotation(previous, next);

    const valid = await postJson(baseUrl, "/v1/verify/rotation", rotation);
    assert.equal(valid.status, 200);
    assert.equal((valid.body as { valid: boolean }).valid, true);

    const tampered = { ...rotation, newPublicKey: generateKeyPair().publicKeyDer };
    const invalid = await postJson(baseUrl, "/v1/verify/rotation", tampered);
    assert.equal(invalid.status, 200);
    assert.equal((invalid.body as { valid: boolean }).valid, false);
  });
});

test("malformed JSON body returns 400 on a verify route", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(baseUrl + "/v1/verify/manifest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not json",
    });

    assert.equal(response.status, 400);
  });
});

test("oversized request body is rejected with 413, not buffered unbounded", async () => {
  await withServer(async (baseUrl) => {
    // MAX_ARTIFACT_BYTES is 1 MiB; comfortably exceed it.
    const oversized = "x".repeat(1_048_576 + 1024);
    const response = await fetch(baseUrl + "/v1/verify/manifest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: oversized,
    });

    assert.equal(response.status, 413);
  });
});

test("wrong method on a known route returns 405", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(baseUrl + "/v1/verify/manifest");
    assert.equal(response.status, 405);
  });
});

test("unknown route returns 404", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(baseUrl + "/does-not-exist");
    assert.equal(response.status, 404);
  });
});

test("concurrent requests against one server instance each get their own correct result", async () => {
  await withServer(async (baseUrl) => {
    const tamperedManifest = {
      ...GOLDEN_SIGNED_MANIFEST,
      manifest: { ...GOLDEN_SIGNED_MANIFEST.manifest, serverName: "tampered" },
    };
    const requests = Array.from({ length: 20 }, (_, index) =>
      postJson(
        baseUrl,
        "/v1/verify/manifest",
        index % 2 === 0 ? GOLDEN_SIGNED_MANIFEST : tamperedManifest,
      ).then((result) => ({ index, ...result })),
    );

    const results = await Promise.all(requests);

    for (const result of results) {
      assert.equal(result.status, 200);
      const expectedValid = result.index % 2 === 0;
      assert.equal((result.body as { valid: boolean }).valid, expectedValid);
    }
  });
});

test("POST /v1/admit returns 501 when admission is not configured (default besa serve)", async () => {
  await withServer(async (baseUrl) => {
    const { status, body } = await postJson(baseUrl, "/v1/admit", {
      signedManifest: GOLDEN_SIGNED_MANIFEST,
      toolName: "crm.lookup",
    });

    assert.equal(status, 501);
    assert.match((body as { error: string }).error, /not enabled/);
  });
});

test("POST /v1/admit issues a signed allow attestation for a trusted manifest under budget", async () => {
  const keypair: KeyPair = generateKeyPair();
  const meterDir = mkdtempSync(join(tmpdir(), "besa-admission-test-"));
  const meterPath = join(meterDir, "meter.json");

  try {
    await withAdmissionServer(
      { trustStore: trustedManifestKeyStore(), meterPath, keyPair: keypair },
      async (baseUrl) => {
        const { status, body } = await postJson(baseUrl, "/v1/admit", {
          signedManifest: GOLDEN_SIGNED_MANIFEST,
          toolName: "crm.lookup",
        });

        assert.equal(status, 200);
        const attestation = body as {
          decision: string;
          reasonCode: string;
          meterCountAtCheck: number;
        };
        assert.equal(attestation.decision, "allow");
        assert.equal(attestation.reasonCode, "ALLOWED");
        assert.equal(attestation.meterCountAtCheck, 0);

        const verification = verifyAdmissionAttestationDetailed(
          attestation,
          keypair.publicKeyDer,
        );
        assert.equal(verification.valid, true);
      },
    );
  } finally {
    rmSync(meterDir, { recursive: true, force: true });
  }
});

test("POST /v1/admit issues a signed deny attestation for an untrusted manifest", async () => {
  const keypair: KeyPair = generateKeyPair();
  const meterDir = mkdtempSync(join(tmpdir(), "besa-admission-test-"));
  const meterPath = join(meterDir, "meter.json");
  const emptyTrustStore: TrustStore = { version: 1, keys: [] };

  try {
    await withAdmissionServer(
      { trustStore: emptyTrustStore, meterPath, keyPair: keypair },
      async (baseUrl) => {
        const { status, body } = await postJson(baseUrl, "/v1/admit", {
          signedManifest: GOLDEN_SIGNED_MANIFEST,
          toolName: "crm.lookup",
        });

        assert.equal(status, 200);
        const attestation = body as { decision: string; reasonCode: string };
        assert.equal(attestation.decision, "deny");
        assert.equal(attestation.reasonCode, "E_KEY_UNTRUSTED");

        const verification = verifyAdmissionAttestationDetailed(
          attestation,
          keypair.publicKeyDer,
        );
        assert.equal(verification.valid, true);
      },
    );
  } finally {
    rmSync(meterDir, { recursive: true, force: true });
  }
});

test("POST /v1/admit denies TOOL_NOT_FOUND for a tool absent from the manifest", async () => {
  const keypair: KeyPair = generateKeyPair();
  const meterDir = mkdtempSync(join(tmpdir(), "besa-admission-test-"));
  const meterPath = join(meterDir, "meter.json");

  try {
    await withAdmissionServer(
      { trustStore: trustedManifestKeyStore(), meterPath, keyPair: keypair },
      async (baseUrl) => {
        const { status, body } = await postJson(baseUrl, "/v1/admit", {
          signedManifest: GOLDEN_SIGNED_MANIFEST,
          toolName: "does.not.exist",
        });

        assert.equal(status, 200);
        const attestation = body as { decision: string; reasonCode: string };
        assert.equal(attestation.decision, "deny");
        assert.equal(attestation.reasonCode, "TOOL_NOT_FOUND");
      },
    );
  } finally {
    rmSync(meterDir, { recursive: true, force: true });
  }
});

test("POST /v1/admit denies BUDGET_EXCEEDED and does not consume/mutate the meter file", async () => {
  const keypair: KeyPair = generateKeyPair();
  const meterDir = mkdtempSync(join(tmpdir(), "besa-admission-test-"));
  const meterPath = join(meterDir, "meter.json");
  // crm.lookup's budgetLimit is 100 in the golden manifest; pre-set the
  // count to exactly the limit so admit() denies BUDGET_EXCEEDED.
  const meterState = {
    [`${GOLDEN_SIGNED_MANIFEST.manifestHash}:crm.lookup`]: 100,
  };
  writeFileSync(meterPath, JSON.stringify(meterState), "utf8");

  try {
    await withAdmissionServer(
      { trustStore: trustedManifestKeyStore(), meterPath, keyPair: keypair },
      async (baseUrl) => {
        const { status, body } = await postJson(baseUrl, "/v1/admit", {
          signedManifest: GOLDEN_SIGNED_MANIFEST,
          toolName: "crm.lookup",
        });

        assert.equal(status, 200);
        const attestation = body as {
          decision: string;
          reasonCode: string;
          meterCountAtCheck: number;
        };
        assert.equal(attestation.decision, "deny");
        assert.equal(attestation.reasonCode, "BUDGET_EXCEEDED");
        assert.equal(attestation.meterCountAtCheck, 100);

        // Non-consuming: the meter file on disk must be byte-identical
        // after the check — /v1/admit never acquires the meter lock or
        // writes to it, unlike the CLI's `besa receipt`.
        const afterCall = JSON.parse(readFileSync(meterPath, "utf8")) as unknown;
        assert.deepEqual(afterCall, meterState);
      },
    );
  } finally {
    rmSync(meterDir, { recursive: true, force: true });
  }
});

test("POST /v1/admit rejects a body missing toolName", async () => {
  const keypair: KeyPair = generateKeyPair();
  const meterDir = mkdtempSync(join(tmpdir(), "besa-admission-test-"));
  const meterPath = join(meterDir, "meter.json");

  try {
    await withAdmissionServer(
      { trustStore: trustedManifestKeyStore(), meterPath, keyPair: keypair },
      async (baseUrl) => {
        const { status } = await postJson(baseUrl, "/v1/admit", {
          signedManifest: GOLDEN_SIGNED_MANIFEST,
        });
        assert.equal(status, 400);
      },
    );
  } finally {
    rmSync(meterDir, { recursive: true, force: true });
  }
});

test("POST /v1/admit rejects a malformed signedManifest", async () => {
  const keypair: KeyPair = generateKeyPair();
  const meterDir = mkdtempSync(join(tmpdir(), "besa-admission-test-"));
  const meterPath = join(meterDir, "meter.json");

  try {
    await withAdmissionServer(
      { trustStore: trustedManifestKeyStore(), meterPath, keyPair: keypair },
      async (baseUrl) => {
        const { status } = await postJson(baseUrl, "/v1/admit", {
          signedManifest: { not: "a signed manifest" },
          toolName: "crm.lookup",
        });
        assert.equal(status, 400);
      },
    );
  } finally {
    rmSync(meterDir, { recursive: true, force: true });
  }
});

test("POST /v1/admit wrong method returns 405, unaffected by admission config", async () => {
  const keypair: KeyPair = generateKeyPair();
  const meterDir = mkdtempSync(join(tmpdir(), "besa-admission-test-"));
  const meterPath = join(meterDir, "meter.json");

  try {
    await withAdmissionServer(
      { trustStore: trustedManifestKeyStore(), meterPath, keyPair: keypair },
      async (baseUrl) => {
        const response = await fetch(baseUrl + "/v1/admit");
        assert.equal(response.status, 405);
      },
    );
  } finally {
    rmSync(meterDir, { recursive: true, force: true });
  }
});

test("GET /metrics reports aggregate request counters", async () => {
  await withServer(async (baseUrl) => {
    await fetch(baseUrl + "/health");
    await postJson(baseUrl, "/v1/verify/manifest", GOLDEN_SIGNED_MANIFEST);

    const response = await fetch(baseUrl + "/metrics");
    const body = (await response.json()) as {
      requestsTotal: number;
      requestsByRoute: Record<string, number>;
      requestsByStatus: Record<string, number>;
    };

    assert.equal(response.status, 200);
    // /health + /v1/verify/manifest happened before this call; /metrics
    // itself is not yet counted in the snapshot it returns.
    assert.equal(body.requestsTotal, 2);
    assert.equal(body.requestsByRoute["/health"], 1);
    assert.equal(body.requestsByRoute["/v1/verify/manifest"], 1);
    assert.equal(body.requestsByStatus["200"], 2);
  });
});

test("GET /metrics wrong method returns 405", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(baseUrl + "/metrics", { method: "POST" });
    assert.equal(response.status, 405);
  });
});

test("rate limiting returns 429 with Retry-After once the per-client limit is exceeded", async () => {
  const server = createHostedVerifierServer({ rateLimit: { limit: 2, windowMs: 60_000 } });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${String(address.port)}`;

  try {
    const first = await fetch(baseUrl + "/health");
    const second = await fetch(baseUrl + "/health");
    const third = await fetch(baseUrl + "/health");

    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(third.status, 429);
    assert.equal(third.headers.has("retry-after"), true);

    const body = (await third.json()) as { error: string };
    assert.equal(body.error, "rate limit exceeded");
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test("rate limiting is disabled by default (no rateLimit option)", async () => {
  await withServer(async (baseUrl) => {
    for (let i = 0; i < 10; i += 1) {
      const response = await fetch(baseUrl + "/health");
      assert.equal(response.status, 200);
    }
  });
});
