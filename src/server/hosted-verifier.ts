import http from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateSignedManifest,
  verifySignedManifest,
  verifyReceiptDetailed,
} from "../signing.js";
import { verifyKeyRotation, verifyTrustedSignedManifest } from "../trust.js";
import { admit, getCount, loadMeter, meterKey } from "../admit.js";
import { createAdmissionAttestation } from "../attestation.js";
import { MAX_ARTIFACT_BYTES } from "../io.js";
import { RateLimiter } from "./rate-limiter.js";
import { Metrics } from "./metrics.js";
import type { VerifyResult } from "../signing.js";
import type { TrustStore } from "../types.js";
import type { KeyPair } from "../crypto.js";

export interface HostedVerifierAdmissionOptions {
  trustStore: TrustStore;
  meterPath: string;
  keyPair: KeyPair;
}

export interface HostedVerifierRateLimitOptions {
  /** Max requests per client (by remote address) per window. */
  limit: number;
  /** Window duration in ms. Defaults to 60_000 (1 minute). */
  windowMs?: number;
}

export interface HostedVerifierOptions {
  port?: number;
  admission?: HostedVerifierAdmissionOptions;
  rateLimit?: HostedVerifierRateLimitOptions;
}

interface RouteResult {
  status: number;
  body: unknown;
}

function readPackageVersion(): string {
  try {
    // dist/server/hosted-verifier.js -> dist/server -> dist -> package root
    const packageRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
    const pkg = JSON.parse(
      readFileSync(join(packageRoot, "package.json"), "utf8"),
    ) as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

const VERSION = readPackageVersion();

function readBody(req: http.IncomingMessage): Promise<Buffer | "too-large"> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;

    req.on("data", (chunk: Buffer) => {
      // Once the ceiling is crossed, stop accumulating (bounded memory) but
      // keep draining the socket so the client's write completes normally —
      // destroying the socket here would race the 413 response the caller
      // is about to send and the client would see a connection reset
      // instead of a structured error.
      if (tooLarge) return;

      total += chunk.length;
      if (total > MAX_ARTIFACT_BYTES) {
        tooLarge = true;
        resolve("too-large");
        return;
      }

      chunks.push(chunk);
    });

    req.on("end", () => {
      if (!tooLarge) resolve(Buffer.concat(chunks));
    });

    req.on("error", (error) => {
      if (!tooLarge) reject(error);
    });
  });
}

function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(raw.toString("utf8")) as unknown };
  } catch {
    return { ok: false };
  }
}

function verifyResultResponse(result: VerifyResult): RouteResult {
  return { status: 200, body: result };
}

function isReceiptEnvelope(
  value: unknown,
): value is { receipt: unknown; publicKey: unknown } {
  return (
    typeof value === "object" &&
    value !== null &&
    "receipt" in value &&
    "publicKey" in value
  );
}

function isAdmissionEnvelope(
  value: unknown,
): value is { signedManifest: unknown; toolName: unknown } {
  return (
    typeof value === "object" &&
    value !== null &&
    "signedManifest" in value &&
    "toolName" in value
  );
}

// Non-consuming admission check: verifies the manifest's trust chain, reads
// (never locks or writes) the current meter count, and returns a signed
// AdmissionAttestation — the same admit() decision logic and the same
// signWithKeyPair() primitive the CLI's `besa admit`/`besa receipt` already
// use, exposed over HTTP. Never acquires the meter file lock, so it can
// never block the event loop the way a consuming call (admitAndConsume)
// would under contention. See docs/RUNTIME_ADMISSION.md for the full
// guarantee/non-guarantee statement and why this is not a Receipt.
function handleAdmissionRequest(
  parsedBody: unknown,
  admission: HostedVerifierAdmissionOptions,
): RouteResult {
  if (
    !isAdmissionEnvelope(parsedBody) ||
    typeof parsedBody.toolName !== "string"
  ) {
    return {
      status: 400,
      body: { error: "body must be { signedManifest: <SignedManifest>, toolName: <string> }" },
    };
  }

  const manifestValidation = validateSignedManifest(parsedBody.signedManifest);
  if (!manifestValidation.ok || !manifestValidation.signedManifest) {
    return {
      status: 400,
      body: { error: `signedManifest is malformed: ${manifestValidation.errors.join("; ")}` },
    };
  }

  const signed = manifestValidation.signedManifest;
  const toolName = parsedBody.toolName;

  try {
    const trustResult = verifyTrustedSignedManifest(signed, admission.trustStore, "admit");

    let decisionOutcome: { decision: "allow" | "deny"; reasonCode: string; detail: string };
    let meterCountAtCheck = 0;

    if (!trustResult.valid) {
      decisionOutcome = {
        decision: "deny",
        reasonCode: trustResult.reasonCode,
        detail: trustResult.detail,
      };
    } else {
      let key: string | undefined;
      try {
        key = meterKey(signed.manifestHash, toolName);
      } catch {
        key = undefined;
      }

      if (key !== undefined) {
        meterCountAtCheck = getCount(loadMeter(admission.meterPath), key);
      }

      const decision = admit(signed.manifest, toolName, meterCountAtCheck);
      decisionOutcome = {
        decision: decision.decision,
        reasonCode: decision.reasonCode,
        detail: decision.detail,
      };
    }

    const attestation = createAdmissionAttestation(
      {
        manifestHash: signed.manifestHash,
        toolName,
        decision: decisionOutcome.decision,
        reasonCode: decisionOutcome.reasonCode,
        detail: decisionOutcome.detail,
        meterCountAtCheck,
      },
      admission.keyPair,
    );

    return { status: 200, body: attestation };
  } catch {
    // Meter file corruption or an unexpected storage error: fail closed with
    // a fixed, non-leaking error rather than risk issuing an attestation
    // built from a wrong or partial meter read.
    return { status: 500, body: { error: "admission check failed" } };
  }
}

/**
 * Pure route dispatch: method + path + raw body bytes in, {status, body} out.
 * No socket required — exercised directly by tests without spinning a real
 * HTTP server, and reused by the actual http.Server request handler below.
 */
export function routeVerifierRequest(
  method: string,
  url: string,
  rawBody: Buffer | "too-large",
  admission?: HostedVerifierAdmissionOptions,
  metrics?: Metrics,
): RouteResult {
  if (rawBody === "too-large") {
    return {
      status: 413,
      body: {
        error: `request body exceeds the ${String(MAX_ARTIFACT_BYTES)} byte limit`,
      },
    };
  }

  if (url === "/health") {
    if (method !== "GET") {
      return { status: 405, body: { error: "method not allowed" } };
    }
    return { status: 200, body: { status: "ok", version: VERSION } };
  }

  if (url === "/metrics") {
    if (method !== "GET") {
      return { status: 405, body: { error: "method not allowed" } };
    }
    return { status: 200, body: metrics?.snapshot() ?? new Metrics().snapshot() };
  }

  if (url === "/v1/admit") {
    if (method !== "POST") {
      return { status: 405, body: { error: "method not allowed" } };
    }

    if (!admission) {
      return {
        status: 501,
        body: {
          error: "admission is not enabled on this server; start `besa serve` with --trust and a signing key to enable /v1/admit",
        },
      };
    }

    const parsed = parseJsonBody(rawBody);
    if (!parsed.ok) {
      return { status: 400, body: { error: "invalid JSON body" } };
    }

    return handleAdmissionRequest(parsed.value, admission);
  }

  const verifyRoutes = new Set([
    "/v1/verify/manifest",
    "/v1/verify/receipt",
    "/v1/verify/rotation",
  ]);

  if (!verifyRoutes.has(url)) {
    return { status: 404, body: { error: "not found" } };
  }

  if (method !== "POST") {
    return { status: 405, body: { error: "method not allowed" } };
  }

  const parsed = parseJsonBody(rawBody);
  if (!parsed.ok) {
    return { status: 400, body: { error: "invalid JSON body" } };
  }

  if (url === "/v1/verify/manifest") {
    return verifyResultResponse(verifySignedManifest(parsed.value));
  }

  if (url === "/v1/verify/rotation") {
    return verifyResultResponse(verifyKeyRotation(parsed.value));
  }

  // /v1/verify/receipt
  if (!isReceiptEnvelope(parsed.value) || typeof parsed.value.publicKey !== "string") {
    return {
      status: 400,
      body: { error: "body must be { receipt: <Receipt>, publicKey: <string> }" },
    };
  }

  return verifyResultResponse(
    verifyReceiptDetailed(parsed.value.receipt, parsed.value.publicKey),
  );
}

/**
 * Hosted verifier. By default (no `admission` option) this is exactly the
 * Phase 5 behavior: wraps verifySignedManifest/verifyReceiptDetailed/
 * verifyKeyRotation behind HTTP, never loads a signing key, never touches a
 * trust store, never issues receipts or makes admission decisions. See
 * docs/HOSTED_VERIFIER.md for that guarantee/non-guarantee statement, which
 * is unchanged for a plain `besa serve` invocation.
 *
 * When `admission` is supplied, this ALSO mounts POST /v1/admit — an
 * opt-in, additive Phase 7 route that loads a signing key and a trust
 * store to issue signed, non-consuming AdmissionAttestations. This is a
 * materially different trust boundary than the rest of this file; see
 * docs/RUNTIME_ADMISSION.md for its own guarantee/non-guarantee statement
 * and threat model.
 *
 * Returns an unstarted server; the caller decides when to `.listen()`.
 */
const KNOWN_ROUTES = new Set([
  "/health",
  "/metrics",
  "/v1/verify/manifest",
  "/v1/verify/receipt",
  "/v1/verify/rotation",
  "/v1/admit",
]);

// Bucket into a fixed, known label set rather than the raw URL — an
// unbounded label space would let a caller inflate the metrics object's
// memory by requesting many distinct nonsense paths.
function routeLabel(url: string): string {
  return KNOWN_ROUTES.has(url) ? url : "other";
}

function logRequest(method: string, route: string, status: number, durationMs: number): void {
  // Structured, metadata-only access log: method/route/status/duration.
  // Never logs headers, bodies, keys, or signatures.
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      method,
      route,
      status,
      durationMs,
    }),
  );
}

/**
 * Hosted verifier. By default (no `admission` option) this is exactly the
 * Phase 5 behavior: wraps verifySignedManifest/verifyReceiptDetailed/
 * verifyKeyRotation behind HTTP, never loads a signing key, never touches a
 * trust store, never issues receipts or makes admission decisions. See
 * docs/HOSTED_VERIFIER.md for that guarantee/non-guarantee statement, which
 * is unchanged for a plain `besa serve` invocation.
 *
 * When `admission` is supplied, this ALSO mounts POST /v1/admit — an
 * opt-in, additive Phase 7 route that loads a signing key and a trust
 * store to issue signed, non-consuming AdmissionAttestations. This is a
 * materially different trust boundary than the rest of this file; see
 * docs/RUNTIME_ADMISSION.md for its own guarantee/non-guarantee statement
 * and threat model.
 *
 * When `rateLimit` is supplied, requests are throttled per client remote
 * address before the body is even read (cheapest possible rejection).
 * Always-on regardless of options: a structured access log line per
 * request, and a GET /metrics route with aggregate request counters — both
 * read-only, non-invasive additions (Phase 8 hardening scope; no auth, no
 * multi-tenant layer, no cloud deployment machinery).
 *
 * Returns an unstarted server; the caller decides when to `.listen()`.
 */
export function createHostedVerifierServer(
  options: HostedVerifierOptions = {},
): http.Server {
  const admission = options.admission;
  const rateLimiter = options.rateLimit
    ? new RateLimiter(options.rateLimit.limit, options.rateLimit.windowMs)
    : undefined;
  const metrics = new Metrics();

  const server = http.createServer((req, res) => {
    const method = req.method ?? "GET";
    const url = req.url ?? "/";
    const route = routeLabel(url);
    const startedAt = process.hrtime.bigint();

    const respond = (status: number, body: unknown, extraHeaders?: http.OutgoingHttpHeaders) => {
      const json = JSON.stringify(body);
      const headers: http.OutgoingHttpHeaders = {
        "Content-Type": "application/json",
        ...extraHeaders,
      };
      res.writeHead(status, headers);
      res.end(json);
      metrics.record(route, status);
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      logRequest(method, route, status, Math.round(durationMs));
    };

    if (rateLimiter) {
      const clientKey = req.socket.remoteAddress ?? "unknown";
      const result = rateLimiter.attempt(clientKey);
      if (!result.allowed) {
        metrics.recordRateLimited();
        respond(429, { error: "rate limit exceeded" }, {
          "Retry-After": String(Math.ceil(result.retryAfterMs / 1000)),
        });
        return;
      }
    }

    readBody(req)
      .then((rawBody) => {
        const { status, body } = routeVerifierRequest(method, url, rawBody, admission, metrics);
        // A 413 responds before the client has finished sending its (still
        // in-flight, oversized) body — force the socket closed afterward
        // rather than returning it to the keep-alive pool in an unknown
        // drain state.
        respond(status, body, status === 413 ? { Connection: "close" } : undefined);
      })
      .catch((error: unknown) => {
        console.error(
          JSON.stringify({
            ts: new Date().toISOString(),
            method,
            route,
            error: error instanceof Error ? error.message : "unknown error",
          }),
        );
        respond(400, { error: "invalid request body" });
      });
  });

  // Node emits 'clientError' for malformed low-level HTTP (bad request
  // line, invalid headers) before a request object even exists. Left
  // unhandled this can surface as an unhandled 'error' event and crash the
  // process; responding here keeps one bad connection from taking down a
  // long-running server holding admission signing key material.
  server.on("clientError", (error, socket) => {
    console.error(
      JSON.stringify({
        ts: new Date().toISOString(),
        event: "clientError",
        error: error.message,
      }),
    );
    if (socket.writable) {
      socket.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
    }
  });

  return server;
}
