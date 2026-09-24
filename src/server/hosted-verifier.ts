import http from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";
import {
  validateSignedManifest,
  verifySignedManifest,
  verifyReceiptDetailed,
} from "../signing.js";
import {
  validateTrustStore,
  verifyKeyRotation,
  verifyTrustedSignedManifest,
} from "../trust.js";
import { admit, getCount, loadMeter, meterKey } from "../admit.js";
import { createAdmissionAttestation } from "../attestation.js";
import { MAX_ARTIFACT_BYTES } from "../io.js";
import { checkActionEnvelope, validateActionEnvelope } from "../action.js";
import { admitAction, validateActionPolicy, type ActionPolicyV1 } from "../action-policy.js";
import {
  createActionCapability,
  verifyActionCapability,
} from "../action-capability.js";
import { verifyActionEvidence } from "../action-evidence.js";
import { verifyActionDelegation, type DelegationV1 } from "../delegation.js";
import { RateLimiter } from "./rate-limiter.js";
import { Metrics } from "./metrics.js";
import type { VerifyResult } from "../signing.js";
import type { TrustStore } from "../types.js";
import { validateKeyPair, type KeyPair } from "../crypto.js";

export interface HostedVerifierAdmissionOptions {
  trustStore: TrustStore;
  meterPath: string;
  keyPair: KeyPair;
  apiToken?: string;
}

export interface HostedVerifierActionAdmissionOptions {
  trustStore: TrustStore;
  policy: ActionPolicyV1;
  keyPair: KeyPair;
  issuerId: string;
  apiToken: string;
  delegationTrustStore?: TrustStore;
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
  actionAdmission?: HostedVerifierActionAdmissionOptions;
  /** Public verification trust; does not grant this process signing authority. */
  actionTrustStore?: TrustStore;
  /** Optional distinct trust store for delegation roots. */
  delegationTrustStore?: TrustStore;
  rateLimit?: HostedVerifierRateLimitOptions | false;
  maxBodyBytes?: number;
  requestTimeoutMs?: number;
  headersTimeoutMs?: number;
  keepAliveTimeoutMs?: number;
  maxHeaderBytes?: number;
  maxHeadersCount?: number;
  readiness?: () => boolean;
  clock?: () => Date;
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
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function readBody(
  req: http.IncomingMessage,
  maxBodyBytes: number,
): Promise<Buffer | "too-large"> {
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
      if (total > maxBodyBytes) {
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
    return { ok: true, value: JSON.parse(UTF8_DECODER.decode(raw)) as unknown };
  } catch {
    return { ok: false };
  }
}

function errorResult(status: number, reasonCode: string, error: string): RouteResult {
  return { status, body: { error, reasonCode } };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function currentDate(clock: (() => Date) | undefined): Date {
  const now = clock?.() ?? new Date();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new Error("hosted verifier clock returned an invalid date");
  }
  return new Date(now);
}

function isValidApiToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 32 &&
    value.length <= 4_096 &&
    !/[\u0000-\u0020\u007f]/.test(value)
  );
}

function isValidServiceId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    value === value.trim() &&
    value === value.normalize("NFC") &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function bearerTokenMatches(header: string | undefined, expected: string): boolean {
  const match = /^Bearer ([^\s]+)$/i.exec(header ?? "");
  if (!match) return false;
  const actualDigest = createHash("sha256").update(match[1]!, "utf8").digest();
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(actualDigest, expectedDigest);
}

function requestPath(url: string): { path: string; hasQuery: boolean } | undefined {
  try {
    const parsed = new URL(url, "http://localhost");
    return { path: parsed.pathname, hasQuery: parsed.search.length > 0 };
  } catch {
    return undefined;
  }
}

function privilegedToken(
  path: string,
  options: HostedVerifierOptions,
): string | undefined {
  if (path === "/v1/admit") return options.admission?.apiToken;
  if (path === "/v1/actions/admit") return options.actionAdmission?.apiToken;
  return undefined;
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

function handleActionAdmissionRequest(
  parsedBody: unknown,
  admission: HostedVerifierActionAdmissionOptions,
  now: Date,
): RouteResult {
  if (!isObject(parsedBody) || !("action" in parsedBody)) {
    return errorResult(
      400,
      "SCHEMA_REQUEST_INVALID",
      "body must be { action: <ActionEnvelopeV1>, delegationChain?: <DelegationV1[]> }",
    );
  }

  const actionValidation = validateActionEnvelope(parsedBody.action);
  const actionCheck = checkActionEnvelope(parsedBody.action, now);
  if (!actionValidation.ok || !actionValidation.action || !actionCheck.valid) {
    return errorResult(
      400,
      actionCheck.reasonCode,
      actionValidation.errors.join("; ") || actionCheck.detail,
    );
  }
  const action = actionValidation.action;
  const policyDecision = admitAction(action, admission.policy, now);
  let decision = policyDecision.decision;
  let reasonCode = policyDecision.reasonCode;
  let delegationChainHash: string | null = null;

  const suppliedChain = parsedBody.delegationChain;
  if (suppliedChain !== undefined && !Array.isArray(suppliedChain)) {
    return errorResult(
      400,
      "SCHEMA_DELEGATION_INVALID",
      "delegationChain must be an array when supplied",
    );
  }
  const chain = suppliedChain as DelegationV1[] | undefined;
  if (policyDecision.delegationRequired && (!chain || chain.length === 0)) {
    decision = "deny";
    reasonCode = "DELEGATION_REQUIRED";
  } else if (chain && chain.length > 0) {
    const delegation = verifyActionDelegation(
      chain,
      action,
      admission.delegationTrustStore ?? admission.trustStore,
      now,
    );
    if (!delegation.valid || !delegation.chainHash) {
      decision = "deny";
      reasonCode = delegation.reasonCode;
    } else {
      delegationChainHash = delegation.chainHash;
    }
  }

  try {
    return {
      status: 200,
      body: createActionCapability(
        {
          action,
          decision,
          reasonCode,
          policyId: policyDecision.policyId,
          delegationChainHash,
          issuerId: admission.issuerId,
          issuedAt: now.toISOString(),
        },
        admission.keyPair,
      ),
    };
  } catch {
    return errorResult(
      500,
      "CAPABILITY_ISSUANCE_FAILED",
      "action capability issuance failed",
    );
  }
}

function actionTrustStore(options: HostedVerifierOptions): TrustStore | undefined {
  return options.actionTrustStore ?? options.actionAdmission?.trustStore;
}

function delegationTrustStore(options: HostedVerifierOptions): TrustStore | undefined {
  return (
    options.delegationTrustStore ??
    options.actionAdmission?.delegationTrustStore ??
    actionTrustStore(options)
  );
}

function actionTrustRequired(): RouteResult {
  return errorResult(
    501,
    "TRUST_CONFIGURATION_REQUIRED",
    "this verification route requires a server-controlled action trust store",
  );
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
  options: HostedVerifierOptions = {},
  metrics?: Metrics,
): RouteResult {
  const target = requestPath(url);
  if (!target) {
    return errorResult(400, "HTTP_TARGET_INVALID", "invalid request target");
  }
  if (target.hasQuery) {
    return errorResult(400, "HTTP_QUERY_UNSUPPORTED", "query parameters are not supported");
  }
  const path = target.path;

  if (rawBody === "too-large") {
    return errorResult(
      413,
      "HTTP_BODY_TOO_LARGE",
      `request body exceeds the ${String(options.maxBodyBytes ?? MAX_ARTIFACT_BYTES)} byte limit`,
    );
  }

  if (path === "/health") {
    if (method !== "GET") {
      return { status: 405, body: { error: "method not allowed" } };
    }
    return { status: 200, body: { status: "ok", version: VERSION } };
  }

  if (path === "/ready") {
    if (method !== "GET") {
      return { status: 405, body: { error: "method not allowed" } };
    }
    let ready = true;
    try {
      ready = options.readiness?.() ?? true;
    } catch {
      ready = false;
    }
    return {
      status: ready ? 200 : 503,
      body: { status: ready ? "ready" : "not-ready", version: VERSION },
    };
  }

  if (path === "/metrics") {
    if (method !== "GET") {
      return { status: 405, body: { error: "method not allowed" } };
    }
    return { status: 200, body: metrics?.snapshot() ?? new Metrics().snapshot() };
  }

  if (path === "/v1/admit") {
    if (method !== "POST") {
      return { status: 405, body: { error: "method not allowed" } };
    }

    if (!options.admission) {
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

    return handleAdmissionRequest(parsed.value, options.admission);
  }

  if (path === "/v1/actions/admit") {
    if (method !== "POST") {
      return { status: 405, body: { error: "method not allowed" } };
    }
    if (!options.actionAdmission) {
      return errorResult(
        501,
        "ACTION_ADMISSION_DISABLED",
        "action admission is not enabled on this server",
      );
    }
    const parsed = parseJsonBody(rawBody);
    if (!parsed.ok) return errorResult(400, "HTTP_JSON_INVALID", "invalid JSON body");
    return handleActionAdmissionRequest(
      parsed.value,
      options.actionAdmission,
      currentDate(options.clock),
    );
  }

  const verifyRoutes = new Set([
    "/v1/verify/manifest",
    "/v1/verify/receipt",
    "/v1/verify/rotation",
    "/v1/verify/action",
    "/v1/verify/capability",
    "/v1/verify/delegation",
    "/v1/verify/evidence",
  ]);

  if (!verifyRoutes.has(path)) {
    return { status: 404, body: { error: "not found" } };
  }

  if (method !== "POST") {
    return { status: 405, body: { error: "method not allowed" } };
  }

  const parsed = parseJsonBody(rawBody);
  if (!parsed.ok) {
    return { status: 400, body: { error: "invalid JSON body" } };
  }

  if (path === "/v1/verify/manifest") {
    return verifyResultResponse(verifySignedManifest(parsed.value));
  }

  if (path === "/v1/verify/rotation") {
    return verifyResultResponse(verifyKeyRotation(parsed.value));
  }

  if (path === "/v1/verify/action") {
    const result = checkActionEnvelope(parsed.value, currentDate(options.clock));
    const { action: _action, ...response } = result;
    return { status: 200, body: response };
  }

  if (path === "/v1/verify/capability") {
    const trustStore = actionTrustStore(options);
    if (!trustStore) return actionTrustRequired();
    if (!isObject(parsed.value) || !("capability" in parsed.value) || !("action" in parsed.value)) {
      return errorResult(
        400,
        "SCHEMA_REQUEST_INVALID",
        "body must be { capability: <ActionCapabilityV1>, action: <ActionEnvelopeV1> }",
      );
    }
    return verifyResultResponse(
      verifyActionCapability(
        parsed.value.capability,
        parsed.value.action,
        trustStore,
        currentDate(options.clock),
      ),
    );
  }

  if (path === "/v1/verify/delegation") {
    const trustStore = delegationTrustStore(options);
    if (!trustStore) return actionTrustRequired();
    if (
      !isObject(parsed.value) ||
      !Array.isArray(parsed.value.chain) ||
      !("action" in parsed.value)
    ) {
      return errorResult(
        400,
        "SCHEMA_REQUEST_INVALID",
        "body must be { chain: <DelegationV1[]>, action: <ActionEnvelopeV1> }",
      );
    }
    return verifyResultResponse(
      verifyActionDelegation(
        parsed.value.chain,
        parsed.value.action as never,
        trustStore,
        currentDate(options.clock),
      ),
    );
  }

  if (path === "/v1/verify/evidence") {
    const trustStore = actionTrustStore(options);
    if (!trustStore) return actionTrustRequired();
    if (
      !isObject(parsed.value) ||
      !("evidence" in parsed.value) ||
      !("action" in parsed.value) ||
      !("capability" in parsed.value) ||
      !("result" in parsed.value)
    ) {
      return errorResult(
        400,
        "SCHEMA_REQUEST_INVALID",
        "body must include evidence, action, capability, and result",
      );
    }
    return verifyResultResponse(
      verifyActionEvidence(
        parsed.value.evidence,
        {
          action: parsed.value.action,
          capability: parsed.value.capability,
          result: parsed.value.result,
          trustStore,
          ...(parsed.value.receiptHash === undefined
            ? {}
            : { receiptHash: parsed.value.receiptHash as string | null }),
        },
        currentDate(options.clock),
      ),
    );
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
  "/ready",
  "/metrics",
  "/v1/verify/manifest",
  "/v1/verify/receipt",
  "/v1/verify/rotation",
  "/v1/verify/action",
  "/v1/verify/capability",
  "/v1/verify/delegation",
  "/v1/verify/evidence",
  "/v1/admit",
  "/v1/actions/admit",
]);

const BODY_ROUTES = new Set(
  [...KNOWN_ROUTES].filter((route) => route.startsWith("/v1/")),
);

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

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
    throw new TypeError(`${name} must be an integer between ${String(minimum)} and ${String(maximum)}`);
  }
  return selected;
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
  if (options.admission) {
    if (!isValidApiToken(options.admission.apiToken)) {
      throw new TypeError("admission.apiToken must be a secret of 32-4096 non-whitespace characters");
    }
    if (!validateKeyPair(options.admission.keyPair)) {
      throw new TypeError("admission.keyPair must be a valid Ed25519 key pair");
    }
  }
  if (options.actionAdmission) {
    if (!isValidApiToken(options.actionAdmission.apiToken)) {
      throw new TypeError("actionAdmission.apiToken must be a secret of 32-4096 non-whitespace characters");
    }
    if (!validateKeyPair(options.actionAdmission.keyPair)) {
      throw new TypeError("actionAdmission.keyPair must be a valid Ed25519 key pair");
    }
    if (!isValidServiceId(options.actionAdmission.issuerId)) {
      throw new TypeError("actionAdmission.issuerId must be bounded NFC text without controls");
    }
    const policyValidation = validateActionPolicy(options.actionAdmission.policy);
    if (!policyValidation.ok) {
      throw new TypeError(`invalid action admission policy: ${policyValidation.errors.join("; ")}`);
    }
  }
  for (const [name, store] of [
    ["admission.trustStore", options.admission?.trustStore],
    ["actionAdmission.trustStore", options.actionAdmission?.trustStore],
    [
      "actionAdmission.delegationTrustStore",
      options.actionAdmission?.delegationTrustStore,
    ],
    ["actionTrustStore", options.actionTrustStore],
    ["delegationTrustStore", options.delegationTrustStore],
  ] as const) {
    if (store) {
      const validation = validateTrustStore(store);
      if (!validation.ok) {
        throw new TypeError(`invalid ${name}: ${validation.errors.join("; ")}`);
      }
    }
  }

  const maxBodyBytes = boundedInteger(
    options.maxBodyBytes,
    MAX_ARTIFACT_BYTES,
    1_024,
    MAX_ARTIFACT_BYTES,
    "maxBodyBytes",
  );
  const requestTimeout = boundedInteger(
    options.requestTimeoutMs,
    10_000,
    1_000,
    120_000,
    "requestTimeoutMs",
  );
  const headersTimeout = boundedInteger(
    options.headersTimeoutMs,
    5_000,
    1_000,
    requestTimeout,
    "headersTimeoutMs",
  );
  const keepAliveTimeout = boundedInteger(
    options.keepAliveTimeoutMs,
    5_000,
    1_000,
    60_000,
    "keepAliveTimeoutMs",
  );
  const maxHeaderSize = boundedInteger(
    options.maxHeaderBytes,
    16_384,
    4_096,
    65_536,
    "maxHeaderBytes",
  );
  const maxHeadersCount = boundedInteger(
    options.maxHeadersCount,
    100,
    16,
    1_000,
    "maxHeadersCount",
  );
  const rateLimit = options.rateLimit === false
    ? undefined
    : (options.rateLimit ?? { limit: 120, windowMs: 60_000 });
  const rateLimiter = rateLimit
    ? new RateLimiter(rateLimit.limit, rateLimit.windowMs)
    : undefined;
  const metrics = new Metrics();

  const server = http.createServer({
    requestTimeout,
    headersTimeout,
    keepAliveTimeout,
    maxHeaderSize,
    connectionsCheckingInterval: 1_000,
    rejectNonStandardBodyWrites: true,
  }, (req, res) => {
    const method = req.method ?? "GET";
    const url = req.url ?? "/";
    const target = requestPath(url);
    const path = target?.path ?? "other";
    const route = routeLabel(path);
    const startedAt = process.hrtime.bigint();

    const respond = (status: number, body: unknown, extraHeaders?: http.OutgoingHttpHeaders) => {
      const json = JSON.stringify(body);
      const headers: http.OutgoingHttpHeaders = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(json, "utf8"),
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        ...extraHeaders,
      };
      res.writeHead(status, headers);
      res.end(json);
      metrics.record(route, status);
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      logRequest(method, route, status, Math.round(durationMs));
    };

    if (!target) {
      respond(400, { error: "invalid request target", reasonCode: "HTTP_TARGET_INVALID" });
      return;
    }

    if (rateLimiter && path !== "/health" && path !== "/ready") {
      const clientKey = req.socket.remoteAddress ?? "unknown";
      const result = rateLimiter.attempt(clientKey);
      if (!result.allowed) {
        req.resume();
        metrics.recordRateLimited();
        respond(429, { error: "rate limit exceeded" }, {
          "Retry-After": String(Math.ceil(result.retryAfterMs / 1000)),
          Connection: "close",
        });
        return;
      }
    }

    const token = privilegedToken(path, options);
    if (token && !bearerTokenMatches(req.headers.authorization, token)) {
      req.resume();
      respond(
        401,
        { error: "valid bearer token required", reasonCode: "AUTH_TOKEN_INVALID" },
        { "WWW-Authenticate": "Bearer" },
      );
      return;
    }

    if (method === "POST" && BODY_ROUTES.has(path)) {
      const contentType = req.headers["content-type"] ?? "";
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)) {
        req.resume();
        respond(415, {
          error: "Content-Type must be application/json",
          reasonCode: "HTTP_MEDIA_TYPE_UNSUPPORTED",
        });
        return;
      }
    }

    const contentLength = req.headers["content-length"];
    if (
      typeof contentLength === "string" &&
      /^\d+$/.test(contentLength) &&
      Number(contentLength) > maxBodyBytes
    ) {
      req.resume();
      respond(
        413,
        {
          error: `request body exceeds the ${String(maxBodyBytes)} byte limit`,
          reasonCode: "HTTP_BODY_TOO_LARGE",
        },
      );
      return;
    }

    readBody(req, maxBodyBytes)
      .then((rawBody) => {
        const { status, body } = routeVerifierRequest(
          method,
          url,
          rawBody,
          { ...options, maxBodyBytes },
          metrics,
        );
        // readBody stops buffering at the limit and keeps draining the request.
        // Let Node manage the connection so the caller receives the structured
        // 413 instead of racing a forced socket close.
        respond(status, body);
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

  server.maxHeadersCount = maxHeadersCount;
  server.maxRequestsPerSocket = 1_000;

  server.on("checkContinue", (_req, res) => {
    const body = JSON.stringify({
      error: "Expect: 100-continue is not supported",
      reasonCode: "HTTP_EXPECTATION_UNSUPPORTED",
    });
    res.writeHead(417, {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(body, "utf8"),
      "Cache-Control": "no-store",
      Connection: "close",
    });
    res.end(body);
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
        errorCode: (error as NodeJS.ErrnoException).code ?? "HTTP_CLIENT_ERROR",
      }),
    );
    if (socket.writable) {
      socket.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
    }
  });

  return server;
}
