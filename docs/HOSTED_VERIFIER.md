# Hosted Verifier

Architecture, endpoint reference, and threat model for `besa serve`. No
compliance claim, no marketing language — every statement below is either
demonstrated by a test in `src/tests/server.test.ts` or explicitly named as
not implemented.

## What this is

A stateless HTTP wrapper around the exact same verification functions the
CLI already calls: `verifySignedManifest`, `verifyReceiptDetailed`, and
`verifyKeyRotation` (`src/signing.ts`/`src/trust.ts`). It answers exactly
one question per request — "is this artifact's signature cryptographically
valid" — the same question `besa verify` (without `--trust`) answers
locally. Implemented in `src/server/hosted-verifier.ts`, started via `besa
serve [--port <n>] [--host <addr>]` (default port `8787`, default bind
address `127.0.0.1` — loopback-only; pass `--host 0.0.0.0` explicitly to
accept connections from other machines, which prints a visible warning on
startup).

This closes a real, previously-documented gap: a third party without the
Besa CLI installed had no way to independently check a Besa-signed
artifact's validity (`docs/CI_GATE.md`, `docs/THREAT_MODEL.md`,
`CHANGELOG.md` all named this). It does not close the broader "Hosted Trust
Plane" gap described in `docs/V1_ROADMAP.md`'s Phase 2 — see "What this is
not," below.

## What this is not

`docs/V1_ROADMAP.md`'s Phase 2 diagram names four hosted nodes:
Authorization API, Policy Engine, Trust Ledger, and Verifier, sitting below
the Besa SDK. This implements **only the Verifier node.** Specifically, a
plain `besa serve` (no `--trust` flag):

- **Never loads a trust store.** It cannot answer "do I trust this key," only
  "is this signature valid for the key embedded in the artifact." Use `besa
  verify --trust <file>` locally for trust-aware verification.
- **Never runs admission policy.** No `admit()` call, no risk/budget/scope
  checks. Use `besa admit` locally.
- **Never issues receipts.** No signing key is ever loaded by the server
  process — it holds no private key material at all, so it structurally
  cannot sign anything, deny or allow.
- **Never touches `.besa/`** — no meter, no receipts directory, no key file.

Passing `--trust <file>` opts into a materially different, additive
component — see "Opt-in extension: runtime admission," below, and its own
document, `docs/RUNTIME_ADMISSION.md`. Without that flag, every guarantee
above holds exactly as stated.

This is a deliberate scope cut, not an oversight: the user's own
"Infrastructure Development" authorization named "Hosted Verifier"
specifically, and `CLAUDE.md`'s "smallest credible implementation" +
"no fake enterprise functionality" rules stay in force for everything this
authorization didn't explicitly name. The Authorization API, Policy Engine,
and Trust Ledger nodes each need their own separate scope decision and plan
before being built.

## Endpoint reference

All request/response bodies are JSON. Request bodies are capped at
`MAX_ARTIFACT_BYTES` (1 MiB, `src/io.ts:18`) — the same ceiling every local
artifact read already enforces.

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/health` | — | `200 { status: "ok", version: <string> }` |
| `GET` | `/metrics` | — | `200` with aggregate request counters (see "Monitoring," below) |
| `POST` | `/v1/verify/manifest` | a `SignedManifest` | `200` with the `VerifyResult` (`{valid, reasonCode, detail}`) — `valid` may be `true` or `false`, both are `200` |
| `POST` | `/v1/verify/receipt` | `{ receipt: <Receipt>, publicKey: <string> }` | `200` with the `VerifyResult` |
| `POST` | `/v1/verify/rotation` | a `KeyRotation` | `200` with the `VerifyResult` |

Error responses: `400` malformed JSON or a malformed `/v1/verify/receipt`
envelope (missing `receipt`/`publicKey`); `404` unknown path; `405` known
path, wrong method; `413` body exceeds `MAX_ARTIFACT_BYTES`; `429` rate
limit exceeded (only when `--rate-limit` is enabled, see "Rate limiting,"
below).

## Monitoring

`GET /metrics` returns a JSON snapshot of in-memory, per-process counters:
`startedAt`, `uptimeSeconds`, `requestsTotal`, `requestsByRoute` (bucketed
into the fixed set of known routes plus `"other"` — never the raw request
URL, to bound memory against a caller hitting many distinct nonsense
paths), `requestsByStatus`, and `rateLimitedTotal`. Reset to zero on
process restart; not persisted. This is a read-only, always-on addition —
no authentication, matching the rest of this server's public-endpoint
model.

Every request also emits one structured JSON access-log line to stdout
(`{ts, method, route, status, durationMs}`) — metadata only, never
headers, bodies, keys, or signatures.

## Rate limiting

Opt-in via `besa serve --rate-limit <n>`: a fixed-window limiter (default
window 60s) keyed by the client's remote address, rejecting with `429` and
a `Retry-After` header once a client exceeds `<n>` requests in the current
window. Rejected requests are counted in `/metrics`'s `rateLimitedTotal`
and never reach body parsing or verification logic — the cheapest possible
rejection. Disabled by default; without `--rate-limit`, behavior is
unchanged from Phase 5. The limiter tracks at most 10,000 distinct client
keys at a time (oldest evicted first) to bound memory under a
many-source-address attack.

A `200` response does not mean "the artifact is valid" — it means "the
verifier successfully computed an answer." The answer itself is in the
response body's `valid` field, exactly mirroring how `verifySignedManifest`
already behaves as a function: it returns a structured result, it does not
throw for an invalid-but-well-formed artifact.

## Guarantees

- Byte-identical verification logic to the CLI — no second crypto pipeline.
  `routeVerifierRequest()` calls the same `src/signing.ts`/`src/trust.ts`
  functions directly; nothing is reimplemented.
- The server process never loads a signing key or trust store. A
  compromised or DoS'd verifier process cannot leak signing material or
  forge a trust/admission decision, because it holds neither.
- Concurrent requests are independently correct — proven in
  `src/tests/server.test.ts` by firing 20 simultaneous requests with mixed
  valid/invalid payloads against one server instance and asserting each
  response matches its own request.
- Oversized bodies are rejected without unbounded buffering — the request
  handler stops accumulating past `MAX_ARTIFACT_BYTES` and responds `413`.

## Limitations

| Feature | Status | Notes |
|---|---|---|
| Authentication | Not implemented | Deliberate — this is a public verification function, like checking a certificate's signature. Anyone can call it. |
| Rate limiting | Opt-in (`--rate-limit <n>`) | Off by default. See "Rate limiting," above. Operator must still choose a limit appropriate to their deployment. |
| TLS | Not implemented | Run behind a reverse proxy that terminates TLS. |
| Trust-store awareness | Not implemented | See "What this is not," above. |
| Admission / receipts | Not implemented | See "What this is not," above. |
| Persistent state | None — fully stateless | No filesystem access of any kind after startup (package version is read once at process start). Rate-limit/metrics counters are in-memory only, reset on restart. |

## Threat model

Per-attacker format matching `docs/PROVIDER_THREAT_MODEL.md`.

### Attacker: unauthenticated caller

- **Assets:** the verification function's compute/network capacity.
- **Trust boundary:** anyone who can reach the listening port.
- **Attack:** send verify requests, at any volume.
- **Detection:** none built in — no request logging beyond Node's own
  process I/O.
- **Mitigation:** verifying a signature is not a privileged operation; the
  artifact and its claimed public key are both in the request itself, so
  no authentication is required by design. An operator can additionally
  opt into `--rate-limit <n>` (Phase 8) to cap requests per client address;
  off by default.
- **Residual risk:** an operator who exposes this publicly without
  `--rate-limit` (or their own reverse-proxy-level limiting) accepts
  unmetered request volume. Named, not silently assumed away.

### Attacker: oversized-body denial of service

- **Assets:** server memory and CPU.
- **Trust boundary:** anyone who can reach the listening port.
- **Attack:** send a request body far exceeding `MAX_ARTIFACT_BYTES`.
- **Detection:** the request handler counts bytes as they arrive and stops
  accumulating past the ceiling.
- **Mitigation:** `413` response, bounded memory (`src/tests/server.test.ts`,
  "oversized request body is rejected with 413, not buffered unbounded").
- **Residual risk:** a large volume of *many* oversized requests still
  costs the server per-connection overhead and bandwidth — the byte cap
  bounds memory per request, not aggregate request volume. `--rate-limit`
  (Phase 8, opt-in, off by default) is the actual mitigation for that.

### Attacker: malformed input

- **Assets:** none directly — a correctness/availability concern, not
  confidentiality.
- **Trust boundary:** anyone who can reach the listening port.
- **Attack:** send non-JSON bodies, wrong-shaped JSON, or artifacts with
  unexpected field types.
- **Detection:** `verifySignedManifest`/`verifyReceiptDetailed`/
  `verifyKeyRotation` already fail closed on malformed input (they are the
  same functions the CLI trusts against untrusted file contents); the HTTP
  layer additionally returns `400` for JSON that doesn't even parse.
- **Mitigation:** covered by the existing fail-closed contract of the
  wrapped functions — no new validation logic was written for this layer.
- **Residual risk:** none identified beyond what already applies to local
  CLI verification of untrusted files.

### Attacker: information leakage via error responses

- **Assets:** internal implementation details.
- **Trust boundary:** anyone who can reach the listening port.
- **Attack:** probe error responses for stack traces or internal paths.
- **Detection:** manual review of every response body in
  `routeVerifierRequest()` — all error bodies are fixed, short strings
  (`"invalid JSON body"`, `"not found"`, etc.), never `error.message` or a
  stack trace.
- **Mitigation:** the request handler's `.catch()` also returns a fixed
  string, not the caught error's message.
- **Residual risk:** none identified.

## Opt-in extension: runtime admission

`besa serve --trust <file>` additionally mounts `POST /v1/admit` — a
materially different trust boundary (it loads a signing key) covered by its
own document: `docs/RUNTIME_ADMISSION.md`. Without `--trust`, everything in
this document remains exactly as stated: no key, no trust store, no
admission, no receipts.

## Why not exported via the SDK yet

`createHostedVerifierServer()` is reachable only via `besa serve`, not
through `sdk.ts`'s public export surface (`sdk-surface.test.ts`'s frozen
list is unchanged by this phase). Same judgment already applied to
`KeyProvider`/`LocalKeyProvider` in Phase 3
(`KEY_PROVIDER_ARCHITECTURE.md`, "SDK surface decision"): freeze a public
export only once a real second consumer or embedding use case proves the
shape is right, not on the strength of the first implementation.
