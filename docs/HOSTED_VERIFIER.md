# Self-hosted Hosted Verifier

`besa serve` is a self-hosted HTTP distribution of Besa verification and,
when explicitly configured, admission. Besa v1.1 does not operate a public
service. The operator owns deployment, TLS, ingress, keys, retention, replay
state, monitoring, and incident response.

## Modes

| Invocation | Private key loaded | Token required | Available capability |
|---|---:|---:|---|
| `besa serve` | No | No | Public signature/schema verification for v1.0 artifacts and Action Envelope validation. |
| `besa serve --action-trust trust.json` | No | No | Above plus trust-aware capability, delegation, and evidence verification. |
| `besa serve --trust trust.json` | Yes | Yes | Above plus legacy `POST /v1/admit`, which returns signed non-consuming `AdmissionAttestation`s. |
| `besa serve --trust trust.json --action-policy policy.yaml` | Yes | Yes | Above plus signed Action Capability issuance at `POST /v1/actions/admit`. |

`--action-trust` is the least-privilege verification deployment: it loads only
public keys. `--trust` deliberately enables a signing process, requires
`BESA_ADMISSION_TOKEN`, and requires an existing encrypted key at
`.besa/key.json`. The server never creates a signing identity automatically.

## Run locally

```bash
npm install @dorigjo/besa
npx besa serve --port 8787
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/ready
```

The CLI binds `127.0.0.1` by default. Passing `--host 0.0.0.0` is an explicit
decision to accept non-loopback connections. Put a publicly reachable instance
behind a TLS-terminating reverse proxy and restrict inbound network access.

## HTTP API

All `POST` routes require `Content-Type: application/json` (optional UTF-8
charset) and strictly valid UTF-8 JSON bytes. Success at transport level is
`200` even when a supplied artifact is invalid; inspect the JSON `valid`,
`authorized`, `decision`, or `reasonCode` field. Malformed UTF-8, JSON, or
request envelopes receive `400`.

| Method | Path | Mode | Body | Result |
|---|---|---|---|---|
| GET | `/health` | all | none | `{status:"ok",version}` |
| GET | `/ready` | all | none | `200` ready or `503` during shutdown |
| GET | `/metrics` | all | none | In-memory aggregate route/status counters |
| POST | `/v1/verify/manifest` | all | `SignedManifest` | Signature result |
| POST | `/v1/verify/receipt` | all | `{receipt,publicKey}` | Receipt signature result |
| POST | `/v1/verify/rotation` | all | `KeyRotation` | Rotation signature result |
| POST | `/v1/verify/action` | all | `ActionEnvelopeV1` | Strict schema/expiry result |
| POST | `/v1/verify/capability` | action trust | `{capability,action}` | Trust-aware capability result |
| POST | `/v1/verify/delegation` | action trust | `{chain,action}` | Trust-aware, narrowed-chain result |
| POST | `/v1/verify/evidence` | action trust | `{evidence,action,capability,result,receiptHash?}` | Linked-evidence result |
| POST | `/v1/admit` | `--trust` | `{signedManifest,toolName}` | Signed legacy `AdmissionAttestation` |
| POST | `/v1/actions/admit` | `--trust --action-policy` | `{action,delegationChain?}` | Signed allow/deny `ActionCapabilityV1` |

Action-capability verification does not issue an authorization. It verifies an
already-issued artifact against the configured public trust store.

### Action admission request

```json
{
  "action": {
    "artifactVersion": 1,
    "principalId": "principal:acme",
    "agentId": "agent:payments",
    "authority": "customer:acme",
    "tool": "payments.transfer",
    "operation": "transfer",
    "resource": "payment:merchant-123",
    "requestHash": "<sha-256 of canonical tool arguments>",
    "scopes": ["payments:transfer"],
    "constraints": {"amountEur": 100, "merchantId": "merchant-123"},
    "expiresAt": "2030-01-02T00:00:00.000Z",
    "nonce": "unique-base64url-nonce",
    "riskClass": "high"
  }
}
```

```bash
curl --fail-with-body http://127.0.0.1:8787/v1/actions/admit \
  --header "Authorization: Bearer $BESA_ADMISSION_TOKEN" \
  --header "Content-Type: application/json" \
  --data @action-request.json
```

The response is a signed `ActionCapabilityV1`. `decision: "deny"` is a valid,
signed answer that must never be passed to an executor. A configured policy
requiring delegation denies an absent, invalid, widened, expired, or
non-authorizing chain.

## Operational defaults

- Body limit: 1 MiB, including early `Content-Length` rejection and streamed
  bounded buffering.
- Request timeout: 10 seconds; header and keep-alive timeout: 5 seconds.
- Header size: 16 KiB; header count: 100; requests per socket: 1,000.
- Rate limit: 120 requests per minute per remote address by default. Health and
  readiness probes are exempt. Set `--rate-limit <n>` to choose another
  positive limit. Limiting runs before bearer-token validation, so failed
  authentication attempts consume the same client budget. A reverse proxy
  changes the visible remote address; enforce an additional proxy-level limit
  for public ingress.
- POSTs with unsupported JSON media types get `415`; unsupported `Expect:
  100-continue` gets `417`; query strings are rejected; oversized bodies get
  `413`; protected routes without a valid bearer token get `401` before body
  parsing.
- Responses set `Cache-Control: no-store`, CSP `default-src 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and
  `X-Frame-Options: DENY`.
- Access logs are structured JSON metadata (`ts`, method, route, status,
  duration). They do not include bodies, bearer tokens, keys, or signatures.
- `/metrics` is in-process, resets on restart, and is not authenticated. Limit
  access to it at the network layer when route/status activity is sensitive.

The server makes no outbound HTTP requests, so it has no URL-fetch/SSRF
surface. It is still subject to inbound bandwidth, CPU, and connection-exhaustion
attacks; request limits are not a substitute for ingress controls.

## Container deployment

The repository includes a two-stage, non-root Docker image. It installs from
`package-lock.json` with lifecycle scripts disabled and ships compiled output
plus production dependencies only.

```bash
docker build --pull --tag besa:1.1.0 .
docker run --rm --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --publish 127.0.0.1:8787:8787 \
  besa:1.1.0
```

The image defaults to `serve --host 0.0.0.0` so the published container port
is reachable. Restrict the host publication or use a private network; do not
publish it directly to the internet without TLS, rate limits, and network
policy.

### Keyless full-chain verification

```bash
docker run --rm --read-only \
  --publish 127.0.0.1:8787:8787 \
  --mount type=bind,src="$PWD/verifier-trust.json",dst=/run/besa/trust.json,readonly \
  besa:1.1.0 serve --host 0.0.0.0 --action-trust /run/besa/trust.json
```

### Signed action admission

Provision the encrypted key and trust file outside the image. Store the
passphrase and bearer token in the orchestrator's secret store. Besa does not
load `.env` files automatically; `examples/hosted-verifier.env.example` is a
reference, not a secrets mechanism.

```bash
docker run --rm --read-only \
  --publish 127.0.0.1:8787:8787 \
  --mount type=bind,src="$PWD/.besa",dst=/app/.besa,readonly \
  --mount type=bind,src="$PWD/verifier-trust.json",dst=/run/besa/trust.json,readonly \
  --mount type=bind,src="$PWD/examples/action-policy.yaml",dst=/run/besa/policy.yaml,readonly \
  --env BESA_KEY_PASSPHRASE \
  --env BESA_ADMISSION_TOKEN \
  --env BESA_ADMISSION_ISSUER_ID=besa:hosted-verifier \
  besa:1.1.0 serve --host 0.0.0.0 --trust /run/besa/trust.json \
    --action-policy /run/besa/policy.yaml
```

The server process holds the decrypted signing key in memory for its lifetime.
Run admission in an isolated workload, rotate compromised keys, and do not
co-locate the signing key with an untrusted executor where separation of duty
matters.

## What this service proves and does not prove

It can verify artifact signatures and links, and it can issue a signed decision
for a supplied exact action under its configured policy. It cannot authenticate
the agent for you, prove an executor performed a real-world side effect, settle
a payment, enforce a globally unique nonce without an external replay store, or
turn a local policy file into organizational governance. See `ARCHITECTURE.md`,
`docs/RUNTIME_ADMISSION.md`, and `docs/THREAT_MODEL.md` for the corresponding
trust model and limits.
