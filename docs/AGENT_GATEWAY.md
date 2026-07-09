# Agent Gateway Skeleton

The `examples/agent-gateway/server.ts` file is a minimal, honest skeleton showing how Besa fits into the path of an AI agent making tool calls.

It is a development prototype. It is not production-ready infrastructure.

---

## What it demonstrates

```
agent request
    ↓
POST /gate { signedManifest, toolName, requestPayload }
    ↓
verifyTrustedSignedManifest(manifest, trustStore)
    ↓ (reject if signature invalid or key untrusted)
admit(manifest, toolName, currentCallCount)
    ↓ (check risk level, budget, scopes)
createReceipt(...)
    ↓
200 { decision: "allow", receipt } or 403 { decision: "deny", receipt }
```

Every request produces a signed receipt — whether allowed or denied. This is intentional. The receipt is the audit evidence.

---

## Running the skeleton

```bash
npm run build

# Set up a key and sign the example manifest first
node dist/index.js sign examples/manifest.yaml
export BESA_KEY_PASSPHRASE=your-passphrase

# Start the gateway
npx tsx examples/agent-gateway/server.ts
# → Besa agent gateway skeleton listening on http://localhost:3742

# In another terminal, send a test request
curl -X POST http://localhost:3742/gate \
  -H 'Content-Type: application/json' \
  -d '{
    "signedManifest": '"$(cat examples/manifest.signed.json)"',
    "toolName": "crm.lookup",
    "requestPayload": { "customerId": "123" }
  }'
```

Expected response:

```json
{
  "decision": "allow",
  "reasonCode": "ALLOWED",
  "receipt": {
    "id": "...",
    "toolName": "crm.lookup",
    "decision": "allow",
    "reasonCode": "ALLOWED",
    "signature": "...",
    "timestamp": "..."
  }
}
```

---

## Trust store setup

The skeleton starts with an empty trust store. No manifests will pass verification until you add a trusted key:

```bash
# Add the signing key from the example manifest to the trust store
node dist/index.js trust add examples/manifest.signed.json --trust examples/agent-gateway/trust.json
```

Then load `examples/agent-gateway/trust.json` in the server instead of the empty `{ keys: [] }`.

---

## What the skeleton intentionally omits

| Feature | Status | Notes |
|---|---|---|
| Agent authentication | Not implemented | Who is calling the gateway? |
| Persistent call counters | Placeholder (always 0) | Budget enforcement requires persistence |
| Trust store management | Manual | Hardcoded in server startup |
| Actual tool forwarding | Placeholder | Returns decision without calling the tool |
| Receipt persistence | Not implemented | Receipts returned but not stored |
| Rate limiting | Not implemented | Needed before any public exposure |
| TLS | Not implemented | Use a reverse proxy in front |

These features are the Runtime Gateway surface — on the roadmap, not in 0.1.0.

---

## How it fits the roadmap

```
Today (0.1.0):
  CLI → sign → verify → admit → receipt (local, file-based)

This skeleton adds:
  HTTP endpoint → same Besa core → JSON response with receipt

Runtime Gateway (roadmap):
  Agent SDK → gateway → persistent counters → hosted verifier → receipt retention
```

The skeleton proves the call sequence is correct and the SDK is composable. The infrastructure that surrounds it in production is a separate engineering effort.

---

## Limitations (0.1.0)

- Trust store is in-memory only — restart resets it
- Call counter is hardcoded to 0 — budget enforcement does not work correctly
- No authentication — any caller can POST to /gate
- No TLS — do not expose to a network without a terminating proxy
- Receipts are returned but not persisted — no audit trail across restarts
