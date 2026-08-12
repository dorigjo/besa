/**
 * Agent Gateway Skeleton
 *
 * A minimal, honest example of the runtime gateway pattern. It is NOT
 * production-ready. It demonstrates the correct call sequence:
 *
 *   agent request → verify trusted manifest → admit → allow/deny
 *
 * On allow, the tool call would be forwarded to the upstream system.
 * On deny, the upstream call is blocked and never reaches the tool.
 *
 * This skeleton performs verification and admission only. It does NOT issue
 * signed receipts: receipt issuance requires an explicitly configured signing
 * key (see createReceipt(input, keypair) in @dorigjo/besa), and correct local
 * key custody is out of scope for a transport-only skeleton. The gateway
 * returns the structured admission decision and never claims to sign a receipt.
 *
 * What this skeleton does NOT include (and should not):
 *   - Authentication of the agent caller
 *   - Signed receipt issuance (needs a configured signing key)
 *   - Persistent, cross-restart call counters (the meter here is in-memory)
 *   - Key rotation or trust store management
 *   - Rate limiting or DDoS protection
 *   - Any actual tool forwarding (placeholder only)
 *
 * These belong in the Runtime Gateway surface, which is on the roadmap.
 */

import http from 'node:http'
import { admit, emptyTrustStore, verifyTrustedSignedManifest } from '@dorigjo/besa'
import type { AdmissionDecision, SignedManifest, TrustStore } from '@dorigjo/besa'

// Load the trust store at startup. In production this would be persisted and
// rotated; this skeleton starts empty, so no key is trusted until one is added
// (e.g. via `besa trust add`). With an empty store, every manifest fails closed.
const trustStore: TrustStore = emptyTrustStore()

// In-memory ActionMeter. Demonstrates budget enforcement within a single
// process; it resets on restart. Persistent, cross-process metering is the
// Runtime Gateway surface (see admitAndConsume in @dorigjo/besa).
const callCounts = new Map<string, number>()

interface GatewayRequest {
  signedManifest: SignedManifest
  toolName: string
  requestPayload: unknown
}

interface GatewayResponse {
  decision: 'allow' | 'deny'
  reasonCode: string
  toolName: string
  detail: string
  // 'forwarded (placeholder)' only when allowed. The skeleton does not actually
  // call the tool; a real gateway forwards the upstream request here.
  upstream: 'forwarded (placeholder)' | 'blocked'
}

function parseBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let body = ''
    req.on('data', (chunk: Buffer) => { body += chunk.toString() })
    req.on('end', () => {
      try { resolve(JSON.parse(body)) } catch { reject(new Error('Invalid JSON')) }
    })
    req.on('error', reject)
  })
}

function sendJson(res: http.ServerResponse, status: number, data: unknown): void {
  const json = JSON.stringify(data, null, 2)
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(json)
}

function denyResponse(decision: AdmissionDecision): GatewayResponse {
  return {
    decision: 'deny',
    reasonCode: decision.reasonCode,
    toolName: decision.toolName,
    detail: decision.detail,
    upstream: 'blocked',
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/gate') {
    sendJson(res, 404, { error: 'Not found. POST /gate' })
    return
  }

  let body: unknown
  try {
    body = await parseBody(req)
  } catch {
    sendJson(res, 400, { error: 'Invalid request body' })
    return
  }

  const { signedManifest, toolName } = body as GatewayRequest

  if (!signedManifest || !toolName) {
    sendJson(res, 400, { error: 'Missing signedManifest or toolName' })
    return
  }

  // Step 1: Verify the manifest signature against the trust store (fail-closed).
  // purpose 'admit' rejects retired keys for new admissions.
  const verified = verifyTrustedSignedManifest(signedManifest, trustStore, 'admit')
  if (!verified.valid) {
    sendJson(res, 403, {
      decision: 'deny',
      reasonCode: verified.reasonCode,
      toolName,
      detail: verified.detail,
      upstream: 'blocked',
    } satisfies GatewayResponse)
    return
  }

  // Step 2: Check admission policy (risk level, budget, scopes) using the
  // in-memory call count for this manifest + tool.
  const meterKey = `${signedManifest.manifestHash}:${toolName}`
  const currentCallCount = callCounts.get(meterKey) ?? 0
  const decision = admit(signedManifest.manifest, toolName, currentCallCount)

  // Step 3: On deny, block the upstream call. The tool is never reached.
  if (decision.decision === 'deny') {
    sendJson(res, 403, denyResponse(decision))
    return
  }

  // Step 4: Only here — the tool call is allowed. Consume one unit of budget,
  // then forward to the upstream system. This skeleton returns the decision
  // without forwarding; a real gateway would call the tool at this point.
  callCounts.set(meterKey, currentCallCount + 1)

  sendJson(res, 200, {
    decision: 'allow',
    reasonCode: decision.reasonCode,
    toolName: decision.toolName,
    detail: decision.detail,
    upstream: 'forwarded (placeholder)',
  } satisfies GatewayResponse)
})

const PORT = process.env.PORT ?? 3742

server.listen(PORT, () => {
  console.log(`Besa agent gateway skeleton listening on http://localhost:${PORT}`)
  console.log('POST /gate with { signedManifest, toolName, requestPayload }')
  console.log('')
  console.log('WARNING: This is a development skeleton.')
  console.log('Trust store is empty — add keys via besa trust add before use.')
  console.log('See docs/AGENT_GATEWAY.md for usage and limitations.')
})

export { server }
