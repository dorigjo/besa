/**
 * Agent Gateway Skeleton
 *
 * This is a minimal, honest example of the runtime gateway pattern.
 * It is NOT production-ready. It demonstrates the correct call sequence:
 *   agent request → Besa policy check → allow/deny → signed receipt
 *
 * What this skeleton does NOT include (and should not):
 *   - Authentication of the agent caller
 *   - Persistent receipt storage
 *   - Key rotation or trust store management
 *   - Rate limiting or DDoS protection
 *   - Any actual tool forwarding (placeholder only)
 *
 * These belong in the Runtime Gateway surface, which is on the roadmap.
 */

import http from 'node:http'
import { admit, createReceipt, hashRequest, verifyTrustedSignedManifest } from '@dorigjo/besa'
import type { SignedManifest, TrustStore } from '@dorigjo/besa'

// Load trust store at startup — in production this would be persisted and rotated
// For this skeleton, start with an empty trust store (no keys trusted)
const trustStore: TrustStore = { keys: [] }

interface GatewayRequest {
  signedManifest: SignedManifest
  toolName: string
  requestPayload: unknown
}

interface GatewayResponse {
  decision: 'allow' | 'deny'
  reasonCode: string
  receipt?: unknown
  error?: string
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

  const { signedManifest, toolName, requestPayload } = body as GatewayRequest

  if (!signedManifest || !toolName) {
    sendJson(res, 400, { error: 'Missing signedManifest or toolName' })
    return
  }

  // Step 1: Verify the manifest signature against the trust store
  const verified = verifyTrustedSignedManifest(signedManifest, trustStore)
  if (!verified.valid) {
    const response: GatewayResponse = {
      decision: 'deny',
      reasonCode: verified.reasonCode ?? 'E_KEY_UNTRUSTED',
    }
    sendJson(res, 403, response)
    return
  }

  // Step 2: Check admission policy (risk level, budget, scopes)
  const currentCallCount = 0 // placeholder — real implementation needs persistent counter
  const decision = admit(signedManifest.manifest, toolName, currentCallCount)

  // Step 3: Create a signed receipt regardless of outcome
  const requestHash = hashRequest({ toolName, payload: requestPayload ?? null })
  const receipt = createReceipt(
    signedManifest,
    toolName,
    decision.decision,
    decision.reason,
    requestHash,
  )

  if (decision.decision === 'deny') {
    const response: GatewayResponse = {
      decision: 'deny',
      reasonCode: decision.reason,
      receipt,
    }
    sendJson(res, 403, response)
    return
  }

  // Step 4: Only here — the tool call is allowed
  // In a real gateway, this is where you would forward the request to the actual tool.
  // This skeleton returns the admission decision and receipt without forwarding.
  const response: GatewayResponse = {
    decision: 'allow',
    reasonCode: 'ALLOWED',
    receipt,
  }
  sendJson(res, 200, response)
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
