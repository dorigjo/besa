<p align="center">
  <img src="site/logo.svg" alt="" width="44" height="40" />
</p>

<h1 align="center">Besa</h1>

<p align="center"><strong>Agent Action Receipts</strong></p>

<p align="center">Besa is the receipt layer for AI-agent actions.</p>

---

AI agents call real tools — CRMs, payment APIs, deployment pipelines, databases. Every call is a real action. Most teams cannot prove what was admitted, what was denied, or what was executed.

Besa signs the admission decision and issues a tamper-evident receipt for every tool call.

> **Alpha.** `0.1.0-alpha.2` — not production-ready. APIs and file formats may change without notice.

## The flow

```text
manifest.yaml
  ↓  besa sign         →  signed-manifest.json
  ↓  besa verify
  ↓  besa admit crm.lookup   →  ✓ admitted
  ↓  besa receipt crm.lookup →  receipt.json
```

The receipt is the artifact. Everything before it makes the receipt trustworthy.

## Why

When an AI agent calls a tool, three questions carry operational weight:

1. Was the tool manifest signed by someone you trust?
2. Was this call admitted or denied, and on what grounds?
3. Is there a tamper-evident record proving the decision?

Today, the answer is usually: no.

## What Besa does

- Signs MCP-style tool manifests with Ed25519
- Verifies manifest integrity before runtime
- Admits or denies tool calls against declared capability, risk level, and scope
- Issues a signed, tamper-evident receipt for every admission decision
- Tracks per-tool call counts against declared budget limits

## Install

```bash
npm install @dorigjo/besa@alpha
```

Clone and build locally:

```bash
git clone https://github.com/dorigjo/besa
cd besa
npm install
npm run build
```

## Quickstart

```bash
node dist/index.js keys
node dist/index.js sign examples/manifest.yaml
node dist/index.js verify examples/manifest.signed.json
node dist/index.js admit examples/manifest.signed.json crm.lookup
node dist/index.js admit examples/manifest.signed.json crm.delete
node dist/index.js receipt crm.lookup examples/manifest.signed.json
```

`crm.lookup` returns `ALLOWED`. `crm.delete` returns `RISK_BLOCKED`.

Run the full smoke test:

```bash
npm run smoke
```

## What a receipt proves

```json
{
  "receipt_id": "rcpt_01J2K5N8P3QR4S6T7U8V9W0X",
  "manifest_hash": "sha256:4a8f2c1d9e3b7f6a0d4c8e2b5f9a1d3e",
  "tool_name": "crm.lookup",
  "decision": "allow",
  "reason_code": "CAPABILITY_DECLARED_SCOPE_MATCHED",
  "timestamp": "2026-06-17T14:32:07.443Z",
  "request_hash": "sha256:9f1e3c5a7d2b4f8e0c6a2d4b6f8e0c2a",
  "public_key_id": "besa-key-2026-a1b2c3d4",
  "signature": "MEYCIQDkv2mN8rT..."
}
```

The receipt encodes which manifest was signed, whether the call was admitted, the cryptographic request fingerprint, and an Ed25519 signature over the canonical receipt body. Altering any field after signing causes verification to fail.

## Commands

- `besa keys` — generate a local Ed25519 key pair
- `besa sign <manifest>` — sign a manifest YAML or JSON file
- `besa verify <signed>` — verify a signed manifest
- `besa admit <signed> <tool>` — admit or deny a tool call
- `besa receipt <tool> <signed>` — issue a signed receipt

Reason codes: `ALLOWED` · `TOOL_NOT_FOUND` · `RISK_BLOCKED` · `BUDGET_EXCEEDED` · `TOOL_NOT_GRANTED`

## Security

`.besa/` contains local trust artifacts including the Ed25519 private key. Do not commit it.

```
.besa/
examples/manifest.signed.json
```

The demo key is for local development only. Rotate before real use.

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## What Besa is not

- A hosted SaaS or dashboard
- Production key management
- A compliance certification
- A replacement for identity, authorization, audit storage, or security monitoring

## Status

Alpha. `0.1.0-alpha.2`. Local-first. No hosted backend. Not production-stable.

Working: manifest signing, admission with reason codes, signed receipts, mini ActionMeter, agent-scoped grants, TypeScript SDK exports, full CLI.

Not yet: hosted key management, remote verifier, key rotation, replay protection.

## License

[MIT](LICENSE)
