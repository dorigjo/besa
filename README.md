<p align="center">
  <img src="site/logo.svg" alt="" width="44" height="40" />
</p>

<h1 align="center">Besa</h1>

<p align="center"><strong>The audit layer for AI-agent actions.</strong></p>

<p align="center">
  Know what your AI agents were authorized to do — and prove it.
</p>

<p align="center">
  <a href="https://github.com/dorigjo/besa/actions/workflows/ci.yml"><img src="https://github.com/dorigjo/besa/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.npmjs.com/package/@dorigjo/besa"><img src="https://img.shields.io/npm/v/@dorigjo/besa" alt="npm" /></a>
</p>

---

## The problem

AI agents are calling real systems — CRMs, payment APIs, deployment pipelines, databases. Every call is a real action with real consequences.

When something goes wrong — or when compliance asks — your team needs to answer:

- What was this agent actually authorized to do?
- Was this action inside declared policy?
- Was it blocked — or admitted — and why?
- Can you show an auditor the evidence?

Most teams today cannot answer these questions. There is no record. There is no proof.

---

## What Besa does

Besa gives every AI-agent action a signed, tamper-evident audit record.

**Before a tool call:** Besa checks whether the tool is declared, policy-approved, and within budget. Blocked by default if the tool is undeclared or marked `destructive`/`high` risk.

**When a call is admitted:** Besa issues a cryptographic receipt — a tamper-evident record of the decision, the manifest hash, the request fingerprint, and the signing key.

**When you need to prove it:** the receipt chain is independently verifiable. Any tampering is detectable.

> **Beta.** `0.1.0-beta.5` is a public developer beta. Designed for development and early integration. See [Beta limitations](#beta-limitations).

---

## The evidence flow

```
manifest.yaml
  → besa sign              # declare and sign tool capabilities, risks, scopes
  → manifest.signed.json   # tamper-evident capability declaration
  → besa trust add         # pin the publisher's public key
  → besa verify            # verify signature against trust anchor
  → besa admit <tool>      # policy gate: allow or deny (dry-run)
  → besa receipt <tool>    # enforce budget, issue signed audit receipt
  → besa verify-receipt    # verify the complete evidence chain
```

Every step produces a durable, independently verifiable artifact. Changing any field in any artifact causes verification to fail closed.

---

## What you get

### Signed capability declarations
Every tool's declared capabilities, risk level, allowed scopes, and budget limits are captured in a manifest and signed with Ed25519. Any change after signing is detectable.

### Policy enforcement at the gate
Besa checks every tool call before it happens. Destructive high-risk tools are blocked by default. Budget limits cap runaway usage. Per-agent grant scoping restricts access to specific tools.

### Tamper-evident audit receipts
Every admission decision — allow or deny — produces a signed receipt recording the tool name, manifest hash, request fingerprint, decision, and timestamp. Not a log. Proof.

### Verifiable evidence chain
Sign → verify → admit → receipt → verify-receipt. Each step is independently verifiable. The signed manifest, admission decision, and receipt form a complete, tamper-evident chain.

---

## Install

```bash
npm install @dorigjo/besa
```

Pin the beta channel explicitly:

```bash
npm install @dorigjo/besa@beta
```

Set the key passphrase before any signing operation:

```bash
export BESA_KEY_PASSPHRASE="your-passphrase-at-least-16-bytes"
```

### Build from source

```bash
git clone https://github.com/dorigjo/besa
cd besa
npm ci
npm run build
```

---

## Quickstart

```bash
# Show available commands
npx besa --help

# Generate or load the local signing key
npx besa keys

# Validate the manifest (dry-run, no signing)
npx besa load examples/manifest.yaml

# Sign the manifest
npx besa sign examples/manifest.yaml

# Verify the signature
npx besa verify examples/manifest.signed.json

# Admission dry-run (does not consume budget)
npx besa admit examples/manifest.signed.json crm.lookup   # → allow
npx besa admit examples/manifest.signed.json crm.delete   # → deny RISK_BLOCKED

# Issue a signed receipt (consumes budget)
npx besa receipt crm.lookup examples/manifest.signed.json \
  --request examples/request.json

# Verify the receipt chain
npx besa verify-receipt .besa/receipts/<id>.json \
  examples/manifest.signed.json
```

### PowerShell

```powershell
$env:BESA_KEY_PASSPHRASE = "your-passphrase-at-least-16-bytes"
npx besa keys
npx besa sign examples/manifest.yaml
npx besa verify examples/manifest.signed.json
npx besa admit examples/manifest.signed.json crm.lookup
npx besa receipt crm.lookup examples/manifest.signed.json `
  --request examples/request.json

$receipt = Get-ChildItem .\.besa\receipts\*.json |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
npx besa verify-receipt $receipt.FullName examples/manifest.signed.json
```

### Consumer trust (separate system)

```bash
# Pin the publisher's public key
npx besa trust add examples/manifest.signed.json \
  --trust consumer-trust.json

# Verify against a pinned trust anchor (fails without it)
npx besa verify examples/manifest.signed.json \
  --trust consumer-trust.json
```

### Key rotation

```bash
npx besa keys rotate

npx besa trust apply .besa/rotations/<rotation>.json \
  --trust consumer-trust.json

npx besa sign examples/manifest.yaml   # re-sign under the new key
```

The previous key becomes `retired`: artifacts signed before rotation remain
verifiable, but new admissions under that key are denied. `trust revoke`
invalidates a key for all artifacts, current and historical.

---

## Commands

| Command | Description |
|---|---|
| `besa keys` | Generate or display the local signing key |
| `besa keys rotate` | Rotate to a new key, archive the previous |
| `besa trust add <manifest>` | Pin the manifest's public key as a trust anchor |
| `besa trust apply <rotation>` | Apply a signed rotation proof |
| `besa trust revoke <key-id>` | Revoke a trust anchor |
| `besa trust list` | List all trust anchors and their status |
| `besa load <manifest>` | Validate a manifest without signing |
| `besa sign <manifest>` | Sign a manifest |
| `besa verify <manifest>` | Verify a signed manifest against the trust store |
| `besa admit <manifest> <tool>` | Dry-run: check policy + budget |
| `besa receipt <tool> <manifest>` | Enforce budget and issue a signed receipt |
| `besa verify-receipt <receipt> <manifest>` | Verify the receipt trust chain |

All commands accept `--trust <trust.json>` to use a consumer-side trust store.
`admit` and `receipt` also accept `--agent <id> --grants <grants.yaml>`.

---

## The audit receipt

```json
{
  "receiptId": "rcpt_2d7942c7-8f70-4984-9c3f-24876acfd860",
  "manifestHash": "ea7e9ca22d199f40281cdf9e5d6145440c6c7d6bfbe94157c4b1da5527054410",
  "toolName": "crm.lookup",
  "decision": "allow",
  "reasonCode": "ALLOWED",
  "timestamp": "2026-06-19T10:00:00.000Z",
  "requestHash": "b27b80d1227c167a6fca199778645daa77d20a8087782fc48802d11d6281c920",
  "publicKeyId": "f68668614543c4896cf8cee418492f1a4df1f1acdba8850f94728b8a94cf90fe",
  "algorithm": "ed25519",
  "signature": "<base64-ed25519-signature>"
}
```

`publicKeyId` is the full SHA-256 fingerprint of the Ed25519 public key DER bytes.
Changing any field causes `verify-receipt` to fail closed.

---

## Admission reason codes

| Code | Meaning |
|---|---|
| `ALLOWED` | Tool call admitted |
| `TOOL_NOT_FOUND` | Tool not declared in the signed manifest |
| `RISK_BLOCKED` | Destructive high-risk tool blocked by policy |
| `BUDGET_EXCEEDED` | Call count reached the manifest budget limit |
| `TOOL_NOT_GRANTED` | Agent not granted access to this tool |
| `AGENT_NOT_FOUND` | Agent ID not listed in the grant set |
| `E_KEY_UNTRUSTED` | Signing key not in the trust store |
| `E_KEY_RETIRED` | Key retired; new admissions under it are denied |
| `E_KEY_REVOKED` | Key revoked; all operations denied |

---

## SDK

```typescript
import {
  admit,
  addTrustAnchor,
  applyKeyRotation,
  canonicalize,
  checkTrustedKey,
  createKeyRotation,
  createReceipt,
  generateKeyPair,
  hashRequest,
  loadManifest,
  signManifest,
  validateManifest,
  validateReceipt,
  verifyReceiptDetailed,
  verifySignedManifest,
  verifyTrustedSignedManifest,
} from "@dorigjo/besa";
```

---

## Security model

Besa provides **tamper-evidence**, not secrecy.

A signed manifest proves that the declared tool capabilities, scopes, risks, and
metadata have not changed since signing. A signed receipt creates a
tamper-evident record that a specific admission decision was made at a specific
time under a specific key.

**Cryptography:**

- Ed25519 signatures (256-bit security) on the complete artifact envelope
- AES-256-GCM key encryption at rest with scrypt KDF (N=32768, r=8, p=1)
- SHA-256 manifest hashing and full 256-bit (64-hex-character) SHA-256 public key fingerprints
- Domain-separated signature messages (`besa:<domain>:v1\0<canonical-json>`)
- Timing-safe public key comparison via `crypto.timingSafeEqual`

**Fail-closed behavior:**

- Verification fails on any signature, hash, or key mismatch
- Admission fails closed on invalid policy, manifest, or call count
- Trust store rejects symlinks, unknown fields, and duplicate key IDs
- Trust store paths must end in `.json`
- Tool names are restricted to ASCII printable characters

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Release gates

```bash
npm ci
npm run build
npm test          # 56 tests
npm run smoke     # end-to-end trust flow
npm run test:package
npm pack --dry-run
```

---

## Beta limitations

Besa `0.1.0-beta.5` is a **public developer beta**. The core evidence artifacts — signed manifests, signed receipts, and the verification chain — are production-quality. The surrounding infrastructure is not yet.

Current limitations:
- Local key storage only; no hosted key management or HSM integration
- File-based meter and trust state; intended for single-host use
- No distributed replay protection across machines or environments
- No external trusted timestamp authority
- No hosted verifier, receipt retention, or SIEM export
- No production identity or multi-user authorization
- No formal compliance certification (SOC 2, ISO 27001, EU AI Act)

Use Besa today to build and validate the audit layer for your AI-agent tooling. The evidence artifacts are designed to remain forward-compatible as the infrastructure matures.

---

## License

[MIT](LICENSE)
