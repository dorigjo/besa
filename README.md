<p align="center">
  <img src="site/logo.svg" alt="" width="44" height="40" />
</p>

<h1 align="center">Besa</h1>

<p align="center"><strong>Agent Action Receipts</strong></p>

<p align="center">
  The signed-receipt layer for AI-agent tool calls.
</p>

<p align="center">
  <a href="https://github.com/dorigjo/besa/actions/workflows/ci.yml"><img src="https://github.com/dorigjo/besa/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.npmjs.com/package/@dorigjo/besa"><img src="https://img.shields.io/npm/v/@dorigjo/besa" alt="npm" /></a>
  <img src="https://img.shields.io/badge/public_release-coming_soon-C1121F?labelColor=003049" alt="Public release coming soon" />
</p>

---

## Early Access

Besa 0.1.0-beta.2 is available as a GitHub Release tarball while npm publishing is pending.

Install:

```bash
npm install https://github.com/dorigjo/besa/releases/download/v0.1.0-beta.2/dorigjo-besa-0.1.0-beta.2.tgz
```

See [EARLY_ACCESS.md](EARLY_ACCESS.md) for integrity hash, quickstart, and known limitations.

---

AI agents are calling real systems: CRMs, payment APIs, deployment pipelines,
databases. Every call is a liability.

The question your compliance team will ask: **which tools was this agent
authorized to call, and where is the signed record?**

Besa answers that by creating cryptographically signed **Agent Action Receipts**
for every admission decision — before the tool executes.

> **Beta.** `0.1.0-beta.2` is a local developer beta for security review and
> early integration. Public release coming soon.
> Enterprise inquiry: [open an issue](https://github.com/dorigjo/besa/issues).

---

## Why this matters

The regulatory window is closing:

| Framework | Requirement |
|---|---|
| EU AI Act (2025–2026) | Logging and documentation of high-risk AI systems |
| NIST AI RMF | Govern → Map → Measure → Manage AI risk |
| SOC 2 Type II | Evidence of access controls for AI-integrated systems |
| ISO 42001 | AI management system standard |
| SEC / FINRA guidance | Explainability and audit trails for AI in financial services |

Besa creates the artifact that answers the audit question: **which tool was
called, by which agent, under which signed authorization, at what time, and was
it allowed or denied?**

---

## Trust flow

```
manifest.yaml
  → besa sign              # sign the declared tools, capabilities, risks, scopes
  → manifest.signed.json   # Ed25519-signed artifact
  → besa trust add         # pin the publisher's public key
  → besa verify            # verify signature against pinned trust anchor
  → besa admit <tool>      # dry-run: check policy, capabilities, budget
  → besa receipt <tool>    # enforce budget, issue signed receipt
  → besa verify-receipt    # verify the receipt chain end-to-end
```

Every step produces a durable, verifiable artifact. The signed manifest, public
key ID, manifest hash, admission decision, request hash, and signed receipt are
all tamper-evident. Changing any field causes verification to fail.

---

## What works today

- YAML + JSON manifest loading with strict schema validation
- Ed25519 key generation; AES-256-GCM encrypted key storage with scrypt KDF
- Whole-envelope Ed25519 signatures covering manifest, hash, key, algorithm, and timestamp
- Explicit public-key trust anchors (active / retired / revoked)
- Signed key-rotation proofs preserving forward trust continuity
- Allow / deny decisions with machine-readable reason codes
- Destructive high-risk tool blocking by default policy
- ASCII-validated tool names (prevents Unicode homograph attacks)
- Manifest-scoped call budgets with cross-process atomic file locking
- Optional per-agent grant scoping
- Signed, tamper-evident Agent Action Receipts
- Receipt trust-chain verification
- TypeScript SDK exports

---

## Install

```bash
npm install @dorigjo/besa@beta
```

Or build from source:

```bash
git clone https://github.com/dorigjo/besa
cd besa
npm ci
npm run build
```

Set the key passphrase before any signing operation:

```bash
export BESA_KEY_PASSPHRASE="your-passphrase-at-least-16-bytes"
```

---

## Quickstart

```bash
# Generate or load the local signing key
node dist/index.js keys

# Validate the manifest (dry-run, no signing)
node dist/index.js load examples/manifest.yaml

# Sign the manifest
node dist/index.js sign examples/manifest.yaml

# Verify the signature
node dist/index.js verify examples/manifest.signed.json

# Admission dry-run (does not consume budget)
node dist/index.js admit examples/manifest.signed.json crm.lookup   # → allow
node dist/index.js admit examples/manifest.signed.json crm.delete   # → deny RISK_BLOCKED

# Issue a signed receipt (consumes budget)
node dist/index.js receipt crm.lookup examples/manifest.signed.json \
  --request examples/request.json

# Verify the receipt chain
node dist/index.js verify-receipt .besa/receipts/<id>.json \
  examples/manifest.signed.json
```

### PowerShell

```powershell
$env:BESA_KEY_PASSPHRASE = "your-passphrase-at-least-16-bytes"
node .\dist\index.js keys
node .\dist\index.js sign .\examples\manifest.yaml
node .\dist\index.js verify .\examples\manifest.signed.json
node .\dist\index.js admit .\examples\manifest.signed.json crm.lookup
node .\dist\index.js receipt crm.lookup .\examples\manifest.signed.json `
  --request .\examples\request.json

$receipt = Get-ChildItem .\.besa\receipts\*.json |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
node .\dist\index.js verify-receipt $receipt.FullName .\examples\manifest.signed.json
```

### Consumer trust (separate system)

```bash
# Pin the publisher's public key
node dist/index.js trust add examples/manifest.signed.json \
  --trust consumer-trust.json

# Verify against a pinned trust anchor (fails without it)
node dist/index.js verify examples/manifest.signed.json \
  --trust consumer-trust.json
```

### Key rotation

```bash
node dist/index.js keys rotate

node dist/index.js trust apply .besa/rotations/<rotation>.json \
  --trust consumer-trust.json

node dist/index.js sign examples/manifest.yaml   # re-sign under the new key
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

## Receipt artifact

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

## Reason codes

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
- SHA-256 manifest hashing and full 64-bit SHA-256 public key fingerprints
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

- Local key storage only; no hosted key management or HSM integration
- File-based meter and trust state; intended for single-host use
- No distributed replay protection across machines or environments
- No external trusted timestamp authority
- No hosted verifier, receipt retention, or SIEM export
- No production identity or multi-user authorization
- No formal compliance certification (SOC 2, ISO 27001, EU AI Act)

---

## License

[MIT](LICENSE)
