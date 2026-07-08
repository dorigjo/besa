<p align="center">
  <img src="site/logo.svg" alt="" width="44" height="40" />
</p>

<h1 align="center">Besa</h1>

<p align="center"><strong>The AI agent execution control plane.</strong></p>

<p align="center">
  Before an AI agent touches a tool, API, database, or deployment pipeline — Besa checks whether the action is declared, policy-approved, within budget, and attributable.
</p>

<p align="center">
  <a href="https://github.com/dorigjo/besa/actions/workflows/ci.yml"><img src="https://github.com/dorigjo/besa/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.npmjs.com/package/@dorigjo/besa"><img src="https://img.shields.io/npm/v/@dorigjo/besa" alt="npm" /></a>
</p>

---

## The problem

AI agents are calling real systems — CRMs, payment APIs, deployment pipelines, databases, code repositories. Every call is a real action with real consequences and no natural chokepoint.

When something goes wrong — or when compliance asks — your team needs to answer:

- What was this agent actually declared to do?
- Was this action inside policy before it happened?
- Was it admitted or blocked — and why?
- Can you show an auditor a tamper-evident proof?

Most teams today cannot answer these questions. There is no gate. There is no record. There is no proof.

---

## What Besa does

Besa is the execution control plane for AI-agent tool calls.

**Gate before execution:** Besa checks whether the tool is declared in a signed manifest, policy-approved, within budget, and scoped to the requesting agent. Undeclared tools are denied. Destructive high-risk tools are blocked by default. Budget overruns are stopped.

**Sign the decision:** Every admission — allow or deny — produces a signed cryptographic receipt recording the tool name, manifest hash, request fingerprint, reason code, and signing key. Not a log. Signed proof.

**Verify the chain:** The signed manifest, admission decision, and receipt form a complete, tamper-evident evidence chain. Any field change causes verification to fail closed.

> **Beta.** `0.1.0-beta.5` is a public developer beta. Designed for development, CI integration, and early runtime control. See [Beta limitations](#beta-limitations).

---

## The control flow

```
manifest.yaml
  → besa sign              # declare and sign tool capabilities, risks, scopes
  → manifest.signed.json   # tamper-evident capability declaration
  → besa trust add         # pin the publisher's public key
  → besa verify            # verify signature against trust anchor
  → besa admit <tool>      # policy gate: allow or deny (fail-closed)
  → besa receipt <tool>    # enforce budget, issue signed execution receipt
  → besa verify-receipt    # verify the complete evidence chain
```

Every step produces a durable, independently verifiable artifact. Changing any field in any artifact causes verification to fail closed.

---

## What you get

### Signed capability declarations
Every tool's declared capabilities, risk level, allowed scopes, and budget limits are captured in a manifest and signed with Ed25519. Any change after signing is detectable.

### Policy-gated tool calls
Besa checks every tool call before it happens. Destructive high-risk tools are blocked by default. Budget limits cap runaway usage. Per-agent grant scoping restricts access to specific tools. Undeclared tools are denied.

### Signed allow/deny decisions
Every admission decision — allow or deny — produces a signed receipt recording the tool name, manifest hash, request fingerprint, decision, and timestamp. Not a log. Proof.

### Verifiable evidence chain
Sign → verify → admit → receipt → verify-receipt. Each step is independently verifiable. The signed manifest, admission decision, and receipt form a complete, tamper-evident chain.

### CI/CD gate
Run Besa in your CI pipeline to verify that manifests are signed, that declared tools pass policy, and that undeclared or high-risk tools fail the build. See [docs/CI_GATE.md](docs/CI_GATE.md).

---

## Install

```bash
npm install @dorigjo/besa
```

Pin the exact version explicitly:

```bash
npm install @dorigjo/besa@0.1.0
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

# Admission gate (fail-closed dry-run)
npx besa admit examples/manifest.signed.json crm.lookup   # → allow
npx besa admit examples/manifest.signed.json crm.delete   # → deny RISK_BLOCKED

# Issue a signed execution receipt (consumes budget)
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

## CI/CD gate

Besa can run as a verification gate in GitHub Actions or any CI pipeline. A failed manifest signature or a denied tool call fails the build.

```yaml
- name: Verify manifest
  run: |
    npx besa verify examples/manifest.signed.json
    npx besa admit examples/manifest.signed.json crm.lookup
```

See [docs/CI_GATE.md](docs/CI_GATE.md) for a complete example workflow.

---

## Runtime gateway pattern

Besa's SDK can sit on the call path of an agent runtime. Before the agent calls a tool, the gateway calls `admit()` or `admitAndConsume()` from `@dorigjo/besa`. If the decision is deny, the tool call never reaches the upstream system.

```typescript
import { admit, verifyTrustedSignedManifest } from "@dorigjo/besa";

// Before forwarding any agent tool call:
const verified = verifyTrustedSignedManifest(signedManifest, trustStore);
if (!verified.valid) return { decision: "deny", reasonCode: verified.reasonCode };

const decision = admit(signedManifest.manifest, toolName, currentCount);
if (decision.decision === "deny") return decision;

// Only here: forward the call to the actual tool
```

See [examples/agent-gateway/](examples/agent-gateway/) for a working skeleton.

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
| `besa admit <manifest> <tool>` | Gate: check policy + budget (fail-closed, dry-run) |
| `besa receipt <tool> <manifest>` | Enforce budget and issue a signed execution receipt |
| `besa verify-receipt <receipt> <manifest>` | Verify the receipt trust chain |

All commands accept `--trust <trust.json>` to use a consumer-side trust store.
`admit` and `receipt` also accept `--agent <id> --grants <grants.yaml>`.

---

## The execution receipt

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

Besa `0.1.0` is a **first public release (early access)**. The core execution control artifacts — signed manifests, signed execution receipts, and the verification chain — are production-quality cryptography. The surrounding infrastructure is not yet production-grade.

Current limitations:
- Local key storage only; no hosted key management or HSM integration
- File-based meter and trust state; intended for single-host use
- No distributed replay protection across machines or environments
- No external trusted timestamp authority
- No hosted verifier, receipt retention, or SIEM export
- No production identity or multi-user authorization
- No formal compliance certification (SOC 2, ISO 27001, EU AI Act)

The signed manifest, admission gate, and receipt chain are designed to remain forward-compatible as the infrastructure matures. The policy contract you establish today will be verifiable against future infrastructure.

---

## Roadmap

The path from local control plane to hosted infrastructure:

1. **Today (0.1.0):** CLI gate, CI/CD integration, local enforcement, signed receipts
2. **Next:** Hosted verifier API — consumers verify receipts without a local trust store
3. **Then:** Hosted receipt retention — tamper-evident receipt log with export
4. **Then:** Runtime gateway — HTTP proxy that gates agent tool calls in production
5. **Then:** Enterprise control plane — org-level policy, SIEM export, HSM signing, multi-user

---

## License

[MIT](LICENSE)
