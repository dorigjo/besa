<p align="center">
  <img src="site/logo.svg" alt="" width="44" height="40" />
</p>

<h1 align="center">Besa</h1>

<p align="center"><strong>Agent Action Receipts</strong></p>

<p align="center">Signed trust infrastructure for AI-agent tools.</p>

---

AI agents call real systems: CRMs, payment APIs, deployment pipelines, and
databases. Besa makes those calls verifiable.

Besa validates and signs an MCP-style tool manifest, verifies it before use,
admits or denies a tool call, and issues a signed receipt for the decision.

> **Beta.** `0.1.0-beta.0` is a local developer beta. It is not production key
> management, authorization, or audit storage.

## Trust flow

```text
manifest.yaml
  -> besa sign
  -> manifest.signed.json
  -> besa verify
  -> besa admit crm.lookup
  -> besa receipt crm.lookup
  -> besa verify-receipt receipt.json
```

The durable artifacts are the signed manifest, public key ID, manifest hash,
admission decision, request hash, and signed execution receipt.

## What works

- YAML and JSON manifest loading with runtime schema validation
- Ed25519 key generation, manifest signing, and verification
- Stable canonical manifest hashing with SHA-256
- Allow/deny decisions with explicit reason codes
- Destructive high-risk tool blocking
- Manifest-scoped local call budgets
- Optional agent grants
- Signed receipts bound to the manifest signing key
- Receipt trust-chain verification
- TypeScript SDK exports

## Install

```powershell
npm install @dorigjo/besa@beta
```

Or build the repository locally:

```powershell
git clone https://github.com/dorigjo/besa
Set-Location .\besa
npm ci
npm run build
```

## PowerShell quickstart

```powershell
node .\dist\index.js keys
node .\dist\index.js load .\examples\manifest.yaml
node .\dist\index.js sign .\examples\manifest.yaml
node .\dist\index.js verify .\examples\manifest.signed.json
node .\dist\index.js admit .\examples\manifest.signed.json crm.lookup
node .\dist\index.js admit .\examples\manifest.signed.json crm.delete
node .\dist\index.js receipt crm.lookup .\examples\manifest.signed.json --request .\examples\request.json

$receipt = Get-ChildItem .\.besa\receipts\*.json |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

node .\dist\index.js verify-receipt $receipt.FullName .\examples\manifest.signed.json
```

`crm.lookup` is allowed. `crm.delete` is denied with `RISK_BLOCKED` and exits
with code `1`.

Agent-scoped admission is opt-in:

```powershell
node .\dist\index.js admit .\examples\manifest.signed.json crm.lookup `
  --agent agent-alpha `
  --grants .\examples\grants.yaml
```

## Commands

- `besa keys`
- `besa load <manifest>`
- `besa sign <manifest>`
- `besa verify <signed-manifest>`
- `besa admit <signed-manifest> <tool-name>`
- `besa receipt <tool-name> [signed-manifest] [--request <request.json>]`
- `besa verify-receipt <receipt> [signed-manifest]`

Admission and receipt commands also accept
`--agent <agent-id> --grants <grants.yaml>`.

Reason codes include `ALLOWED`, `TOOL_NOT_FOUND`, `RISK_BLOCKED`,
`BUDGET_EXCEEDED`, `TOOL_NOT_GRANTED`, and `AGENT_NOT_FOUND`.

## Receipt artifact

```json
{
  "receiptId": "rcpt_2d7942c7-8f70-4984-9c3f-24876acfd860",
  "manifestHash": "ea7e9ca22d199f40281cdf9e5d6145440c6c7d6bfbe94157c4b1da5527054410",
  "toolName": "crm.lookup",
  "decision": "allow",
  "reasonCode": "ALLOWED",
  "timestamp": "2026-06-18T10:00:00.000Z",
  "requestHash": "b27b80d1227c167a6fca199778645daa77d20a8087782fc48802d11d6281c920",
  "publicKeyId": "89f17bbd1da3fae8",
  "algorithm": "ed25519",
  "signature": "..."
}
```

Changing any signed receipt field causes verification to fail. The
`verify-receipt` command also verifies the signed manifest and confirms that
the receipt references its manifest hash and signing key.

## SDK

```typescript
import {
  admit,
  generateKeyPair,
  signManifest,
  verifySignedManifest,
} from "@dorigjo/besa";
```

The package exports the manifest, signing, admission, grant, receipt, and
cryptographic helper APIs from `dist/sdk.js`.

## Release gates

```powershell
npm ci
npm run build
npm test
npm run smoke
npm pack --dry-run
```

## Security

`.besa/` contains the local Ed25519 private key, budget meter, active manifest,
and receipts. It is ignored by Git and must never be committed.

See [SECURITY.md](SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Beta limitations

- Local unencrypted key storage
- Local JSON meter state
- No key rotation or revocation
- No distributed replay protection
- No hosted verifier or receipt retention
- No production identity or authorization integration

## License

[MIT](LICENSE)
