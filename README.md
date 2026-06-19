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

> **Beta.** `0.1.0-beta.2` is a local developer beta. It is not production key
> management, authorization, or audit storage.

## Trust flow

```text
manifest.yaml
  -> besa sign
  -> manifest.signed.json
  -> besa trust add
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
- Whole-envelope signatures binding manifest, hash, key, algorithm, and time
- Explicit public-key trust anchors with active, retired, and revoked states
- Old-key-signed rotation proofs and local private-key archival
- Stable canonical manifest hashing with SHA-256
- Allow/deny decisions with explicit reason codes
- Destructive high-risk tool blocking
- Manifest-scoped call budgets with cross-process file locking
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

To verify as a separate consumer, pin the publisher key explicitly:

```powershell
node .\dist\index.js trust add .\examples\manifest.signed.json `
  --trust .\consumer-trust.json

node .\dist\index.js verify .\examples\manifest.signed.json `
  --trust .\consumer-trust.json
```

Rotate the publisher key and propagate the signed transition:

```powershell
node .\dist\index.js keys rotate

$rotation = Get-ChildItem .\.besa\rotations\*.json |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

node .\dist\index.js trust apply $rotation.FullName `
  --trust .\consumer-trust.json

node .\dist\index.js sign .\examples\manifest.yaml
```

The previous key becomes `retired`: artifacts signed before rotation remain
verifiable, but new admissions under that key are denied. `trust revoke`
invalidates a key for both historical verification and new admission.

## Commands

- `besa keys`
- `besa keys rotate [--trust <trust.json>]`
- `besa trust add <signed-manifest> [--trust <trust.json>]`
- `besa trust apply <rotation> [--trust <trust.json>]`
- `besa trust revoke <public-key-id> [--trust <trust.json>]`
- `besa trust list [--trust <trust.json>]`
- `besa load <manifest>`
- `besa sign <manifest> [--trust <trust.json>]`
- `besa verify <signed-manifest> [--trust <trust.json>]`
- `besa admit <signed-manifest> <tool-name> [--trust <trust.json>]`
- `besa receipt <tool-name> [signed-manifest] [--trust <trust.json>] [--request <request.json>]`
- `besa verify-receipt <receipt> [signed-manifest] [--trust <trust.json>]`

Admission and receipt commands also accept
`--agent <agent-id> --grants <grants.yaml>`.

Reason codes include `ALLOWED`, `TOOL_NOT_FOUND`, `RISK_BLOCKED`,
`BUDGET_EXCEEDED`, `TOOL_NOT_GRANTED`, `AGENT_NOT_FOUND`, `E_KEY_UNTRUSTED`,
`E_KEY_RETIRED`, and `E_KEY_REVOKED`.

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
  addTrustAnchor,
  applyKeyRotation,
  createKeyRotation,
  generateKeyPair,
  signManifest,
  verifyTrustedSignedManifest,
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
npm run test:package
npm pack --dry-run
```

## Security

`.besa/` contains active and archived Ed25519 private keys, the trust store,
rotation proofs, budget meter, active manifest, and receipts. It is ignored by
Git and must never be committed.

See [SECURITY.md](SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Beta limitations

- Local unencrypted key storage
- File-based trust and meter state, intended for one host
- No hardware-backed or remote key custody
- No distributed replay protection
- No external trusted timestamp authority
- No hosted verifier or receipt retention
- No production identity or authorization integration

## License

[MIT](LICENSE)
