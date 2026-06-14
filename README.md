# Besa

Signed trust infrastructure for AI-agent tools.

> **Alpha / developer preview — not production-ready.**
>
> Besa is currently an early alpha (`0.1.0-alpha.0`). APIs, file formats, receipt formats, and behavior may change without notice.
>
> Do not use Besa to protect production systems, production secrets, customer data, or real signing keys yet.
>
> The key under `.besa/` is a local demo key.

Besa signs MCP-style tool manifests, verifies them before use, admits or denies tool calls against policy, and issues signed tamper-evident receipts.

Besa is the trust layer for AI-agent tools.

## What it does

* Signs tool manifests with Ed25519.
* Verifies signed manifests before runtime use.
* Allows or denies tool calls with reason codes.
* Blocks destructive high-risk tools by default.
* Tracks local per-tool usage with a mini ActionMeter.
* Creates signed receipts for admission decisions.

Flow:

```text
manifest.yaml -> sign -> verify -> admit -> receipt
```

## Why it matters

AI agents increasingly call external tools, APIs, MCP servers, and internal systems.

The important question is not only whether an agent can call a tool.

The important questions are:

* Which tool is the agent allowed to call?
* Who signed the declared capability?
* Has the manifest changed?
* Was the call allowed or denied?
* Is there a receipt proving the decision?

Besa turns those answers into signed artifacts.

## Quickstart

Install dependencies:

```bash
npm install
```

Build:

```bash
npm run build
```

Run tests:

```bash
npm test
```

Run the smoke test:

```bash
npm run smoke
```

The smoke test runs the full CLI flow: build, load, sign, verify, admit allow, admit deny, and receipt creation.

## CLI commands

Load a manifest:

```bash
node dist/index.js load examples/manifest.yaml
```

Sign a manifest:

```bash
node dist/index.js sign examples/manifest.yaml
```

Verify a signed manifest:

```bash
node dist/index.js verify examples/manifest.signed.json
```

Admit a safe tool:

```bash
node dist/index.js admit examples/manifest.signed.json crm.lookup
```

Deny a dangerous tool:

```bash
node dist/index.js admit examples/manifest.signed.json crm.delete
```

Create a signed receipt:

```bash
node dist/index.js receipt crm.lookup
```

Expected behavior:

* `crm.lookup` -> allow / `ALLOWED`
* `crm.delete` -> deny / `RISK_BLOCKED`

### Grant-aware admission (optional)

Besa can scope a tool call to a specific agent. Add a `grants.yaml` listing which `agentId` may use which tools:

```
grants:
  - agentId: agent-alpha
    tools:
      - crm.lookup
```

Then pass `--agent` and `--grants` to `admit` or `receipt`:

```
node dist/index.js admit examples/manifest.signed.json crm.lookup --agent agent-alpha --grants examples/grants.yaml
```

- `--agent <id>`: the id of the calling agent.
- `--grants <file>`: the grants file to check against.
- If the agent is not granted the tool, admission is denied (`TOOL_NOT_GRANTED`, or `AGENT_NOT_FOUND` for an unknown agent), and the receipt records `agentId` and `grantReasonCode`.

Grants are **optional and backward-compatible**: without `--grants`, admission behaves exactly as before.

## Core concepts

### Tool Manifest

A YAML or JSON file that declares a tool server and its tools.

Each tool has:

* name
* description
* capability
* risk
* scopes
* budgetLimit
* inputSchema

Capabilities:

* read
* write
* destructive

Risk levels:

* low
* medium
* high

### Signed Manifest

A manifest signed with Ed25519.

The signed manifest includes:

* manifest
* manifestHash
* algorithm
* publicKey
* publicKeyId
* signature
* signedAt

### Admission Decision

Besa evaluates whether a tool call should be allowed or denied.

Reason codes include:

* `ALLOWED`
* `TOOL_NOT_FOUND`
* `RISK_BLOCKED`
* `BUDGET_EXCEEDED`

### Mini ActionMeter

Besa tracks local call counts per tool.

This allows simple budget enforcement through `budgetLimit`.

### Signed Receipt

A receipt proves what decision was made.

A receipt includes:

* receiptId
* manifestHash
* toolName
* decision
* reasonCode
* timestamp
* requestHash
* publicKeyId
* algorithm
* signature

## SDK usage

Import Besa from the SDK:

```ts
import {
  loadManifest,
  generateKeyPair,
  signManifest,
  verifySignedManifest,
  admit,
  createReceipt,
  verifyReceipt,
} from "besa";
```

Basic flow:

```ts
const manifest = loadManifest("examples/manifest.yaml");

const keypair = generateKeyPair();

const signed = signManifest(manifest, keypair);

const verified = verifySignedManifest(signed);

if (!verified.valid) {
  throw new Error(verified.reasonCode);
}

const decision = admit(signed, "crm.lookup");

const receipt = createReceipt(signed, decision, keypair);

const receiptResult = verifyReceipt(receipt);

if (!receiptResult.valid) {
  throw new Error(receiptResult.reasonCode);
}
```

## Security

Never commit `.besa/`.

The `.besa/` folder contains local trust artifacts, including the Ed25519 private key.

Ignored local artifacts:

* `.besa/`
* `.besa/key.json`
* `.besa/meter.json`
* `.besa/receipts/`
* `examples/manifest.signed.json`

The local key generated by this MVP is a demo key. Rotate keys before real usage.

See:

* [SECURITY.md](SECURITY.md)
* [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## MVP limitations

This is an MVP and alpha developer preview.

Current limitations:

* local key storage only
* local JSON meter only
* no hosted registry
* no SaaS backend
* no dashboard
* no remote verifier API
* no hosted receipts API
* no distributed replay protection
* no key rotation
* no key revocation
* one default policy

Default policy:

* destructive + high risk = denied

## What Besa is not

Besa is currently an alpha trust layer for AI-agent tool control and evidence.

It is not:

* a hosted SaaS
* a dashboard or UI
* a full MCP gateway
* production key management
* a compliance certification product
* a replacement for identity, authorization, audit storage, or security monitoring
* ready for production secrets or production systems

## Release docs

* [SECURITY.md](SECURITY.md) — security policy, key handling, and vulnerability reporting
* [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, threats, mitigations, and current MVP limitations
* [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) — pre-release gates before tagging or publishing
* [CHANGELOG.md](CHANGELOG.md) — notable changes by version

## Roadmap

Planned next layers:

* hosted key management
* remote verifier API
* policy packs
* MCP gateway integration
* enterprise audit export
* receipts API
* usage-based ActionMeter
* organization-level trust registry

## Positioning

Besa is signed trust infrastructure for AI-agent tools.

It is not another chatbot.

It is not another dashboard.

It is a trust layer for agentic execution.