# n8n-nodes-besa

n8n community node for [Besa](https://github.com/dorigjo/besa) -- the cryptographic admission and evidence layer for AI-agent tool calls.

## What this is

A thin n8n adapter around the real [`@dorigjo/besa`](https://www.npmjs.com/package/@dorigjo/besa) SDK. It does not reimplement any Besa logic -- the actual `@dorigjo/besa` package is bundled into this node's build output and does all signing, verification, admission, and receipt work. This node exists so an n8n workflow can call that logic without shelling out to the `besa` CLI.

It is stateless: no database, no dashboard, no server. Every operation is a pure function call against JSON you already have in your workflow (a signed manifest, a receipt, a trust store).

## Why

If an n8n workflow lets an AI agent call tools -- HTTP requests, database writes, other services -- you may want a policy gate in front of that call, and a signed, tamper-evident record of what was allowed or denied afterward. Besa provides both without requiring any hosted service: everything here runs locally, inside your own n8n instance.

## Install

Self-hosted n8n only (see [Limitations](#limitations) -- this is not eligible for n8n Cloud's verified community-node tier, because it depends on a real external library rather than only making HTTP calls).

**Settings > Community Nodes > Install**, package name:

```
n8n-nodes-besa
```

Or from the CLI, inside your n8n installation:

```bash
npm install n8n-nodes-besa
```

## 5-minute example

You need a Besa manifest and a signing key. If you don't have the `besa` CLI yet:

```bash
npm install -g @dorigjo/besa
besa keygen                      # writes .besa/key.json (encrypted, passphrase-protected)
besa sign examples/manifest.yaml # writes examples/manifest.signed.json
```

1. Import [`examples/workflows/besa-demo.workflow.json`](examples/workflows/besa-demo.workflow.json) from this package into n8n (**Workflows > Import from File**).
2. Open the **Besa Signing Key** credential the workflow creates a placeholder for, and paste in:
   - **Stored Key Pair**: the full contents of your `.besa/key.json`
   - **Passphrase**: the passphrase you used with `besa keygen`
3. In the **Set Signed Manifest** node, paste the contents of your `examples/manifest.signed.json`.
4. Run the workflow. It will: verify the manifest's signature, check admission for a demo tool call, branch on allow/deny, and (on allow) create and then verify a signed receipt -- all without ever calling a real destructive tool.

## Workflow diagram

The shipped example ([`examples/workflows/besa-demo.workflow.json`](examples/workflows/besa-demo.workflow.json)) is a straight line through all four operations -- it creates and verifies a receipt for whatever `Check Admission` actually decides, allow or deny, so it's a complete demonstration either way:

```
Manual Trigger
      |
      v
Set Signed Manifest  (paste your signed manifest + a demo request)
      |
      v
Besa: Verify Signed Manifest
      |
      v
Besa: Check Admission        (tool = "demo.echo")
      |
      v
Besa: Create Receipt         (decision/reasonCode taken from Check Admission)
      |
      v
Besa: Verify Receipt
```

For real tool-gating, put your actual tool call (an HTTP Request node, another service call, etc.) behind an IF node keyed on `{{$json.decision === "allow"}}` between **Check Admission** and **Create Receipt** -- the example keeps that out to stay a pure, harmless demo of the Besa chain itself.

## Operations

| Operation | Needs credential | What it does |
|---|---|---|
| **Verify Signed Manifest** | No | Checks a signed manifest's Ed25519 signature and internal self-consistency. If a **Trust Store** is also supplied, additionally requires the signing key to be an active trust anchor -- otherwise only self-consistency is checked, and the output says so (`trustAnchored: false`). |
| **Check Admission** | No | Runs Besa's admission policy (`admit()`) for one tool call: budget limit, destructive+high-risk denial. Returns `{decision, reasonCode, toolName, detail}`. A deny is a normal, non-throwing result -- branch on it with an IF node. Does not write or track state; call-count tracking is your workflow's responsibility. |
| **Create Receipt** | **Yes** | Signs a tamper-evident execution receipt for a decision (allow or deny). Requires the **Besa Signing Key** credential. |
| **Verify Receipt** | No | Replays Besa's full receipt-verification chain: manifest trust/signature, `manifestHash` match, tool-declared check (for allow receipts), optional request-hash rebinding, receipt signature, and (if a trust store is supplied) trust re-check at the receipt's own timestamp. |

Only **Create Receipt** touches the private key. The other three operations are read-only verification and never request the credential.

## Security

- The **Besa Signing Key** credential stores the same encrypted `.besa/key.json` your `besa` CLI already produces (AES-256-GCM, scrypt-derived key) -- never a raw private key.
- The passphrase is only used in-memory, for the duration of a single **Create Receipt** execution, to decrypt the key via Besa's own `openKeyPair()`. It is never logged, persisted, or included in any node output.
- A wrong passphrase produces a fixed, generic error (`key file authentication failed`) -- never the passphrase, the ciphertext, or key bytes. This is enforced by an automated test (`test/security/no-secret-leak.test.mjs`).
- This node makes no network calls, phones home to nothing, and writes no files of its own.

## Limitations

- **Self-hosted n8n only.** This node depends on the real `@dorigjo/besa` library (bundled at build time), which n8n Cloud's community-node verification tier does not allow (community nodes there may only make HTTP calls). It installs and runs normally in any self-hosted n8n instance.
- **No call-count tracking.** `Check Admission` is a pure policy check; it does not persist how many times a tool has been called. If your policy needs budget enforcement across calls, track the count yourself (e.g. in a database or n8n data table) and pass it in.
- **No grant/scope evaluation.** Besa's agent-scoped grant system (`checkGrant`) is not exposed here yet -- only manifest-level admission.
- **JSON-in, JSON-out only.** This node does not read or write `.besa/` files, YAML manifests, or the `besa` CLI's local receipt store. Feed it JSON your workflow already has, and store its JSON output wherever your workflow needs it.

## Besa

Spec, CLI, and the underlying SDK: [github.com/dorigjo/besa](https://github.com/dorigjo/besa)
