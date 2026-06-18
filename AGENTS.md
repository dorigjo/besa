# Besa MVP

Besa is signed trust infrastructure for AI-agent tools.

We are not building a dashboard SaaS.
We are building the first tiny root-of-trust layer for agentic software.

## Strategic thesis

AI agents will increasingly call external tools, APIs, MCP servers, workflows, and internal systems.

The core future problem is:

> Which tools is an AI agent allowed to trust, under which declared capabilities, with which verifiable proof, and with which execution receipt?

Besa solves this by creating signed trust artifacts for agent tools.

## Product category

Besa is a developer-first trust layer for MCP-style AI tools.

It provides:

1. Signed tool manifests
2. Runtime verification
3. Admission decisions
4. Signed execution receipts
5. Minimal usage and budget controls

## Core product

Besa signs MCP tool capability manifests, verifies them before runtime use, admits or denies tool calls, and issues signed receipts for every allowed execution.

## Core flow

manifest.yaml
→ besa sign
→ signed-manifest.json
→ besa verify
→ admit tool call
→ issue signed receipt

## Monopoly wedge

Besa must create durable lock-in through artifacts, not features.

The sticky assets are:

* signed manifests
* public keys
* manifest hashes
* policy files
* admission decisions
* execution receipts
* tool trust history
* integration into CI/CD and agent runtime

Every feature must strengthen this trust-artifact loop.

## MVP scope

Build only the first working developer prototype.

Required commands:

1. `besa sign <manifest>`
2. `besa verify <signed-manifest>`
3. `besa admit <signed-manifest> <tool-name>`
4. `besa receipt <tool-name>`

Required modules:

1. Manifest loading
2. Manifest schema validation
3. Ed25519 key generation
4. Manifest signing
5. Manifest verification
6. Admission allow/deny logic
7. Signed receipt creation
8. Mini ActionMeter: call count and budget cap
9. Example MCP-style manifest
10. TypeScript SDK exports

## Manifest must include

Each tool manifest should support:

* server name
* server version
* server URL
* tool list
* tool name
* tool description
* input schema
* capability type: read | write | destructive
* risk level: low | medium | high
* allowed scopes
* budget limit
* created timestamp

## Receipt must include

Each signed receipt should include:

* receipt id
* manifest hash
* tool name
* decision: allow | deny
* reason code
* timestamp
* request hash
* public key id
* signature

## Technical rules

Use:

* TypeScript
* Node.js
* ESM modules
* minimal dependencies
* Ed25519 signatures
* YAML and JSON support
* simple CLI
* small files
* testable functions

Prefer:

* boring code
* explicit types
* deterministic outputs
* pure functions
* simple JSON artifacts
* no hidden state

## Strictly forbidden for MVP

Do not build:

* dashboard
* frontend app
* billing
* database
* login system
* user accounts
* enterprise auth
* multi-tenant SaaS
* hosted registry
* AgentRoot
* GrantRail
* full agent runtime
* complex policy engine
* complex UI
* cloud deployment
* investor deck
* branding system

## Engineering philosophy

This is not a toy app.

But the MVP must stay brutally small.

The first version only has to prove one thing:

> An AI-agent tool can publish a manifest, Besa can sign it, another system can verify it, a tool call can be admitted or denied, and a tamper-evident receipt can be issued.

If a feature does not directly support this flow, do not build it.

## Success criteria for first milestone

The following commands must work locally:

```bash
npm run build
node dist/index.js sign examples/manifest.yaml
node dist/index.js verify examples/manifest.signed.json
node dist/index.js admit examples/manifest.signed.json crm.lookup
node dist/index.js receipt crm.lookup
```

Expected result:

* manifest loads correctly
* manifest is signed
* signature verifies
* tool call can be allowed or denied
* signed receipt is generated
* tests pass

## Code quality bar

Before finishing any task:

1. Run the build
2. Run tests
3. Remove dead code
4. Keep file structure clean
5. Explain exactly what changed
6. Explain exactly how to run it

## Founder constraint

The founder is a solo builder with limited time.

Therefore:

* no overengineering
* no architecture astronaut behavior
* no speculative features
* no fake enterprise platform
* no unnecessary abstractions

Build the smallest credible trust layer that could later become infrastructure.
