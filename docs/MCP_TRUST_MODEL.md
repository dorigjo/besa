# Besa × MCP Trust Model

Architecture notes only. **Nothing described here is implemented.** Besa's
CLI today (`besa admit`, `besa receipt`) operates on signed manifests and
tool names supplied directly on the command line; there is no MCP transport
integration, no MCP server, and no MCP client code in this repository. This
document exists so that if/when MCP integration is built, it is built on a
flow that was thought through once, deliberately, rather than bolted on
tool call by tool call.

## Guarantees, non-guarantees, and trust boundary

Since nothing in this document is implemented, there is nothing to
guarantee yet. What follows is what a future implementation *would* and
*would not* guarantee, so that a security engineer evaluating this design
knows what to check for when it is eventually built:

**Would be guaranteed:** the admission decision and receipt attached to an
MCP tool call would carry the same cryptographic guarantees as any other
Besa admission/receipt (see `TRUST_MODEL.md`'s guarantees section) — a
verifiable, tamper-evident record of what was decided and why.

**Would NOT be guaranteed:** that the MCP transport itself is authenticated
or confidential — Besa's admission/receipt layer says nothing about
whether the MCP connection is trustworthy, only about the tool-call
decision layered on top of it. Transport security is the MCP host's
responsibility, not something a Besa integration would add.

**Trust boundary (future):** identical to `TRUST_MODEL.md` — the boundary
is the trust store of whichever party runs the admission check. An MCP
integration would not move that boundary; it would only change *where in
the request lifecycle* the check happens.

## Why this matters

Besa's MVP scope (its founder constraints document) forbids a "full agent runtime." MCP
integration is not that — it is a place to attach an *existing* runtime's
tool-call boundary to Besa's admission and receipt primitives, which already
work independently of any transport. This document describes that
attachment point, not a new execution engine.

## Flow

```
Agent
  |
  |  1. wants to call a tool exposed by an MCP server
  v
MCP Tool Request
  |  { serverName, toolName, arguments }
  v
Besa Admission Layer                    <-- attachment point
  |  besa admit <signed-manifest> <toolName> [--agent <id> --grants <file>]
  |  -> AdmissionDecision { decision, reasonCode, toolName, detail, agentId? }
  v
  +-- deny -> request is refused before the MCP server ever sees it
  |
  +-- allow
       |
       v
     Tool Execution                      <-- unchanged: the MCP server runs
       |                                     the tool exactly as it does today
       v
     Signed Receipt
       |  besa receipt <toolName> <signed-manifest> [--request <file>]
       |  -> Receipt { receiptId, manifestHash, toolName, decision,
       |                reasonCode, requestHash, publicKeyId, signature, ... }
       v
     Evidence attached to the MCP response (or logged alongside it)
```

The admission check and the receipt are the same two primitives Besa
already has; MCP integration is "call them at the right two points in an
MCP tool-call lifecycle," not new trust logic.

## Metadata mapping

| MCP concept | Besa artifact field |
|---|---|
| MCP server (name, version, endpoint) | `Manifest.serverName` / `serverVersion` / `serverUrl` |
| MCP tool definition (name, input schema) | `ToolDefinition.name` / `inputSchema` |
| Tool call arguments | Hashed into `Receipt.requestHash` via `hashRequest()`; the raw arguments are never embedded in the receipt itself |
| Calling agent (if the MCP host identifies one) | `AdmissionDecision.agentId` / `Receipt.agentId` — a caller-supplied label today, not a verified identity (see `TRUST_MODEL.md` §1) |
| MCP tool-call result | Out of scope for the receipt; Besa attests to the *decision*, not the tool's output |

A tool exposed over MCP still needs a Besa manifest describing it — Besa
does not derive one from MCP's own tool-listing protocol. Producing a
Besa manifest from an MCP server's tool list automatically would be a
reasonable future convenience, but it is generation tooling, not a change
to the trust model, and is out of scope here.

## Policy input

Admission today (`admit()` in `src/admit.ts`) decides from three inputs:
the manifest's declared `capability`/`risk`/`budgetLimit` for the tool, the
running call count from the local meter, and — if `--agent`/`--grants` is
supplied — whether that agent is granted that tool. An MCP attachment point
would supply exactly these same three inputs, sourced from the MCP request
instead of CLI arguments; it introduces no new policy dimension.

## Decision object

Unchanged: `AdmissionDecision` (dry-run, via `admit`) and `Receipt`
(enforced + signed, via `receipt`) are already transport-agnostic. An MCP
integration serializes one of these two into whatever the MCP host expects
(e.g. an error response on deny, a response header or sidecar object
carrying the receipt on allow) — but the object itself does not change
shape for MCP.

## Receipt attachment

Two options, deliberately left open rather than decided:

1. **Sidecar**: the MCP host stores the receipt file path or the receipt
   object itself alongside the tool-call log entry it already keeps.
2. **Inline**: the receipt (or just its `receiptId` + `signature`) is
   returned to the calling agent as part of the MCP response, so the agent
   itself can carry proof of an authorized call forward.

Both are compatible with today's receipt format; neither requires a schema
change. Which one an integration picks depends on where the MCP host wants
evidence to live — that is a deployment decision, not a trust-model
decision.

## Verification flow

Unchanged from today: `besa verify-receipt <receipt> <signed-manifest>
[--request <file>]` — replays the same manifest/trust chain and, if given
the original request payload, re-checks `hashRequest(request) ===
receipt.requestHash`. An MCP-side verifier (e.g. an audit tool consuming
receipts after the fact) would call the same verification primitives Besa
already exposes; no new verification logic is implied by MCP integration.

## Explicit non-goals of this document

- No MCP server or client code
- No new manifest or receipt fields
- No claim that Besa is "MCP-certified" or endorsed by the MCP project
- No decision on which specific MCP host/SDK a future integration targets
