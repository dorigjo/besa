# Besa integration targets

Date: 2026-09-23

The objective is one integration boundary that reaches many downstream
developers, not a collection of shallow plugins. No partnership is claimed.

## Ranking

| Rank | Target category | Integration point | Why Besa adds value | Minimum credible demo | Contact needed? |
|---:|---|---|---|---|---|
| 1 | MCP TypeScript servers and gateways | Wrap the registered tool handler after transport/server auth | Binds the actual tool name and canonical argument hash to a signed exact-action capability | Authenticated `aws.change` call: deny production delete, allow staging deploy, verify evidence | No for reference code; maintainer review later |
| 2 | Generic HTTP API gateways | Wrap the final consequence-bearing route handler | Works across agent frameworks and keeps admission beside the real side effect | POST action mapped to an envelope; denied handler count remains zero | No |
| 3 | OpenAI Agents SDK tool guardrails | Tool input guardrail immediately before local function-tool execution | Converts a model-selected tool call into deterministic, signed action admission | One custom tool with a Besa-backed input guardrail and explicit limitations | No for example; upstream inclusion would require review |
| 4 | LangChain JavaScript agent middleware | Tool-call middleware around the handler | Adds exact-action artifacts without replacing the agent loop | `wrapToolCall`-style adapter denying a resource mismatch | No for example; upstream inclusion would require review |
| 5 | Cloud automation pipelines | Pre-apply/deploy/delete application boundary | Binds environment, resource, commit, change ticket, expiry, and delegation | Customer-controlled deployment service around a mock or sandbox executor | Usually no; vendor-native integration may need maintainers |
| 6 | Payment-agent infrastructure | Immediately before the external payment rail | Binds exact recipient, amount, currency, account, and expiry | Sandbox rail only; allow one transfer and deny changed amount/recipient | Often yes for a real rail; not for a mock |
| 7 | Developer-agent execution tools | Before shell, repository mutation, deployment, or secret operations | Makes high-impact tool invocations explicit and replay-aware | One protected local tool with narrow resource and command constraints | Depends on host SDK |
| 8 | Security middleware and evidence pipelines | Admission before execution; artifact export after execution | Adds portable signed authorization context to existing telemetry | Correlate trace ID with capability/evidence IDs; state proof limits | No for generic export |

## First distribution test: MCP TypeScript

The MCP boundary is first because it combines strong category fit, a narrow
handler hook, active developer attention, and no need to own an agent runtime.
The official TypeScript SDK exposes registered tool handlers; Besa can wrap the
consequence-bearing callback without changing MCP discovery or transport.

Primary references:

- [MCP TypeScript SDK](https://ts.sdk.modelcontextprotocol.io/v2/)
- [Besa MCP comparison](../BESA_VS_MCP_AUTH.md)
- [Besa typed MCP adapter](../../examples/consequential-mcp-middleware.ts)

### Hypothesis

An MCP server author can place one typed wrapper around a privileged handler,
map the call to an `ActionEnvelopeV1`, and observe a protocol-correct denial in
under ten minutes without adopting a Besa-hosted service.

### Deliverable

1. Keep the adapter dependency-free and typed against Besa's structural
   `McpToolCall` boundary.
2. Show one authenticated call denied before execution and one exact call
   allowed with verified evidence.
3. Document where identity, policy, keys, replay state, and evidence storage
   remain the host application's responsibility.
4. Ask MCP maintainers and server authors for technical criticism only after the
   clean-room demo succeeds.

### Success criteria

- A developer outside the repository runs the demo without founder assistance.
- At least one external MCP server prototype wraps a real handler.
- Feedback identifies concrete API or protocol friction rather than confusion
  about whether Besa replaces MCP authentication.

### Stop criteria

Do not create framework-specific packages until the reference adapter produces
external use or repeated integration requests. Do not add an MCP dependency to
Besa core solely for discoverability.

## Secondary framework hooks

The [OpenAI Agents SDK tool guardrail](https://openai.github.io/openai-agents-js/guides/guardrails/)
is a credible pre-execution hook for local function tools and converted local
MCP tools. A future example must distinguish a deterministic signed admission
contract from model-based or content-safety guardrails and note unsupported
tool paths documented by that SDK.

The [LangChain JavaScript AgentMiddleware reference](https://reference.langchain.com/javascript/langchain/index/AgentMiddleware)
exposes tool-call request/handler interception. A future adapter should wrap the
existing handler rather than introduce another agent abstraction.

Both are follow-on tests, not current partnership claims.

## Outreach rule

Contact maintainers only with a runnable, narrowly scoped example and one clear
question: whether the boundary matches their execution lifecycle. Do not ask
for endorsement, bundling, logos, or stars. Record external integrations only
when a public repository or maintainer confirms them.
