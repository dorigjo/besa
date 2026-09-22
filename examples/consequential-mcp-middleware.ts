import {
  hashRequest,
  withBesaMcp,
  type ActionEnvelopeV1,
  type BesaExecutionResult,
  type BesaMcpConfig,
  type McpToolCall,
} from "@dorigjo/besa";

export interface ConsequentialMcpConfig
  extends Omit<BesaMcpConfig, "actionForCall"> {
  describeAction(call: McpToolCall): Omit<ActionEnvelopeV1, "tool" | "requestHash">;
}

/**
 * Place after the MCP transport's normal authentication and immediately before
 * the privileged tool implementation. The caller supplies business-specific
 * principal, resource, scope, constraint, expiry, and nonce values; this
 * adapter binds the exact MCP tool name and arguments into the action.
 */
export function withConsequentialMcp<TResult>(
  config: ConsequentialMcpConfig,
  execute: (call: McpToolCall) => TResult | Promise<TResult>,
): (call: McpToolCall) => Promise<BesaExecutionResult<TResult>> {
  return withBesaMcp(
    {
      ...config,
      actionForCall(call) {
        const action = config.describeAction(call);
        return {
          ...action,
          tool: call.name,
          requestHash: hashRequest(call.arguments),
        };
      },
    },
    execute,
  );
}
