import {
  canonicalize,
  hashActionPolicy,
  hashRequest,
  withPreExecutionAdmission,
  type ActionEnvelopeV1,
  type BesaExecutionResult,
  type ExternalAuthorityV1,
  type JsonObject,
  type McpToolCall,
  type PreExecutionAdmissionInput,
  type PreExecutionAdmissionReceiptV1,
  type PreExecutionRuntimeConfig,
} from "@dorigjo/besa";

/**
 * This value must be created by trusted application code after agentgateway
 * authentication. Never populate it from MCP arguments or caller headers.
 */
export interface TrustedAgentgatewayIdentity {
  principalId: string;
  agentId: string;
  authority: ExternalAuthorityV1;
}

export interface AgentgatewayActionDescription {
  operation: string;
  resource: string;
  scopes: string[];
  constraints: JsonObject;
  expiresAt: string;
  nonce: string;
  riskClass: ActionEnvelopeV1["riskClass"];
}

export interface AgentgatewayMcpConfig extends PreExecutionRuntimeConfig {
  gatewayVersion: "1.7.0";
  routeId: string;
  describeAction(
    call: McpToolCall,
    identity: TrustedAgentgatewayIdentity,
  ): AgentgatewayActionDescription;
}

function snapshot<T>(value: T): T {
  return JSON.parse(canonicalize(value)) as T;
}

/**
 * Place this wrapper inside the MCP application that agentgateway routes to,
 * immediately before the consequence-bearing tool implementation.
 *
 * Agentgateway authenticates and routes the request. Besa independently binds
 * the trusted identity, exact tool, actual arguments, policy, audience and
 * executor before invoking the handler. The handler receives only the frozen,
 * verified argument snapshot from the admission input.
 */
export function withAgentgatewayMcpAdmission<TResult>(
  config: AgentgatewayMcpConfig,
  execute: (call: McpToolCall) => TResult | Promise<TResult>,
): (
  call: McpToolCall,
  identity: TrustedAgentgatewayIdentity,
) => Promise<BesaExecutionResult<TResult> & {
  receipt: PreExecutionAdmissionReceiptV1;
  admissionInput: PreExecutionAdmissionInput;
}> {
  const { describeAction, gatewayVersion, routeId, ...runtimeConfig } = config;
  const guarded = withPreExecutionAdmission(runtimeConfig, (input) => execute({
    name: input.request.action.tool,
    arguments: input.request.parameters,
  }));

  return async (callValue, identityValue) => {
    const call = snapshot(callValue);
    const identity = snapshot(identityValue);
    if (!call || typeof call.name !== "string" || call.name.length === 0 ||
        !call.arguments || typeof call.arguments !== "object" || Array.isArray(call.arguments)) {
      throw new TypeError("invalid MCP tool call");
    }
    const description = snapshot(describeAction(call, identity));
    const parameters = call.arguments as JsonObject;
    const context: JsonObject = {
      executorId: runtimeConfig.executorId,
      gateway: { product: "agentgateway", version: gatewayVersion, routeId },
    };
    const at = runtimeConfig.clock?.() ?? new Date();
    if (!(at instanceof Date) || !Number.isFinite(at.getTime())) {
      throw new TypeError("RUNTIME_CLOCK_INVALID");
    }
    const action: ActionEnvelopeV1 = {
      artifactVersion: 1,
      principalId: identity.principalId,
      agentId: identity.agentId,
      authority: identity.authority.issuer,
      tool: call.name,
      operation: description.operation,
      resource: description.resource,
      requestHash: hashRequest(parameters),
      contextHash: hashRequest(context),
      scopes: description.scopes,
      constraints: description.constraints,
      expiresAt: description.expiresAt,
      nonce: description.nonce,
      riskClass: description.riskClass,
    };
    const input: PreExecutionAdmissionInput = {
      request: {
        requestVersion: 1,
        action,
        parameters,
        context,
        audience: runtimeConfig.audience,
        policy: {
          id: runtimeConfig.policy.policyId,
          version: 1,
          hash: hashActionPolicy(runtimeConfig.policy),
        },
        requestedAt: at.toISOString(),
      },
      authority: identity.authority,
    };
    const result = await guarded(input);
    return { ...result, admissionInput: snapshot(input) };
  };
}
