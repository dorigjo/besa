import { validateActionEnvelope, type ActionEnvelopeV1 } from "./action.js";
import { hashRequest } from "./signing.js";
import {
  withBesa,
  type BesaExecutionResult,
  type BesaRuntimeConfig,
} from "./runtime.js";

export interface McpToolCall {
  name: string;
  arguments: unknown;
}

export interface BesaMcpConfig extends BesaRuntimeConfig {
  actionForCall(call: McpToolCall): ActionEnvelopeV1;
}

export class BesaMcpError extends Error {
  readonly reasonCode: string;

  constructor(reasonCode: string, message: string, options: { cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "BesaMcpError";
    this.reasonCode = reasonCode;
  }
}

function validateCall(call: unknown): asserts call is McpToolCall {
  if (call === null || typeof call !== "object" || Array.isArray(call)) {
    throw new BesaMcpError("SCHEMA_MCP_CALL_INVALID", "MCP tool call must be an object");
  }
  const name = Object.getOwnPropertyDescriptor(call, "name");
  const argumentsValue = Object.getOwnPropertyDescriptor(call, "arguments");
  if (
    !name ||
    !("value" in name) ||
    typeof name.value !== "string" ||
    name.value.length === 0 ||
    name.value.length > 256 ||
    /[\u0000-\u001f\u007f]/.test(name.value) ||
    !argumentsValue ||
    !("value" in argumentsValue)
  ) {
    throw new BesaMcpError("SCHEMA_MCP_CALL_INVALID", "MCP tool call fields are invalid");
  }
}

export function withBesaMcp<TResult>(
  config: BesaMcpConfig,
  execute: (call: McpToolCall) => TResult | Promise<TResult>,
): (call: McpToolCall) => Promise<BesaExecutionResult<TResult>> {
  if (!config || typeof config !== "object") {
    throw new TypeError("MCP config must be an object");
  }
  if (typeof config.actionForCall !== "function") {
    throw new TypeError("actionForCall must be a function");
  }
  if (typeof execute !== "function") {
    throw new TypeError("execute must be a function");
  }
  const { actionForCall, ...runtimeConfig } = config;

  return async (call: McpToolCall): Promise<BesaExecutionResult<TResult>> => {
    validateCall(call);

    let requested: ActionEnvelopeV1;
    try {
      requested = actionForCall(call);
    } catch (error) {
      throw new BesaMcpError(
        "SCHEMA_ACTION_INVALID",
        "MCP call could not be mapped to a Besa action",
        { cause: error },
      );
    }

    const actionValidation = validateActionEnvelope(requested);
    if (!actionValidation.ok || !actionValidation.action) {
      throw new BesaMcpError(
        "SCHEMA_ACTION_INVALID",
        actionValidation.errors.join("; "),
      );
    }
    const action = actionValidation.action;
    if (action.tool !== call.name) {
      throw new BesaMcpError(
        "ACTION_TOOL_MISMATCH",
        "Besa action tool does not match the MCP tool call",
      );
    }

    let requestHash: string;
    try {
      requestHash = hashRequest(call.arguments);
    } catch (error) {
      throw new BesaMcpError(
        "ACTION_REQUEST_INVALID",
        "MCP arguments cannot be hashed as canonical JSON",
        { cause: error },
      );
    }
    if (action.requestHash !== requestHash) {
      throw new BesaMcpError(
        "ACTION_REQUEST_MISMATCH",
        "Besa action requestHash does not match the MCP arguments",
      );
    }

    // A fresh closure keeps concurrent calls isolated while sharing the
    // configured replay store and evidence sink.
    return withBesa(runtimeConfig, () => execute(call))(action);
  };
}
