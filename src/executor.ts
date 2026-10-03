import {
  BesaAdmissionError, withPreExecutionAdmission, type PreExecutionRuntimeConfig,
} from "./pre-execution-runtime.js";
import type { PreExecutionAdmissionInput, PreExecutionAdmissionReceiptV1 } from "./pre-execution.js";
import type { BesaExecutionResult } from "./runtime.js";
import { snapshotJson } from "./snapshot.js";

export interface AuthenticatedExecutorCaller {
  agentId: string;
  principalId: string;
}

export type BesaExecutorConfig = Omit<PreExecutionRuntimeConfig, "resolveAdmission">;

export function withBesaExecutor<TResult>(
  config: BesaExecutorConfig,
  execute: (input: PreExecutionAdmissionInput) => TResult | Promise<TResult>,
): (input: PreExecutionAdmissionInput, receipt: unknown, caller: AuthenticatedExecutorCaller) =>
  Promise<BesaExecutionResult<TResult> & { receipt: PreExecutionAdmissionReceiptV1 }> {
  if (!config || typeof config.executorId !== "string" || !config.executorId.trim() ||
      typeof execute !== "function") throw new TypeError("executor identity and handler required");
  return async (inputValue, receiptValue, callerValue) => {
    let input: PreExecutionAdmissionInput;
    let receipt: PreExecutionAdmissionReceiptV1;
    let caller: AuthenticatedExecutorCaller;
    try {
      input = snapshotJson(inputValue);
      receipt = snapshotJson(receiptValue) as PreExecutionAdmissionReceiptV1;
      caller = snapshotJson(callerValue);
    } catch { throw new BesaAdmissionError("SCHEMA_EXECUTOR_INPUT_INVALID"); }
    if (!input?.request?.action || !caller ||
        typeof caller.agentId !== "string" || typeof caller.principalId !== "string" ||
        caller.agentId !== input.request.action.agentId ||
        caller.principalId !== input.request.action.principalId) {
      throw new BesaAdmissionError("ADMISSION_CALLER_MISMATCH");
    }
    if (input.request.context?.executorId !== config.executorId) {
      throw new BesaAdmissionError("ADMISSION_EXECUTOR_MISMATCH");
    }
    // The supplied receipt is untrusted. The existing wrapper independently
    // checks it, commits it, consumes replay state and revalidates before execute.
    return withPreExecutionAdmission({
      ...config,
      get policy() { return config.policy; },
      get audience() { return config.audience; },
      get trustStore() { return config.trustStore; },
      get authorityTrustStore() { return config.authorityTrustStore; },
      get delegationTrustStore() { return config.delegationTrustStore; },
      resolveAdmission: () => receipt,
    }, (verified) => {
      if (verified.request.context.executorId !== config.executorId) {
        throw new BesaAdmissionError("ADMISSION_EXECUTOR_MISMATCH");
      }
      return execute(verified);
    })(input);
  };
}
