import {
  hashActionPolicy, hashPreExecutionReceipt, validatePreExecutionRequest,
  verifyPreExecutionAdmission, type PreExecutionAdmissionInput,
  type PreExecutionAdmissionReceiptV1, type PreExecutionVerificationConfig,
} from "./pre-execution.js";
import {
  BesaRuntimeError, withBesa, type BesaExecutionResult, type BesaRuntimeConfig,
} from "./runtime.js";
import { snapshotJson } from "./snapshot.js";

export interface AdmissionReceiptSink {
  append(receipt: PreExecutionAdmissionReceiptV1): Promise<void>;
}

export interface PreExecutionRuntimeConfig extends PreExecutionVerificationConfig,
  Omit<BesaRuntimeConfig, "capability" | "replayRequirement" | "receiptHash" |
    "delegationChain" | "requireDelegation" | "delegationTrustStore"> {
  resolveAdmission(input: PreExecutionAdmissionInput):
    PreExecutionAdmissionReceiptV1 | Promise<PreExecutionAdmissionReceiptV1>;
  admissionSink: AdmissionReceiptSink;
}

export class BesaAdmissionError extends Error {
  constructor(
    readonly reasonCode: string,
    readonly receipt?: PreExecutionAdmissionReceiptV1,
  ) {
    super(reasonCode);
    this.name = "BesaAdmissionError";
  }
}

function time(clock: () => Date): Date {
  const at = clock();
  if (!(at instanceof Date) || !Number.isFinite(at.getTime())) {
    throw new BesaAdmissionError("RUNTIME_CLOCK_INVALID");
  }
  return new Date(at);
}

export function withPreExecutionAdmission<TResult>(
  config: PreExecutionRuntimeConfig,
  execute: (input: PreExecutionAdmissionInput) => TResult | Promise<TResult>,
): (input: PreExecutionAdmissionInput) => Promise<BesaExecutionResult<TResult> & {
  receipt: PreExecutionAdmissionReceiptV1;
}> {
  if (!config || typeof config.resolveAdmission !== "function" ||
      !config.admissionSink || typeof config.admissionSink.append !== "function" ||
      typeof execute !== "function") throw new TypeError("invalid pre-execution runtime config");
  hashActionPolicy(config.policy);
  const clock = config.clock ?? (() => new Date());
  if (typeof clock !== "function") throw new TypeError("clock must be a function");
  if (config.replayStore?.mode !== "enforced") {
    throw new TypeError("pre-execution admission requires an enforced replay store");
  }

  return async (inputValue) => {
    let input: PreExecutionAdmissionInput;
    try {
      input = snapshotJson(inputValue);
      if (!input || typeof input !== "object" || Array.isArray(input) ||
          Object.keys(input).some((key) => !["request", "authority", "delegationChain"].includes(key))) {
        throw new TypeError("invalid admission input");
      }
      const check = validatePreExecutionRequest(input.request);
      if (!check.ok) throw new TypeError(check.reasonCode);
    } catch {
      throw new BesaAdmissionError("SCHEMA_PRE_EXECUTION_REQUEST_INVALID");
    }

    let candidate: unknown;
    try {
      candidate = await config.resolveAdmission(input);
    } catch {
      throw new BesaAdmissionError("ADMISSION_VERIFIER_UNAVAILABLE");
    }
    const verified = verifyPreExecutionAdmission(candidate, input, config, time(clock));
    if (!verified.valid || !verified.receipt) throw new BesaAdmissionError(verified.reasonCode);
    const receipt = snapshotJson(verified.receipt);
    try {
      await config.admissionSink.append(receipt);
    } catch {
      throw new BesaAdmissionError("ADMISSION_RECORD_FAILED", receipt);
    }
    if (!verified.authorized || !receipt.capability) {
      throw new BesaAdmissionError(receipt.reasonCode, receipt);
    }

    const receiptHash = hashPreExecutionReceipt(receipt);
    const guarded = withBesa({
      ...config, capability: receipt.capability, replayRequirement: "enforce", receiptHash,
      delegationChain: input.delegationChain,
      delegationTrustStore: config.delegationTrustStore ?? config.authorityTrustStore,
      requireDelegation: config.policy.delegationRequired,
    }, () => {
      // No await separates the last authority/policy check from invoking execute.
      const final = verifyPreExecutionAdmission(receipt, input, config, time(clock));
      if (!final.valid || !final.authorized) {
        throw new BesaAdmissionError(final.reasonCode, receipt);
      }
      return execute(input);
    });
    try {
      const result = await guarded(input.request.action);
      return { ...result, receipt };
    } catch (error) {
      if (error instanceof BesaRuntimeError && error.cause instanceof BesaAdmissionError) {
        throw error.cause;
      }
      throw error;
    }
  };
}
