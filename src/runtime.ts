import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { resolve } from "node:path";
import {
  canonicalize,
  validateKeyPair,
  type KeyPair,
} from "./crypto.js";
import {
  checkActionEnvelope,
  type ActionEnvelopeV1,
} from "./action.js";
import {
  verifyActionCapability,
  type ActionCapabilityV1,
} from "./action-capability.js";
import {
  createActionEvidence,
  type ActionEvidenceV1,
} from "./action-evidence.js";
import {
  verifyActionDelegation,
  type DelegationV1,
} from "./delegation.js";
import {
  REPLAY_REASON,
  replayKey,
  type ReplayConsumeResult,
  type ReplayStore,
} from "./replay.js";
import type { TrustStore } from "./types.js";

export interface RuntimeEvidenceRecordV1 {
  recordVersion: 1;
  action: ActionEnvelopeV1;
  capability: ActionCapabilityV1;
  evidence: ActionEvidenceV1;
}

export interface EvidenceSink {
  append(record: RuntimeEvidenceRecordV1): Promise<void>;
}

export type CapabilityResolver = (
  action: ActionEnvelopeV1,
) => ActionCapabilityV1 | Promise<ActionCapabilityV1>;

export interface BesaRuntimeConfig {
  trustStore: TrustStore;
  capability: ActionCapabilityV1 | CapabilityResolver;
  replayStore: ReplayStore;
  replayRequirement: "detect-only" | "enforce";
  evidenceKeyPair: KeyPair;
  evidenceSink: EvidenceSink;
  recorderId: string;
  executorId: string;
  delegationChain?: DelegationV1[];
  delegationTrustStore?: TrustStore;
  requireDelegation?: boolean;
  clock?: () => Date;
}

export interface BesaExecutionResult<TResult> {
  result: TResult;
  capability: ActionCapabilityV1;
  evidence: ActionEvidenceV1;
  replay: ReplayConsumeResult;
}

interface RuntimeErrorOptions {
  cause?: unknown;
  capability?: ActionCapabilityV1;
  evidence?: ActionEvidenceV1;
}

export class BesaRuntimeError extends Error {
  readonly reasonCode: string;
  readonly capability?: ActionCapabilityV1;
  readonly evidence?: ActionEvidenceV1;

  constructor(reasonCode: string, message: string, options: RuntimeErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "BesaRuntimeError";
    this.reasonCode = reasonCode;
    this.capability = options.capability;
    this.evidence = options.evidence;
  }
}

const MAX_LOG_RECORD_BYTES = 1_048_576;

export class AppendOnlyEvidenceLog implements EvidenceSink {
  readonly path: string;
  #tail: Promise<void> = Promise.resolve();

  constructor(path: string) {
    if (path.trim().length === 0) {
      throw new TypeError("evidence log path must not be empty");
    }
    this.path = resolve(path);
  }

  append(record: RuntimeEvidenceRecordV1): Promise<void> {
    const operation = this.#tail.then(() => this.#appendRecord(record));
    this.#tail = operation.catch(() => undefined);
    return operation;
  }

  async #appendRecord(record: RuntimeEvidenceRecordV1): Promise<void> {
    const line = `${canonicalize(record)}\n`;
    const bytes = Buffer.byteLength(line, "utf8");
    if (bytes > MAX_LOG_RECORD_BYTES) {
      throw new TypeError("evidence log record exceeds the 1048576 byte limit");
    }

    try {
      const existing = await lstat(this.path);
      if (existing.isSymbolicLink() || !existing.isFile()) {
        throw new Error("evidence log path must be a regular non-symlink file");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }

    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    const handle = await open(
      this.path,
      constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | noFollow,
      0o600,
    );
    try {
      const opened = await handle.stat();
      if (!opened.isFile()) {
        throw new Error("evidence log handle is not a regular file");
      }
      await handle.writeFile(line, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
}

function runtimeDate(clock: () => Date): Date {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new BesaRuntimeError("RUNTIME_CLOCK_INVALID", "runtime clock returned an invalid date");
  }
  return new Date(value);
}

function isRuntimeId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    value === value.trim() &&
    value === value.normalize("NFC") &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function verifyRuntimeDelegation(
  config: BesaRuntimeConfig,
  action: ActionEnvelopeV1,
  capability: ActionCapabilityV1,
  at: Date,
): void {
  const chain = config.delegationChain;
  if (!chain || chain.length === 0) {
    if (config.requireDelegation || capability.delegationChainHash !== null) {
      throw new BesaRuntimeError(
        "DELEGATION_REQUIRED",
        "the action capability requires verifiable delegation evidence",
        { capability },
      );
    }
    return;
  }

  const verification = verifyActionDelegation(
    chain,
    action,
    config.delegationTrustStore ?? config.trustStore,
    at,
  );
  if (!verification.valid || !verification.leaf || !verification.chainHash) {
    throw new BesaRuntimeError(
      verification.reasonCode,
      verification.detail,
      { capability },
    );
  }
  if (capability.delegationChainHash !== verification.chainHash) {
    throw new BesaRuntimeError(
      "DELEGATION_PARENT_MISMATCH",
      "capability delegationChainHash does not match the verified chain",
      { capability },
    );
  }
}

async function appendEvidence(
  sink: EvidenceSink,
  record: RuntimeEvidenceRecordV1,
): Promise<void> {
  try {
    await sink.append(record);
  } catch (error) {
    throw new BesaRuntimeError(
      "EVIDENCE_RECORD_FAILED",
      "execution completed but signed evidence could not be appended",
      {
        cause: error,
        capability: record.capability,
        evidence: record.evidence,
      },
    );
  }
}

export function withBesa<TResult>(
  config: BesaRuntimeConfig,
  handler: (action: ActionEnvelopeV1) => TResult | Promise<TResult>,
): (action: ActionEnvelopeV1) => Promise<BesaExecutionResult<TResult>> {
  if (!config || typeof config !== "object") {
    throw new TypeError("runtime config must be an object");
  }
  if (typeof handler !== "function") {
    throw new TypeError("handler must be a function");
  }
  if (!validateKeyPair(config.evidenceKeyPair)) {
    throw new TypeError("evidenceKeyPair must be a valid Ed25519 key pair");
  }
  if (!config.evidenceSink || typeof config.evidenceSink.append !== "function") {
    throw new TypeError("evidenceSink must implement append(record)");
  }
  if (
    !config.replayStore ||
    typeof config.replayStore.consume !== "function" ||
    (config.replayStore.mode !== "verification-only" &&
      config.replayStore.mode !== "enforced")
  ) {
    throw new TypeError("replayStore must implement a declared replay mode and consume()");
  }
  if (
    config.replayRequirement !== "detect-only" &&
    config.replayRequirement !== "enforce"
  ) {
    throw new TypeError("replayRequirement must be detect-only or enforce");
  }
  if (!isRuntimeId(config.recorderId) || !isRuntimeId(config.executorId)) {
    throw new TypeError("recorderId and executorId must be bounded NFC text without controls");
  }
  if (config.clock !== undefined && typeof config.clock !== "function") {
    throw new TypeError("clock must be a function when supplied");
  }
  if (
    config.requireDelegation !== undefined &&
    typeof config.requireDelegation !== "boolean"
  ) {
    throw new TypeError("requireDelegation must be boolean when supplied");
  }

  const clock = config.clock ?? (() => new Date());

  return async (actionValue: ActionEnvelopeV1): Promise<BesaExecutionResult<TResult>> => {
    const receivedAt = runtimeDate(clock);
    const actionCheck = checkActionEnvelope(actionValue, receivedAt);
    if (!actionCheck.valid || !actionCheck.action || !actionCheck.actionHash) {
      throw new BesaRuntimeError(actionCheck.reasonCode, actionCheck.detail);
    }
    const action = actionCheck.action;

    let capabilityValue: ActionCapabilityV1;
    try {
      capabilityValue =
        typeof config.capability === "function"
          ? await config.capability(action)
          : config.capability;
    } catch (error) {
      throw new BesaRuntimeError(
        "CAPABILITY_RESOLUTION_FAILED",
        "action capability could not be resolved",
        { cause: error },
      );
    }

    const admittedAt = runtimeDate(clock);
    const capabilityCheck = verifyActionCapability(
      capabilityValue,
      action,
      config.trustStore,
      admittedAt,
    );
    if (!capabilityCheck.valid || !capabilityCheck.capability) {
      throw new BesaRuntimeError(
        capabilityCheck.reasonCode,
        capabilityCheck.detail,
      );
    }
    const capability = capabilityCheck.capability;
    if (!capabilityCheck.authorized) {
      throw new BesaRuntimeError(
        capability.reasonCode,
        "signed action capability denies execution",
        { capability },
      );
    }

    verifyRuntimeDelegation(config, action, capability, admittedAt);

    if (config.replayRequirement === "enforce" && config.replayStore.mode !== "enforced") {
      throw new BesaRuntimeError(
        REPLAY_REASON.UNAVAILABLE,
        "configured replay guarantee requires an enforced atomic replay store",
        { capability },
      );
    }

    let replay: ReplayConsumeResult;
    try {
      replay = await config.replayStore.consume(
        replayKey(actionCheck.actionHash, action.nonce),
        action.expiresAt,
        admittedAt,
      );
    } catch (error) {
      throw new BesaRuntimeError(
        REPLAY_REASON.UNAVAILABLE,
        "replay store failed while consuming the action nonce",
        { cause: error, capability },
      );
    }
    if (replay.status === "replay" || replay.status === "unavailable") {
      throw new BesaRuntimeError(replay.reasonCode, replay.detail, { capability });
    }
    if (config.replayRequirement === "enforce" && replay.status !== "consumed") {
      throw new BesaRuntimeError(
        REPLAY_REASON.UNAVAILABLE,
        "replay store did not provide enforced one-time consumption",
        { capability },
      );
    }

    const started = runtimeDate(clock);
    const executionCapabilityCheck = verifyActionCapability(
      capability,
      action,
      config.trustStore,
      started,
    );
    if (!executionCapabilityCheck.valid || !executionCapabilityCheck.capability) {
      throw new BesaRuntimeError(
        executionCapabilityCheck.reasonCode,
        executionCapabilityCheck.detail,
        { capability },
      );
    }
    if (!executionCapabilityCheck.authorized) {
      throw new BesaRuntimeError(
        capability.reasonCode,
        "signed action capability denies execution",
        { capability },
      );
    }
    verifyRuntimeDelegation(config, action, capability, started);

    let result: TResult;
    try {
      result = await handler(action);
    } catch (error) {
      let evidence: ActionEvidenceV1;
      try {
        const completed = runtimeDate(clock);
        const recorded = runtimeDate(clock);
        const failure = {
          errorType: error instanceof Error ? error.name : "ThrownValue",
        };
        evidence = createActionEvidence(
          {
            action,
            capability,
            result: failure,
            outcome: "failed",
            executorId: config.executorId,
            recorderId: config.recorderId,
            receiptHash: null,
            startedAt: started.toISOString(),
            completedAt: completed.toISOString(),
            recordedAt: recorded.toISOString(),
          },
          config.evidenceKeyPair,
        );
      } catch (evidenceError) {
        throw new BesaRuntimeError(
          "EVIDENCE_CREATION_FAILED",
          "guarded action failed and signed failure evidence could not be created",
          {
            cause: new AggregateError(
              [error, evidenceError],
              "handler and failure-evidence creation both failed",
            ),
            capability,
          },
        );
      }
      await appendEvidence(config.evidenceSink, {
        recordVersion: 1,
        action,
        capability,
        evidence,
      });
      throw new BesaRuntimeError(
        "ACTION_HANDLER_FAILED",
        "guarded action handler failed after admission",
        { cause: error, capability, evidence },
      );
    }

    let evidence: ActionEvidenceV1;
    try {
      const completed = runtimeDate(clock);
      const recorded = runtimeDate(clock);
      evidence = createActionEvidence(
        {
          action,
          capability,
          result,
          outcome: "succeeded",
          executorId: config.executorId,
          recorderId: config.recorderId,
          receiptHash: null,
          startedAt: started.toISOString(),
          completedAt: completed.toISOString(),
          recordedAt: recorded.toISOString(),
        },
        config.evidenceKeyPair,
      );
    } catch (error) {
      throw new BesaRuntimeError(
        "EVIDENCE_CREATION_FAILED",
        "guarded action succeeded but signed evidence could not be created",
        {
          cause: error,
          capability,
        },
      );
    }
    await appendEvidence(config.evidenceSink, {
      recordVersion: 1,
      action,
      capability,
      evidence,
    });
    return { result, capability, evidence, replay };
  };
}
