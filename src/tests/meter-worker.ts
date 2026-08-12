import { parentPort, workerData } from "node:worker_threads";
import { admitAndConsume, type Manifest } from "../sdk.js";

interface MeterWorkerInput {
  path: string;
  manifestHash: string;
  manifest: Manifest;
  toolName: string;
  attempts: number;
}

export type MeterWorkerResult =
  | { ok: true; allowed: number }
  | { ok: false; error: string };

const input = workerData as MeterWorkerInput;

function consume(): number {
  let allowed = 0;

  for (let attempt = 0; attempt < input.attempts; attempt += 1) {
    const decision = admitAndConsume(
      input.path,
      input.manifestHash,
      input.manifest,
      input.toolName,
    );

    if (decision.decision === "allow") {
      allowed += 1;
    }
  }

  return allowed;
}

// Surface every failure explicitly as a structured message instead of letting an
// uncaught throw race the worker "error"/"exit" events. The parent asserts on
// the discriminated result, so no worker failure is ever silently swallowed.
try {
  const result: MeterWorkerResult = { ok: true, allowed: consume() };
  parentPort?.postMessage(result);
} catch (error) {
  const detail =
    error instanceof Error
      ? `${error.message}\n${error.stack ?? ""}`
      : String(error);
  const result: MeterWorkerResult = { ok: false, error: detail };
  parentPort?.postMessage(result);
}
