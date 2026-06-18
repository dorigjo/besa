import { parentPort, workerData } from "node:worker_threads";
import { admitAndConsume, type Manifest } from "../sdk.js";

interface MeterWorkerInput {
  path: string;
  manifestHash: string;
  manifest: Manifest;
  toolName: string;
  attempts: number;
}

const input = workerData as MeterWorkerInput;
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

parentPort?.postMessage(allowed);
