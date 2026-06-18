import { randomUUID } from "node:crypto";
import { dirname } from "node:path";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import type { AdmissionDecision, Manifest, ToolDefinition } from "./types.js";

export const REASON = {
  ALLOWED: "ALLOWED",
  TOOL_NOT_FOUND: "TOOL_NOT_FOUND",
  RISK_BLOCKED: "RISK_BLOCKED",
  BUDGET_EXCEEDED: "BUDGET_EXCEEDED",
} as const;

export interface AdmissionPolicy {
  denyDestructiveHighRisk: boolean;
}

export const DEFAULT_POLICY: AdmissionPolicy = {
  denyDestructiveHighRisk: true,
};

export type MeterState = Record<string, number>;

export interface MeterLockOptions {
  timeoutMs?: number;
  staleMs?: number;
  retryMs?: number;
}

export function findTool(manifest: Manifest, toolName: string): ToolDefinition | undefined {
  return manifest.tools.find((tool) => tool.name === toolName);
}

export function admit(
  manifest: Manifest,
  toolName: string,
  callCount: number,
  policy: AdmissionPolicy = DEFAULT_POLICY,
): AdmissionDecision {
  const tool = findTool(manifest, toolName);

  if (!tool) {
    return deny(
      toolName,
      REASON.TOOL_NOT_FOUND,
      `tool '${toolName}' is not declared in the manifest`,
    );
  }

  if (
    policy.denyDestructiveHighRisk &&
    tool.capability === "destructive" &&
    tool.risk === "high"
  ) {
    return deny(
      toolName,
      REASON.RISK_BLOCKED,
      "destructive high-risk tool is blocked by policy",
    );
  }

  if (callCount >= tool.budgetLimit) {
    return deny(
      toolName,
      REASON.BUDGET_EXCEEDED,
      `call count ${callCount} has reached budget limit ${tool.budgetLimit}`,
    );
  }

  return {
    decision: "allow",
    reasonCode: REASON.ALLOWED,
    toolName,
    detail: "tool call admitted",
  };
}

function deny(toolName: string, reasonCode: string, detail: string): AdmissionDecision {
  return {
    decision: "deny",
    reasonCode,
    toolName,
    detail,
  };
}

export function meterKey(manifestHash: string, toolName: string): string {
  return `${manifestHash}:${toolName}`;
}

export function loadMeter(path: string): MeterState {
  if (!existsSync(path)) {
    return {};
  }

  let raw: unknown;

  try {
    raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`invalid meter state at ${path}: ${message}`);
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`invalid meter state at ${path}: expected a JSON object`);
  }

  const state: MeterState = {};

  for (const [key, value] of Object.entries(raw)) {
    if (
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < 0
    ) {
      throw new Error(
        `invalid meter state at ${path}: '${key}' must be a safe non-negative integer`,
      );
    }

    state[key] = value;
  }

  return state;
}

export function saveMeter(path: string, state: MeterState): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${String(process.pid)}.${randomUUID()}.tmp`;

  try {
    writeFileSync(temporaryPath, JSON.stringify(state, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    renameSync(temporaryPath, path);
  } finally {
    if (existsSync(temporaryPath)) {
      unlinkSync(temporaryPath);
    }
  }
}

export function getCount(state: MeterState, key: string): number {
  return state[key] ?? 0;
}

export function increment(state: MeterState, key: string): MeterState {
  return {
    ...state,
    [key]: getCount(state, key) + 1,
  };
}

function sleep(milliseconds: number): void {
  const signal = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(signal, 0, 0, milliseconds);
}

function acquireMeterLock(
  path: string,
  options: MeterLockOptions,
): () => void {
  const lockPath = `${path}.lock`;
  const timeoutMs = options.timeoutMs ?? 5_000;
  const staleMs = options.staleMs ?? 30_000;
  const retryMs = options.retryMs ?? 10;
  const startedAt = Date.now();

  mkdirSync(dirname(path), { recursive: true });

  while (true) {
    try {
      const descriptor = openSync(lockPath, "wx", 0o600);
      try {
        writeFileSync(
          descriptor,
          JSON.stringify({
            pid: process.pid,
            createdAt: new Date().toISOString(),
          }) + "\n",
          "utf8",
        );
      } catch (error) {
        closeSync(descriptor);
        unlinkSync(lockPath);
        throw error;
      }

      return () => {
        closeSync(descriptor);
        try {
          unlinkSync(lockPath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw error;
          }
        }
      };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;

      if (code !== "EEXIST") {
        throw error;
      }

      try {
        if (Date.now() - statSync(lockPath).mtimeMs > staleMs) {
          const stalePath = `${lockPath}.${String(process.pid)}.${randomUUID()}.stale`;
          renameSync(lockPath, stalePath);
          unlinkSync(stalePath);
          continue;
        }
      } catch (statError) {
        if ((statError as NodeJS.ErrnoException).code === "ENOENT") {
          continue;
        }
        throw statError;
      }

      if (Date.now() - startedAt >= timeoutMs) {
        throw new Error(`timed out waiting for meter lock at ${lockPath}`);
      }

      sleep(retryMs);
    }
  }
}

export function admitAndConsume(
  path: string,
  manifestHash: string,
  manifest: Manifest,
  toolName: string,
  policy: AdmissionPolicy = DEFAULT_POLICY,
  lockOptions: MeterLockOptions = {},
): AdmissionDecision {
  const release = acquireMeterLock(path, lockOptions);

  try {
    const state = loadMeter(path);
    const key = meterKey(manifestHash, toolName);
    const decision = admit(manifest, toolName, getCount(state, key), policy);

    if (decision.decision === "allow") {
      saveMeter(path, increment(state, key));
    }

    return decision;
  } finally {
    release();
  }
}
