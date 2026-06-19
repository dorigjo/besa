import { randomUUID } from "node:crypto";
import { dirname } from "node:path";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import type { AdmissionDecision, Manifest, ToolDefinition } from "./types.js";
import { validateManifest } from "./manifest.js";
import { readJsonFile, writeJsonAtomic } from "./io.js";

export const REASON = {
  ALLOWED: "ALLOWED",
  TOOL_NOT_FOUND: "TOOL_NOT_FOUND",
  RISK_BLOCKED: "RISK_BLOCKED",
  BUDGET_EXCEEDED: "BUDGET_EXCEEDED",
  INVALID_MANIFEST: "INVALID_MANIFEST",
  INVALID_TOOL_NAME: "INVALID_TOOL_NAME",
  INVALID_CALL_COUNT: "INVALID_CALL_COUNT",
  INVALID_POLICY: "INVALID_POLICY",
} as const;

const SHA256_HEX = /^[a-f0-9]{64}$/;
const TOOL_NAME_RE = /^[a-zA-Z0-9._-]{1,256}$/;

function isValidToolName(name: unknown): name is string {
  return typeof name === "string" && TOOL_NAME_RE.test(name);
}

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
  if (!isValidToolName(toolName)) {
    return deny("", REASON.INVALID_TOOL_NAME, "tool name is invalid");
  }

  if (!Number.isSafeInteger(callCount) || callCount < 0) {
    return deny(
      toolName,
      REASON.INVALID_CALL_COUNT,
      "call count must be a safe non-negative integer",
    );
  }

  if (
    !policy ||
    typeof policy !== "object" ||
    policy.denyDestructiveHighRisk !== true &&
      policy.denyDestructiveHighRisk !== false
  ) {
    return deny(toolName, REASON.INVALID_POLICY, "admission policy is invalid");
  }

  const manifestValidation = validateManifest(manifest);
  if (!manifestValidation.ok) {
    return deny(
      toolName,
      REASON.INVALID_MANIFEST,
      "manifest failed runtime validation",
    );
  }

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
  if (!SHA256_HEX.test(manifestHash)) {
    throw new Error("manifestHash must be a lowercase SHA-256 hex digest");
  }
  if (!isValidToolName(toolName)) {
    throw new Error("toolName is invalid");
  }
  return `${manifestHash}:${toolName}`;
}

export function loadMeter(path: string): MeterState {
  if (!existsSync(path)) {
    return {};
  }

  let raw: unknown;

  try {
    raw = readJsonFile(path);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`invalid meter state at ${path}: ${message}`);
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`invalid meter state at ${path}: expected a JSON object`);
  }

  const state = Object.create(null) as MeterState;

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
  writeJsonAtomic(path, state, 0o600);
}

export function getCount(state: MeterState, key: string): number {
  return state[key] ?? 0;
}

export function increment(state: MeterState, key: string): MeterState {
  const count = getCount(state, key);
  if (!Number.isSafeInteger(count) || count < 0 || count === Number.MAX_SAFE_INTEGER) {
    throw new Error(`meter count for '${key}' cannot be incremented safely`);
  }

  return Object.assign(Object.create(null) as MeterState, state, {
    [key]: count + 1,
  });
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

  if (
    !Number.isFinite(timeoutMs) ||
    !Number.isFinite(staleMs) ||
    !Number.isFinite(retryMs) ||
    timeoutMs < 0 ||
    staleMs <= 0 ||
    retryMs <= 0
  ) {
    throw new Error("meter lock timings must be positive");
  }

  mkdirSync(dirname(path), { recursive: true });

  while (true) {
    try {
      const descriptor = openSync(lockPath, "wx", 0o600);
      const token = randomUUID();
      try {
        writeFileSync(
          descriptor,
          JSON.stringify({
            pid: process.pid,
            token,
            createdAt: new Date().toISOString(),
          }) + "\n",
          "utf8",
        );
        fsyncSync(descriptor);
      } catch (error) {
        closeSync(descriptor);
        unlinkSync(lockPath);
        throw error;
      }

      return () => {
        closeSync(descriptor);
        try {
          const lock = readJsonFile(lockPath) as { token?: unknown };
          if (lock.token === token) {
            unlinkSync(lockPath);
          }
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
        if (
          Date.now() - statSync(lockPath).mtimeMs > staleMs &&
          !lockOwnerIsAlive(lockPath)
        ) {
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

function lockOwnerIsAlive(lockPath: string): boolean {
  try {
    const value = readJsonFile(lockPath);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }

    const pid = (value as Record<string, unknown>).pid;
    if (!Number.isSafeInteger(pid) || (pid as number) <= 0) {
      return false;
    }

    try {
      process.kill(pid as number, 0);
      return true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return code !== "ESRCH";
    }
  } catch {
    return false;
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
