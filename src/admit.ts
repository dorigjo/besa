import { dirname } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
  writeFileSync(path, JSON.stringify(state, null, 2) + "\n", "utf8");
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
