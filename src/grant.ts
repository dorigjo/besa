import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Grant, GrantDecision, GrantSet } from "./types.js";

export const GRANT_REASON = {
  GRANTED: "GRANT_OK",
  AGENT_NOT_FOUND: "AGENT_NOT_FOUND",
  TOOL_NOT_GRANTED: "TOOL_NOT_GRANTED",
} as const;

export interface GrantValidationResult {
  ok: boolean;
  grantSet?: GrantSet;
  errors: string[];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

export function validateGrantSet(raw: unknown): GrantValidationResult {
  const errors: string[] = [];

  if (!isObject(raw)) {
    return {
      ok: false,
      errors: ["grant set must be an object"],
    };
  }

  if (!Array.isArray(raw.grants) || raw.grants.length === 0) {
    errors.push("grants must be a non-empty array");
  } else {
    const seenAgents = new Set<string>();

    raw.grants.forEach((grant, index) => {
      const path = `grants[${index}]`;

      if (!isObject(grant)) {
        errors.push(`${path} must be an object`);
        return;
      }

      if (!isNonEmptyString(grant.agentId)) {
        errors.push(`${path}.agentId must be a non-empty string`);
      } else if (seenAgents.has(grant.agentId)) {
        errors.push(`${path}.agentId must be unique`);
      } else {
        seenAgents.add(grant.agentId);
      }

      if (
        !Array.isArray(grant.tools) ||
        grant.tools.length === 0 ||
        !grant.tools.every((tool) => isNonEmptyString(tool))
      ) {
        errors.push(`${path}.tools must be a non-empty array of non-empty strings`);
      }
    });
  }

  if (errors.length > 0) {
    return {
      ok: false,
      errors,
    };
  }

  return {
    ok: true,
    grantSet: raw as unknown as GrantSet,
    errors: [],
  };
}

export function loadGrants(path: string): GrantSet {
  const source = readFileSync(path, "utf8");
  const raw =
    extname(path).toLowerCase() === ".json" ? JSON.parse(source) : parseYaml(source);

  const result = validateGrantSet(raw);

  if (!result.ok || !result.grantSet) {
    throw new Error(`Invalid grant set:\n  - ${result.errors.join("\n  - ")}`);
  }

  return result.grantSet;
}

export function findGrant(grantSet: GrantSet, agentId: string): Grant | undefined {
  return grantSet.grants.find((grant) => grant.agentId === agentId);
}

export function checkGrant(
  grantSet: GrantSet,
  agentId: string,
  toolName: string,
): GrantDecision {
  const grant = findGrant(grantSet, agentId);

  if (!grant) {
    return {
      granted: false,
      reasonCode: GRANT_REASON.AGENT_NOT_FOUND,
      agentId,
      toolName,
      detail: `no grant found for agent '${agentId}'`,
    };
  }

  if (!grant.tools.includes(toolName)) {
    return {
      granted: false,
      reasonCode: GRANT_REASON.TOOL_NOT_GRANTED,
      agentId,
      toolName,
      detail: `agent '${agentId}' is not granted tool '${toolName}'`,
    };
  }

  return {
    granted: true,
    reasonCode: GRANT_REASON.GRANTED,
    agentId,
    toolName,
    detail: `agent '${agentId}' is granted tool '${toolName}'`,
  };
}
