import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Grant, GrantDecision, GrantSet } from "./types.js";
import { canonicalize } from "./crypto.js";
import { readUtf8File } from "./io.js";

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

const MAX_GRANTS = 256;
const MAX_TOOLS_PER_GRANT = 256;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 256 &&
    value.trim().length > 0 &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

export function validateGrantSet(raw: unknown): GrantValidationResult {
  const errors: string[] = [];

  if (!isObject(raw)) {
    return {
      ok: false,
      errors: ["grant set must be an object"],
    };
  }

  for (const field of Object.keys(raw)) {
    if (field !== "grants") {
      errors.push(`unexpected grant set field '${field}'`);
    }
  }

  if (!Array.isArray(raw.grants) || raw.grants.length === 0) {
    errors.push("grants must be a non-empty array");
  } else if (raw.grants.length > MAX_GRANTS) {
    errors.push(`grants must contain at most ${String(MAX_GRANTS)} entries`);
  } else {
    const seenAgents = new Set<string>();

    raw.grants.forEach((grant, index) => {
      const path = `grants[${index}]`;

      if (!isObject(grant)) {
        errors.push(`${path} must be an object`);
        return;
      }

      for (const field of Object.keys(grant)) {
        if (field !== "agentId" && field !== "tools") {
          errors.push(`unexpected ${path} field '${field}'`);
        }
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
        grant.tools.length > MAX_TOOLS_PER_GRANT ||
        !grant.tools.every((tool) => isNonEmptyString(tool))
      ) {
        errors.push(`${path}.tools must contain 1-${String(MAX_TOOLS_PER_GRANT)} valid tool names`);
      } else if (new Set(grant.tools).size !== grant.tools.length) {
        errors.push(`${path}.tools must not contain duplicate tool names`);
      }
    });
  }

  try {
    canonicalize(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push(`grant set must contain only bounded JSON values: ${message}`);
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
  const source = readUtf8File(path);
  const extension = extname(path).toLowerCase();
  let raw: unknown;

  if (extension === ".json") {
    raw = JSON.parse(source) as unknown;
  } else if (extension === ".yaml" || extension === ".yml") {
    raw = parseYaml(source, {
      maxAliasCount: 50,
      strict: true,
      uniqueKeys: true,
    });
  } else {
    throw new Error("grant path must end in .json, .yaml, or .yml");
  }

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
