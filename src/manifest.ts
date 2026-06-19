import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import type { CapabilityType, Manifest, RiskLevel } from "./types.js";
import { canonicalize } from "./crypto.js";
import { readUtf8File } from "./io.js";

const CAPABILITIES: CapabilityType[] = ["read", "write", "destructive"];
const RISKS: RiskLevel[] = ["low", "medium", "high"];
const ISO_DATE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const MANIFEST_FIELDS = new Set([
  "serverName",
  "serverVersion",
  "serverUrl",
  "createdAt",
  "tools",
]);
const TOOL_FIELDS = new Set([
  "name",
  "description",
  "capability",
  "risk",
  "scopes",
  "budgetLimit",
  "inputSchema",
]);
const MAX_TOOLS = 256;
const MAX_SCOPES = 64;
const TOOL_NAME_RE = /^[a-zA-Z0-9._-]{1,256}$/;

export interface ValidationResult {
  ok: boolean;
  manifest?: Manifest;
  errors: string[];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown, maximumLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length <= maximumLength &&
    value.trim().length > 0 &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function isHttpUrl(value: unknown): boolean {
  if (typeof value !== "string") return false;

  try {
    const url = new URL(value);
    const isLoopback =
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]";
    return (
      value.length <= 2_048 &&
      (url.protocol === "https:" || (url.protocol === "http:" && isLoopback)) &&
      url.username === "" &&
      url.password === "" &&
      url.hash === ""
    );
  } catch {
    return false;
  }
}

function isIsoDate(value: unknown): boolean {
  return (
    typeof value === "string" &&
    ISO_DATE.test(value) &&
    !Number.isNaN(Date.parse(value))
  );
}

export function validateManifest(raw: unknown): ValidationResult {
  const errors: string[] = [];

  if (!isObject(raw)) {
    return { ok: false, errors: ["manifest must be an object"] };
  }

  for (const field of Object.keys(raw)) {
    if (!MANIFEST_FIELDS.has(field)) {
      errors.push(`unexpected manifest field '${field}'`);
    }
  }

  if (!isNonEmptyString(raw.serverName, 128)) {
    errors.push("serverName must be a non-empty string of at most 128 characters");
  }

  if (!isNonEmptyString(raw.serverVersion, 64)) {
    errors.push("serverVersion must be a non-empty string of at most 64 characters");
  }

  if (!isHttpUrl(raw.serverUrl)) {
    errors.push("serverUrl must be a valid http(s) URL");
  }

  if (!isIsoDate(raw.createdAt)) {
    errors.push("createdAt must be a valid ISO-8601 date-time");
  }

  if (!Array.isArray(raw.tools) || raw.tools.length === 0) {
    errors.push("tools must be a non-empty array");
  } else if (raw.tools.length > MAX_TOOLS) {
    errors.push(`tools must contain at most ${String(MAX_TOOLS)} entries`);
  } else {
    const seen = new Set<string>();

    raw.tools.forEach((tool, index) => {
      validateTool(tool, index, errors);

      if (isObject(tool) && typeof tool.name === "string") {
        if (seen.has(tool.name)) {
          errors.push(
            `tools[${index}].name '${tool.name}' is a duplicate tool name`,
          );
        }

        seen.add(tool.name);
      }
    });
  }

  try {
    canonicalize(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push(`manifest must contain only JSON values: ${message}`);
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return { ok: true, manifest: raw as unknown as Manifest, errors: [] };
}

function validateTool(tool: unknown, index: number, errors: string[]): void {
  const path = `tools[${index}]`;

  if (!isObject(tool)) {
    errors.push(`${path} must be an object`);
    return;
  }

  for (const field of Object.keys(tool)) {
    if (!TOOL_FIELDS.has(field)) {
      errors.push(`unexpected ${path} field '${field}'`);
    }
  }

  if (typeof tool.name !== "string" || !TOOL_NAME_RE.test(tool.name)) {
    errors.push(`${path}.name must contain only ASCII letters, digits, dots, underscores, and hyphens (1-256 characters)`);
  }

  if (typeof tool.description !== "string" || tool.description.length > 4_096) {
    errors.push(`${path}.description must be a string of at most 4096 characters`);
  }

  if (!CAPABILITIES.includes(tool.capability as CapabilityType)) {
    errors.push(`${path}.capability must be one of ${CAPABILITIES.join(", ")}`);
  }

  if (!RISKS.includes(tool.risk as RiskLevel)) {
    errors.push(`${path}.risk must be one of ${RISKS.join(", ")}`);
  }

  if (
    !Array.isArray(tool.scopes) ||
    tool.scopes.length === 0 ||
    tool.scopes.length > MAX_SCOPES ||
    !tool.scopes.every((scope) => isNonEmptyString(scope, 256))
  ) {
    errors.push(`${path}.scopes must contain 1-${String(MAX_SCOPES)} non-empty strings of at most 256 characters`);
  }

  if (
    typeof tool.budgetLimit !== "number" ||
    !Number.isSafeInteger(tool.budgetLimit) ||
    tool.budgetLimit < 0
  ) {
    errors.push(`${path}.budgetLimit must be a safe non-negative integer`);
  }

  if (!isObject(tool.inputSchema)) {
    errors.push(`${path}.inputSchema must be an object`);
  }
}

export function loadManifest(path: string): Manifest {
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
    throw new Error("manifest path must end in .json, .yaml, or .yml");
  }
  const result = validateManifest(raw);

  if (!result.ok || !result.manifest) {
    throw new Error(`Invalid manifest:\n  - ${result.errors.join("\n  - ")}`);
  }

  return result.manifest;
}
