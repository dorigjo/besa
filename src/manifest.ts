import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import type { CapabilityType, Manifest, RiskLevel } from "./types.js";

const CAPABILITIES: CapabilityType[] = ["read", "write", "destructive"];
const RISKS: RiskLevel[] = ["low", "medium", "high"];
const ISO_DATE =
/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export interface ValidationResult {
ok: boolean;
manifest?: Manifest;
errors: string[];
}

function isObject(value: unknown): value is Record<string, unknown> {
return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
return typeof value === "string" && value.trim().length > 0;
}

function isHttpUrl(value: unknown): boolean {
if (typeof value !== "string") return false;

try {
const url = new URL(value);
return url.protocol === "http:" || url.protocol === "https:";
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

if (!isNonEmptyString(raw.serverName)) {
errors.push("serverName must be a non-empty string");
}

if (!isNonEmptyString(raw.serverVersion)) {
errors.push("serverVersion must be a non-empty string");
}

if (!isHttpUrl(raw.serverUrl)) {
errors.push("serverUrl must be a valid http(s) URL");
}

if (!isIsoDate(raw.createdAt)) {
errors.push("createdAt must be a valid ISO-8601 date-time");
}

if (!Array.isArray(raw.tools) || raw.tools.length === 0) {
errors.push("tools must be a non-empty array");
} else {
const seen = new Set<string>();

raw.tools.forEach((tool, index) => {
  validateTool(tool, index, errors);

  if (isObject(tool) && typeof tool.name === "string") {
    if (seen.has(tool.name)) {
      errors.push(`tools[${index}].name '${tool.name}' is a duplicate tool name`);
    }

    seen.add(tool.name);
  }
});

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

if (!isNonEmptyString(tool.name)) {
errors.push(`${path}.name must be a non-empty string`);
}

if (typeof tool.description !== "string") {
errors.push(`${path}.description must be a string`);
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
!tool.scopes.every((scope) => isNonEmptyString(scope))
) {
errors.push(`${path}.scopes must be a non-empty array of non-empty strings`);
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
const source = readFileSync(path, "utf8");
const raw = extname(path) === ".json" ? JSON.parse(source) : parseYaml(source);
const result = validateManifest(raw);

if (!result.ok || !result.manifest) {
throw new Error(`Invalid manifest:\n  - ${result.errors.join("\n  - ")}`);
}

return result.manifest;
}