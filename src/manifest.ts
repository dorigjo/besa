import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import type { CapabilityType, Manifest, RiskLevel } from "./types.js";

const CAPABILITIES: CapabilityType[] = ["read", "write", "destructive"];
const RISKS: RiskLevel[] = ["low", "medium", "high"];

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

export function validateManifest(raw: unknown): ValidationResult {
const errors: string[] = [];

if (!isObject(raw)) {
return {
ok: false,
errors: ["manifest must be an object"]
};
}

for (const field of ["serverName", "serverVersion", "serverUrl", "createdAt"]) {
if (!isNonEmptyString(raw[field])) {
errors.push(`${field} must be a non-empty string`);
}
}

if (!Array.isArray(raw.tools) || raw.tools.length === 0) {
errors.push("tools must be a non-empty array");
} else {
raw.tools.forEach((tool, index) => validateTool(tool, index, errors));
}

if (errors.length > 0) {
return {
ok: false,
errors
};
}

return {
ok: true,
manifest: raw as unknown as Manifest,
errors: []
};
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

if (!Array.isArray(tool.scopes) || !tool.scopes.every((scope) => typeof scope === "string")) {
errors.push(`${path}.scopes must be an array of strings`);
}

if (
typeof tool.budgetLimit !== "number" ||
!Number.isInteger(tool.budgetLimit) ||
tool.budgetLimit < 0
) {
errors.push(`${path}.budgetLimit must be a non-negative integer`);
}

if (!isObject(tool.inputSchema)) {
errors.push(`${path}.inputSchema must be an object`);
}
}

export function loadManifest(path: string): Manifest {
const source = readFileSync(path, "utf8");
const raw = extname(path).toLowerCase() === ".json" ? JSON.parse(source) : parseYaml(source);
const result = validateManifest(raw);

if (!result.ok || !result.manifest) {
throw new Error(`Invalid manifest:\n  - ${result.errors.join("\n  - ")}`);
}

return result.manifest;
}