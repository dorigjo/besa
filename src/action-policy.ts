import { canonicalize } from "./crypto.js";
import {
  checkActionEnvelope,
  type ActionEnvelopeV1,
  type JsonObject,
  type JsonValue,
} from "./action.js";
import type { DelegationConstraintsV1 } from "./delegation.js";
import type { Decision, RiskLevel } from "./types.js";

export interface ActionPolicyRuleV1 {
  ruleId: string;
  principals: string[];
  agents: string[];
  tools: string[];
  operations: string[];
  resources: string[];
  allowedScopes: string[];
  maxRisk: RiskLevel;
  constraints: DelegationConstraintsV1;
}

export interface ActionPolicyV1 {
  version: 1;
  policyId: string;
  delegationRequired: boolean;
  rules: ActionPolicyRuleV1[];
}

export interface ActionPolicyValidationResult {
  ok: boolean;
  policy?: ActionPolicyV1;
  errors: string[];
}

export interface ActionPolicyDecision {
  decision: Decision;
  reasonCode: string;
  detail: string;
  policyId: string;
  matchedRuleId?: string;
  delegationRequired: boolean;
}

export const ACTION_POLICY_REASON = {
  ALLOWED: "ACTION_ALLOWED",
  ACTION_INVALID: "SCHEMA_ACTION_INVALID",
  POLICY_INVALID: "SCHEMA_POLICY_INVALID",
  ACTION_NOT_GRANTED: "ACTION_NOT_GRANTED",
  PRINCIPAL_NOT_GRANTED: "IDENTITY_PRINCIPAL_NOT_GRANTED",
  AGENT_NOT_GRANTED: "IDENTITY_AGENT_NOT_GRANTED",
  TOOL_NOT_GRANTED: "ACTION_TOOL_NOT_GRANTED",
  RESOURCE_NOT_GRANTED: "RESOURCE_NOT_GRANTED",
  SCOPE_NOT_GRANTED: "ACTION_SCOPE_NOT_GRANTED",
  RISK_EXCEEDED: "ACTION_RISK_EXCEEDED",
  CONSTRAINT_VIOLATION: "CONSTRAINT_VIOLATION",
} as const;

const MAX_POLICY_BYTES = 262_144;
const MAX_RULES = 256;
const MAX_LIST_ENTRIES = 256;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const POLICY_FIELDS = new Set([
  "version",
  "policyId",
  "delegationRequired",
  "rules",
]);
const RULE_FIELDS = new Set([
  "ruleId",
  "principals",
  "agents",
  "tools",
  "operations",
  "resources",
  "allowedScopes",
  "maxRisk",
  "constraints",
]);
const RISK_RANK: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isBoundedText(value: unknown, maxLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength &&
    value === value.trim() &&
    value === value.normalize("NFC") &&
    !CONTROL_PATTERN.test(value)
  );
}

function canonicalCopy(value: unknown): unknown {
  const canonical = canonicalize(value);
  if (Buffer.byteLength(canonical, "utf8") > MAX_POLICY_BYTES) {
    throw new TypeError("action policy exceeds the 262144 byte limit");
  }
  return JSON.parse(canonical) as unknown;
}

function validateSortedList(
  value: unknown,
  field: string,
  pattern: RegExp | null,
  errors: string[],
): void {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_LIST_ENTRIES) {
    errors.push(`${field} must contain 1-${String(MAX_LIST_ENTRIES)} entries`);
    return;
  }
  if (
    !value.every(
      (entry) =>
        isBoundedText(entry, 2_048) && (pattern === null || pattern.test(entry)),
    )
  ) {
    errors.push(`${field} contains an invalid entry`);
  }
  if (new Set(value).size !== value.length) errors.push(`${field} contains duplicates`);
  const sorted = [...value].sort();
  if (value.some((entry, index) => entry !== sorted[index])) {
    errors.push(`${field} must be sorted lexicographically`);
  }
}

function validateJsonText(value: JsonValue, path: string, errors: string[]): void {
  if (typeof value === "string") {
    if (!isBoundedText(value, 16_384)) {
      errors.push(`${path} must contain bounded NFC text without controls`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      validateJsonText(item, `${path}[${String(index)}]`, errors),
    );
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (!isBoundedText(key, 256)) errors.push(`${path} contains an invalid key`);
      validateJsonText(item, `${path}.${key.slice(0, 64)}`, errors);
    }
  }
}

function validateConstraints(
  value: unknown,
  path: string,
  errors: string[],
): void {
  if (!isObject(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  for (const field of Object.keys(value)) {
    if (field !== "exact" && field !== "maximums") {
      errors.push(`unexpected ${path} field '${field}'`);
    }
  }
  if (!isObject(value.exact)) {
    errors.push(`${path}.exact must be an object`);
  } else {
    validateJsonText(value.exact as JsonObject, `${path}.exact`, errors);
  }
  if (!isObject(value.maximums)) {
    errors.push(`${path}.maximums must be an object`);
  } else {
    for (const [key, maximum] of Object.entries(value.maximums)) {
      if (!isBoundedText(key, 256)) errors.push(`${path}.maximums has an invalid key`);
      if (typeof maximum !== "number" || !Number.isFinite(maximum) || maximum < 0) {
        errors.push(`${path}.maximums.${key.slice(0, 64)} must be non-negative`);
      }
    }
  }
}

export function validateActionPolicy(value: unknown): ActionPolicyValidationResult {
  let candidate: unknown;
  try {
    candidate = canonicalCopy(value);
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : "invalid action policy"],
    };
  }
  if (!isObject(candidate)) {
    return { ok: false, errors: ["action policy must be an object"] };
  }

  const errors: string[] = [];
  for (const field of Object.keys(candidate)) {
    if (!POLICY_FIELDS.has(field)) errors.push(`unexpected action policy field '${field}'`);
  }
  if (candidate.version !== 1) errors.push("policy version must be 1");
  if (!isBoundedText(candidate.policyId, 512)) {
    errors.push("policyId must be bounded NFC text without controls");
  }
  if (typeof candidate.delegationRequired !== "boolean") {
    errors.push("delegationRequired must be boolean");
  }
  if (!Array.isArray(candidate.rules) || candidate.rules.length === 0 || candidate.rules.length > MAX_RULES) {
    errors.push(`rules must contain 1-${String(MAX_RULES)} entries`);
  } else {
    const ruleIds: string[] = [];
    candidate.rules.forEach((rule, index) => {
      const path = `rules[${String(index)}]`;
      if (!isObject(rule)) {
        errors.push(`${path} must be an object`);
        return;
      }
      for (const field of Object.keys(rule)) {
        if (!RULE_FIELDS.has(field)) errors.push(`unexpected ${path} field '${field}'`);
      }
      if (typeof rule.ruleId !== "string" || !NAME_PATTERN.test(rule.ruleId)) {
        errors.push(`${path}.ruleId must be a machine-readable name`);
      } else {
        ruleIds.push(rule.ruleId);
      }
      validateSortedList(rule.principals, `${path}.principals`, null, errors);
      validateSortedList(rule.agents, `${path}.agents`, null, errors);
      validateSortedList(rule.tools, `${path}.tools`, NAME_PATTERN, errors);
      validateSortedList(rule.operations, `${path}.operations`, NAME_PATTERN, errors);
      validateSortedList(rule.resources, `${path}.resources`, null, errors);
      validateSortedList(rule.allowedScopes, `${path}.allowedScopes`, null, errors);
      if (rule.maxRisk !== "low" && rule.maxRisk !== "medium" && rule.maxRisk !== "high") {
        errors.push(`${path}.maxRisk must be low, medium, or high`);
      }
      validateConstraints(rule.constraints, `${path}.constraints`, errors);
    });
    if (new Set(ruleIds).size !== ruleIds.length) errors.push("ruleId values must be unique");
    const sortedRuleIds = [...ruleIds].sort();
    if (ruleIds.some((ruleId, index) => ruleId !== sortedRuleIds[index])) {
      errors.push("rules must be sorted by ruleId");
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    policy: candidate as unknown as ActionPolicyV1,
    errors: [],
  };
}

function constraintsMatch(
  action: ActionEnvelopeV1,
  constraints: DelegationConstraintsV1,
): boolean {
  for (const [key, expected] of Object.entries(constraints.exact)) {
    if (
      !(key in action.constraints) ||
      canonicalize(action.constraints[key]) !== canonicalize(expected)
    ) {
      return false;
    }
  }
  for (const [key, maximum] of Object.entries(constraints.maximums)) {
    const actual = action.constraints[key];
    if (typeof actual !== "number" || actual > maximum) return false;
  }
  return true;
}

function deny(
  reasonCode: string,
  detail: string,
  policyId: string,
  delegationRequired: boolean,
): ActionPolicyDecision {
  return { decision: "deny", reasonCode, detail, policyId, delegationRequired };
}

export function admitAction(
  actionValue: unknown,
  policyValue: unknown,
  now = new Date(),
): ActionPolicyDecision {
  const policyValidation = validateActionPolicy(policyValue);
  if (!policyValidation.ok || !policyValidation.policy) {
    return deny(
      ACTION_POLICY_REASON.POLICY_INVALID,
      policyValidation.errors.join("; "),
      "invalid-policy",
      true,
    );
  }
  const policy = policyValidation.policy;
  const actionCheck = checkActionEnvelope(actionValue, now);
  if (!actionCheck.valid || !actionCheck.action) {
    return deny(
      ACTION_POLICY_REASON.ACTION_INVALID,
      actionCheck.detail,
      policy.policyId,
      policy.delegationRequired,
    );
  }
  const action = actionCheck.action;

  let candidates = policy.rules.filter((rule) => rule.operations.includes(action.operation));
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.ACTION_NOT_GRANTED, "operation is not granted", policy.policyId, policy.delegationRequired);
  }
  candidates = candidates.filter((rule) => rule.principals.includes(action.principalId));
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.PRINCIPAL_NOT_GRANTED, "principal is not granted", policy.policyId, policy.delegationRequired);
  }
  candidates = candidates.filter((rule) => rule.agents.includes(action.agentId));
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.AGENT_NOT_GRANTED, "agent is not granted", policy.policyId, policy.delegationRequired);
  }
  candidates = candidates.filter((rule) => rule.tools.includes(action.tool));
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.TOOL_NOT_GRANTED, "tool is not granted", policy.policyId, policy.delegationRequired);
  }
  candidates = candidates.filter((rule) => rule.resources.includes(action.resource));
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.RESOURCE_NOT_GRANTED, "resource is not granted", policy.policyId, policy.delegationRequired);
  }
  candidates = candidates.filter((rule) =>
    action.scopes.every((scope) => rule.allowedScopes.includes(scope)),
  );
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.SCOPE_NOT_GRANTED, "action scope is not granted", policy.policyId, policy.delegationRequired);
  }
  candidates = candidates.filter(
    (rule) => RISK_RANK[action.riskClass] <= RISK_RANK[rule.maxRisk],
  );
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.RISK_EXCEEDED, "action risk exceeds the rule maximum", policy.policyId, policy.delegationRequired);
  }
  candidates = candidates.filter((rule) => constraintsMatch(action, rule.constraints));
  if (candidates.length === 0) {
    return deny(ACTION_POLICY_REASON.CONSTRAINT_VIOLATION, "action constraints violate policy", policy.policyId, policy.delegationRequired);
  }

  return {
    decision: "allow",
    reasonCode: ACTION_POLICY_REASON.ALLOWED,
    detail: "exact action is allowed by policy",
    policyId: policy.policyId,
    matchedRuleId: candidates[0]!.ruleId,
    delegationRequired: policy.delegationRequired,
  };
}
