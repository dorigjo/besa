import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadActionPolicy } from "../action-policy-io.js";

const POLICY = [
  "version: 1",
  "policyId: policy:deployment-v1",
  "delegationRequired: false",
  "rules:",
  "  - ruleId: allow-staging-deploy",
  "    principals: [principal:platform]",
  "    agents: [agent:release]",
  "    tools: [deployment.release]",
  "    operations: [deploy]",
  "    resources: [environment:staging]",
  "    allowedScopes: [deployment:write]",
  "    maxRisk: high",
  "    constraints:",
  "      exact:",
  "        environment: staging",
  "      maximums:",
  "        riskScore: 50",
  "",
].join("\n");

test("action policies load from YAML and JSON with strict validation", () => {
  const directory = mkdtempSync(join(tmpdir(), "besa-action-policy-"));
  try {
    const yamlPath = join(directory, "policy.yaml");
    const jsonPath = join(directory, "policy.json");
    writeFileSync(yamlPath, POLICY, "utf8");
    writeFileSync(jsonPath, JSON.stringify(loadActionPolicy(yamlPath)), "utf8");

    assert.equal(loadActionPolicy(yamlPath).policyId, "policy:deployment-v1");
    assert.equal(loadActionPolicy(jsonPath).rules.length, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("action policy loading rejects duplicate keys and unsupported extensions", () => {
  const directory = mkdtempSync(join(tmpdir(), "besa-action-policy-"));
  try {
    const duplicatePath = join(directory, "duplicate.yaml");
    const textPath = join(directory, "policy.txt");
    writeFileSync(duplicatePath, `${POLICY}policyId: duplicate\n`, "utf8");
    writeFileSync(textPath, POLICY, "utf8");

    assert.throws(() => loadActionPolicy(duplicatePath));
    assert.throws(() => loadActionPolicy(textPath), /must end in/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
