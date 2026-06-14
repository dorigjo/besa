import { test } from "node:test";
import assert from "node:assert/strict";
import {
checkGrant,
loadGrants,
validateGrantSet,
type GrantSet,
} from "../sdk.js";

function sampleGrants(): GrantSet {
return {
grants: [
{
agentId: "agent-alpha",
tools: ["crm.lookup"],
},
],
};
}

test("checkGrant grants a permitted tool", () => {
const decision = checkGrant(sampleGrants(), "agent-alpha", "crm.lookup");

assert.equal(decision.granted, true);
assert.equal(decision.reasonCode, "GRANT_OK");
assert.equal(decision.agentId, "agent-alpha");
assert.equal(decision.toolName, "crm.lookup");
});

test("checkGrant denies an ungranted tool", () => {
const decision = checkGrant(sampleGrants(), "agent-alpha", "crm.delete");

assert.equal(decision.granted, false);
assert.equal(decision.reasonCode, "TOOL_NOT_GRANTED");
assert.equal(decision.agentId, "agent-alpha");
assert.equal(decision.toolName, "crm.delete");
});

test("checkGrant denies an unknown agent", () => {
const decision = checkGrant(sampleGrants(), "ghost", "crm.lookup");

assert.equal(decision.granted, false);
assert.equal(decision.reasonCode, "AGENT_NOT_FOUND");
assert.equal(decision.agentId, "ghost");
assert.equal(decision.toolName, "crm.lookup");
});

test("validateGrantSet rejects invalid grants", () => {
const result = validateGrantSet({
grants: [
{
agentId: "",
tools: "nope",
},
],
});

assert.equal(result.ok, false);
assert.ok(result.errors.length > 0);
});

test("loadGrants reads the example grant file", () => {
const grantSet = loadGrants("examples/grants.yaml");

assert.equal(grantSet.grants.length, 1);
assert.equal(grantSet.grants[0]?.agentId, "agent-alpha");
assert.deepEqual(grantSet.grants[0]?.tools, ["crm.lookup"]);
});