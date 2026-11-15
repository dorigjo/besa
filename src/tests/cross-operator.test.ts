import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const example = fileURLToPath(new URL("../../examples/cross-operator-proof.mjs", import.meta.url));

test("three local operators exchange admission and independently verify execution evidence", () => {
  const output = execFileSync(process.execPath, [example], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 30_000,
  });
  const report = JSON.parse(output.trim()) as Record<string, unknown>;
  assert.equal(report.verifier, "operator-c-offline-verifier");
  assert.equal(report.admissionValid, true);
  assert.equal(report.admissionDecision, "allow");
  assert.equal(report.executionEvidenceValid, true);
  assert.equal(report.handlerCalls, 1);
  assert.equal(report.mutationRejected, true);
  assert.equal(report.replayRejected, true);
  assert.equal(report.effectMatchesAuthorizedInput, true);
  assert.equal(report.privateKeysProvided, false);
  assert.equal(report.networkUsed, false);
});
