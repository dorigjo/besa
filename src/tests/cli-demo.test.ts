import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { test } from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), "..", "index.js");

test("demo proves exact-action denial and verified allowed execution", () => {
  const result = spawnSync(process.execPath, [CLI, "demo"], { encoding: "utf8" });

  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /AUTHENTICATED != AUTHORIZED FOR THIS EXACT ACTION/);
  assert.match(result.stdout, /operation: delete[\s\S]*resource: database:production-db/);
  assert.match(result.stdout, /DENY\r?\nACTION_NOT_GRANTED\r?\nexecutor called: no/);
  assert.match(result.stdout, /ALLOW\r?\nACTION_ALLOWED\r?\nexecutor called: yes/);
  assert.match(result.stdout, /signed capability: cap_[0-9a-f-]{36}/);
  assert.match(result.stdout, /action hash: [0-9a-f]{64}/);
  assert.match(result.stdout, /evidence verification: EVIDENCE_VALID/);
  assert.match(result.stdout, /evidence recorded: yes/);
});
