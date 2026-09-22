import { spawnSync } from "node:child_process";
import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), "..", "index.js");

test("serve rejects an action policy without a server-controlled trust store", () => {
  const result = spawnSync(process.execPath, [CLI, "serve", "--action-policy", "policy.yaml"], {
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /--action-policy requires --trust/);
});

test("CLI help documents hosted action admission configuration", () => {
  const result = spawnSync(process.execPath, [CLI, "--help"], { encoding: "utf8" });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /--action-policy <file>/);
  assert.match(result.stdout, /--action-trust <file>/);
  assert.match(result.stdout, /BESA_ADMISSION_TOKEN/);
});
