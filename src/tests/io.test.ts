import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readJsonFile } from "../io.js";

test("readJsonFile reports a missing file as a missing file, not invalid JSON", () => {
  const dir = mkdtempSync(join(tmpdir(), "besa-io-test-"));
  const missingPath = join(dir, "does-not-exist.json");

  try {
    assert.throws(() => readJsonFile(missingPath), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /ENOENT|no such file/i);
      assert.doesNotMatch(error.message, /invalid JSON/i);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readJsonFile reports malformed JSON as invalid JSON", () => {
  const dir = mkdtempSync(join(tmpdir(), "besa-io-test-"));
  const badPath = join(dir, "malformed.json");
  writeFileSync(badPath, "{not valid json", "utf8");

  try {
    assert.throws(() => readJsonFile(badPath), /invalid JSON at/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readJsonFile parses a well-formed file", () => {
  const dir = mkdtempSync(join(tmpdir(), "besa-io-test-"));
  const goodPath = join(dir, "good.json");
  writeFileSync(goodPath, JSON.stringify({ a: 1 }), "utf8");

  try {
    assert.deepEqual(readJsonFile(goodPath), { a: 1 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
