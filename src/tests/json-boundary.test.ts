import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { readJsonFile } from "../io.js";
import { createHostedVerifierServer } from "../server/hosted-verifier.js";
import {
  canonicalize, loadActionPolicy, loadGrants, loadManifest, parseArtifactJson,
  verifyPreExecutionAdmission, validateActionEnvelope,
  type PreExecutionAdmissionInput, type PreExecutionAdmissionReceiptV1,
  type PreExecutionVerificationConfig,
} from "../sdk.js";

interface JsonVector { name: string; input: string; canonical?: string; reject?: boolean }
const boundary = parseArtifactJson(readFileSync(
  new URL("../../conformance/json-boundary-v1.json", import.meta.url),
)) as { boundaryVersion: number; vectors: JsonVector[] };
assert.equal(boundary.boundaryVersion, 1);
for (const vector of boundary.vectors) {
  test(`JSON boundary vector: ${vector.name}`, () => {
    if (vector.reject) assert.throws(() => parseArtifactJson(vector.input));
    else assert.equal(canonicalize(parseArtifactJson(vector.input)), vector.canonical);
  });
}

test("JSON boundary rejects invalid UTF-8 and preserves BOM for rejection", () => {
  for (const bytes of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xe2, 0x82]]) {
    assert.throws(() => parseArtifactJson(new Uint8Array(bytes)));
  }
  assert.throws(() => parseArtifactJson(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])));
  assert.throws(() => parseArtifactJson("\ufeff{}"));
  assert.throws(() => parseArtifactJson('"\ud800"'));
  assert.throws(() => parseArtifactJson({} as string));
});

test("JSON boundary enforces depth at the frozen canonical limit", () => {
  const atLimit = "[".repeat(64) + "0" + "]".repeat(64);
  assert.doesNotThrow(() => parseArtifactJson(atLimit));
  assert.throws(() => parseArtifactJson("[" + atLimit + "]"), /depth/);
  const duplicate = '{"a":0,"a":1}';
  assert.throws(() => parseArtifactJson("[".repeat(60) + duplicate + "]".repeat(60)), /duplicate/);
  assert.throws(() => parseArtifactJson("[".repeat(100_000)), /depth/);
});

test("JSON boundary rejects oversized raw bytes and excessive values or keys", () => {
  assert.doesNotThrow(() => parseArtifactJson('"' + "x".repeat(1_048_574) + '"'));
  assert.throws(() => parseArtifactJson('"' + "x".repeat(1_048_575) + '"'), /byte/);
  assert.throws(() => parseArtifactJson("[" + "0,".repeat(100_000) + "0]"), /node/);
  const manyKeys = Array.from({ length: 100_001 }, (_, i) => `"${i}":0`).join(",");
  assert.throws(() => parseArtifactJson("{" + manyKeys + "}"), /limit/);
});

test("JSON boundary delegates syntax to JSON.parse without YAML or extensions", () => {
  for (const source of ["", " ", "{a:1}", "{\"a\":01}", "[1,,2]", "[+1]",
    "[.1]", "[1.]", "[1e]", "undefined", "/*comment*/{}", '"\\x61"', '"\n"']) {
    assert.throws(() => parseArtifactJson(source));
  }
  assert.deepEqual(parseArtifactJson('{"__proto__":{"polluted":true}}'),
    JSON.parse('{"__proto__":{"polluted":true}}'));
  assert.equal(Object.prototype.hasOwnProperty.call({}, "polluted"), false);
});

test("JSON boundary deterministic fuzz retains canonical JSON and rejects escaped duplicates", () => {
  for (let i = 0; i < 512; i++) {
    const value = { [String(i)]: i, nested: [{ text: `quote"slash\\:${i}`, number: i / 7 }],
      unicode: ["\u00e9", "e\u0301", "\ud83d\ude00"], flag: i % 2 === 0 };
    const source = JSON.stringify(value);
    assert.equal(canonicalize(parseArtifactJson(source)), canonicalize(value));
    const key = `key_${i}`;
    assert.throws(() => parseArtifactJson(`{"${key}":0,"\\u006bey_${i}":1}`), /duplicate/);
  }
  for (const number of [Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER,
    9007199254740992, 1e21, 1e-7, -0, -0.1]) {
    assert.equal(canonicalize(parseArtifactJson(JSON.stringify(number))), canonicalize(number));
  }
});

test("JSON boundary does not confuse root types or visually similar schema keys", () => {
  for (const source of ["null", "[]", '"action"', "1", "true"]) {
    assert.equal(validateActionEnvelope(parseArtifactJson(source)).ok, false);
  }
  assert.equal(validateActionEnvelope(parseArtifactJson('{"artifactVersi\u043en":1}')).ok, false);
});

test("JSON file loaders and CLI reject duplicate keys before schema verification", () => {
  const directory = mkdtempSync(join(tmpdir(), "besa-json-boundary-"));
  assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
  try {
    const path = join(directory, "ambiguous.json");
    writeFileSync(path, '{"artifactVersion":1,"artifactVersion":1}');
    for (const load of [readJsonFile, loadManifest, loadGrants, loadActionPolicy]) {
      assert.throws(() => load(path), /duplicate/);
    }
    const cli = spawnSync(process.execPath,
      [fileURLToPath(new URL("../index.js", import.meta.url)), "verify", path],
      { cwd: directory, encoding: "utf8", timeout: 10_000, maxBuffer: 16_384 });
    assert.equal(cli.error, undefined);
    assert.notEqual(cli.status, 0);
    assert.match(cli.stdout + cli.stderr, /duplicate/);
    writeFileSync(path, Buffer.from([0xff]));
    assert.throws(() => readJsonFile(path));
    writeFileSync(path, Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
    assert.throws(() => readJsonFile(path));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("hosted verification rejects ambiguous raw input rather than verifying its last value", async () => {
  const server = createHostedVerifierServer({ rateLimit: false });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const body of [
      '{"artifactVersion":2,"artifactVersion":1}',
      '{"constraints":{"amount":100,"amount":10000}}',
      '{"artifactVersion":1,"\\u0061rtifactVersion":2}',
      '{"constraints":{"amount":9007199254740993}}',
      '{"constraints":{"text":"\\ud800"}}',
      "[".repeat(65) + "0" + "]".repeat(65),
      Buffer.from([0xff]),
    ]) {
      const response = await fetch(base + "/v1/verify/action", {
        method: "POST", headers: { "Content-Type": "application/json" }, body,
        signal: AbortSignal.timeout(5_000),
      });
      assert.equal(response.status, 400);
      await response.arrayBuffer();
    }
    const validJson = await fetch(base + "/v1/verify/action", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "null",
      signal: AbortSignal.timeout(5_000),
    });
    assert.equal(validJson.status, 200);
    assert.equal((await validJson.json() as { valid: boolean }).valid, false);
  } finally {
    await new Promise<void>((done, fail) => server.close((error) => error ? fail(error) : done()));
  }
});

test("strict raw parsing preserves frozen admission bytes and rejects ambiguous receipts", () => {
  const vector = parseArtifactJson(readFileSync(
    new URL("../../conformance/pre-execution-v1.json", import.meta.url),
  )) as { at: string; input: PreExecutionAdmissionInput;
    receipt: PreExecutionAdmissionReceiptV1; config: PreExecutionVerificationConfig };
  const receipt = parseArtifactJson(JSON.stringify(vector.receipt));
  assert.equal(verifyPreExecutionAdmission(receipt, vector.input,
    vector.config, new Date(vector.at)).authorized, true);
  const ambiguous = JSON.stringify(vector.receipt).replace('"decision":"allow"',
    '"decision":"deny","decision":"allow"');
  assert.throws(() => parseArtifactJson(ambiguous), /duplicate/);
});
