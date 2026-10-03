import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync,
  writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addTrustAnchor, admitPreExecution, createExternalAuthority,
  emptyTrustStore, FileReplayStore, generateKeyPair, hashActionPolicy, hashRequest,
  revokeTrustAnchor, publicKeyId, withBesaExecutor,
  type ActionPolicyV1, type BesaExecutorConfig, type PreExecutionAdmissionInput,
  type PreExecutionAdmissionReceiptV1,
} from "../sdk.js";

const NOW = new Date("2026-10-03T12:00:00.000Z");
const BEFORE = "2026-10-03T11:00:00.000Z";
const EXPIRY = "2026-10-03T13:00:00.000Z";
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "besa-executor-"));
  const issuer = generateKeyPair();
  const normalizer = generateKeyPair();
  const recorder = generateKeyPair();
  const caller = { principalId: "principal:platform", agentId: "agent:ci" };
  const policy: ActionPolicyV1 = { version: 1, policyId: "executor-v1", delegationRequired: false,
    rules: [{ ruleId: "write", principals: [caller.principalId], agents: [caller.agentId],
      tools: ["artifact.publish"], operations: ["publish"], resources: ["artifact:staging"],
      allowedScopes: ["artifact:write"], maxRisk: "medium", constraints: { exact: {}, maximums: {} } }] };
  const parameters = { content: "verified artifact" };
  const context = { executorId: "executor:staging" };
  const input: PreExecutionAdmissionInput = {
    request: { requestVersion: 1, parameters, context, audience: "https://ci.example/artifacts",
      requestedAt: NOW.toISOString(), policy: { id: policy.policyId, version: 1, hash: hashActionPolicy(policy) },
      action: { artifactVersion: 1, ...caller, authority: "authority:ci", tool: "artifact.publish",
        operation: "publish", resource: "artifact:staging", requestHash: hashRequest(parameters),
        contextHash: hashRequest(context), scopes: ["artifact:write"], constraints: {},
        expiresAt: EXPIRY, nonce: "nonce_0123456789abcdef", riskClass: "medium" } },
    authority: createExternalAuthority({ artifactVersion: 1, mechanism: "mcp-ema-access-token",
      ...caller, issuer: "authority:ci", audience: "https://ci.example/artifacts", tools: ["artifact.publish"],
      operations: ["publish"], resources: ["artifact:staging"], scopes: ["artifact:write"],
      constraints: { exact: {}, maximums: {} }, notBefore: BEFORE, expiresAt: EXPIRY,
      assertionDigest: "a".repeat(64), delegationChainHash: null },
    { id: "normalizer:ci", keyPair: normalizer, issuedAt: BEFORE }),
  };
  const admission = { policy, audience: input.request.audience, issuerId: "admission:ci", keyPair: issuer,
    trustStore: addTrustAnchor(addTrustAnchor(emptyTrustStore(), issuer.publicKeyDer, BEFORE),
      recorder.publicKeyDer, BEFORE),
    authorityTrustStore: addTrustAnchor(emptyTrustStore(), normalizer.publicKeyDer, BEFORE) };
  const receipts: PreExecutionAdmissionReceiptV1[] = [];
  const config: BesaExecutorConfig = {
    policy, audience: admission.audience, trustStore: admission.trustStore,
    authorityTrustStore: admission.authorityTrustStore, executorId: context.executorId,
    recorderId: "recorder:ci", evidenceKeyPair: recorder, clock: () => new Date(NOW),
    replayStore: new FileReplayStore(join(root, ".besa", "replay"), { durability: "process" }),
    admissionSink: { async append(receipt) { receipts.push(receipt); } },
    evidenceSink: { async append() {} },
  };
  return { root, input, caller, config, admission, receipts, normalizer,
    receipt: admitPreExecution(input, admission, NOW),
    cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("executor independently verifies and commits receipt before a real filesystem effect", async () => {
  const f = fixture();
  try {
    const run = withBesaExecutor(f.config, (input) => {
      assert.equal(f.receipts.length, 1);
      assert.ok(Object.isFrozen(input.request.parameters));
      writeFileSync(join(f.root, "artifact"), String(input.request.parameters.content), { flag: "wx" });
      return { written: true };
    });
    const result = await run(f.input, f.receipt, f.caller);
    assert.equal(result.result.written, true);
    assert.equal(readFileSync(join(f.root, "artifact"), "utf8"), "verified artifact");
    assert.equal(result.evidence.receiptHash?.length, 64);
  } finally { f.cleanup(); }
});

const attacks: Array<[string, (f: ReturnType<typeof fixture>) => unknown]> = [
  ["missing receipt", () => undefined],
  ["malformed receipt", () => ({ validated: true })],
  ["forged signature", (f) => ({ ...f.receipt, signature: "A".repeat(86) + "==" })],
  ["unsupported version", (f) => ({ ...f.receipt, artifactVersion: 2 })],
  ["another agent", (f) => { f.input.request.action.agentId = "agent:other";
    f.caller.agentId = "agent:other"; return f.receipt; }],
  ["another principal", (f) => { f.input.request.action.principalId = "principal:other";
    f.caller.principalId = "principal:other"; return f.receipt; }],
  ["another resource", (f) => { f.input.request.action.resource = "artifact:production"; return f.receipt; }],
  ["another operation", (f) => { f.input.request.action.operation = "delete"; return f.receipt; }],
  ["another tool", (f) => { f.input.request.action.tool = "database.delete"; return f.receipt; }],
  ["changed parameters", (f) => { f.input.request.parameters.content = "malicious"; return f.receipt; }],
  ["wrong policy digest", (f) => { f.input.request.policy.hash = "b".repeat(64); return f.receipt; }],
  ["invalid authority", (f) => { f.input.authority = { verified: true }; return f.receipt; }],
  ["invalid delegation", (f) => { f.input.delegationChain = [{} as never]; return f.receipt; }],
  ["expired receipt", (f) => { f.config.clock = () => new Date(EXPIRY); return f.receipt; }],
];
for (const [name, attack] of attacks) {
  test(`executor rejects ${name} with zero handler calls`, async () => {
    const f = fixture();
    try {
      const receipt = attack(f);
      let calls = 0;
      await assert.rejects(withBesaExecutor(f.config, () => { calls++; return {}; })(f.input, receipt, f.caller));
      assert.equal(calls, 0);
    } finally { f.cleanup(); }
  });
}

test("host caller identity and executor binding cannot be supplied by a receipt", async () => {
  const f = fixture();
  try {
    let calls = 0;
    const run = withBesaExecutor(f.config, () => { calls++; return {}; });
    await assert.rejects(run(f.input, f.receipt, { ...f.caller, agentId: "agent:attacker" }), /ADMISSION_CALLER_MISMATCH/);
    await assert.rejects(run(f.input, f.receipt, { ...f.caller, principalId: "principal:attacker" }), /ADMISSION_CALLER_MISMATCH/);
    await assert.rejects(withBesaExecutor({ ...f.config, executorId: "executor:production" },
      () => { calls++; return {}; })(f.input, f.receipt, f.caller), /ADMISSION_EXECUTOR_MISMATCH/);
    const changed = copy(f.input);
    changed.request.context.executorId = "executor:production";
    changed.request.action.contextHash = hashRequest(changed.request.context);
    await assert.rejects(withBesaExecutor({ ...f.config, executorId: "executor:production" },
      () => { calls++; return {}; })(changed, f.receipt, f.caller));
    assert.equal(calls, 0);
    assert.equal(f.receipts.length, 0);
  } finally { f.cleanup(); }
});

test("executor receipt/storage/revocation failures remain fail closed", async () => {
  for (const failure of ["receipt-storage", "replay-storage", "revocation"] as const) {
    const f = fixture();
    try {
      let calls = 0;
      if (failure === "receipt-storage") f.config.admissionSink = { async append() { throw new Error("disk full"); } };
      if (failure === "replay-storage") {
        writeFileSync(join(f.root, "blocked"), "file");
        f.config.replayStore = new FileReplayStore(join(f.root, "blocked", "replay"), { durability: "process" });
      }
      if (failure === "revocation") f.config.admissionSink = { async append() {
        f.config.authorityTrustStore = revokeTrustAnchor(f.config.authorityTrustStore,
          publicKeyId(f.normalizer.publicKeyDer), NOW.toISOString());
      } };
      await assert.rejects(withBesaExecutor(f.config, () => { calls++; return {}; })(f.input, f.receipt, f.caller));
      assert.equal(calls, 0);
    } finally { f.cleanup(); }
  }
});

test("lost response after a real side effect never causes an automatic retry after restart", async () => {
  const f = fixture();
  try {
    let calls = 0;
    const handler = (): never => {
      calls++;
      writeFileSync(join(f.root, "artifact"), "committed", { flag: "wx" });
      throw new Error("response lost after commit");
    };
    await assert.rejects(withBesaExecutor(f.config, handler)(f.input, f.receipt, f.caller));
    const restarted = { ...f.config, replayStore: new FileReplayStore(join(f.root, ".besa", "replay"),
      { durability: "process" }) };
    await assert.rejects(withBesaExecutor(restarted, handler)(f.input, f.receipt, f.caller), /already been consumed/);
    assert.equal(calls, 1);
    assert.equal(readFileSync(join(f.root, "artifact"), "utf8"), "committed");
  } finally { f.cleanup(); }
});

test("independent file replay instances and concurrent requests have one winner", async () => {
  const f = fixture();
  try {
    let calls = 0;
    const tasks = Array.from({ length: 12 }, () => withBesaExecutor({ ...f.config,
      replayStore: new FileReplayStore(join(f.root, ".besa", "replay"), { durability: "process" }) },
    () => { calls++; return {}; })(f.input, f.receipt, f.caller));
    const results = await Promise.allSettled(tasks);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    assert.equal(calls, 1);
  } finally { f.cleanup(); }
});

test("separate OS processes atomically consume a shared durable replay key", async () => {
  const f = fixture();
  try {
    const moduleUrl = new URL("../file-replay-store.js", import.meta.url).href;
    const code = `import { FileReplayStore } from ${JSON.stringify(moduleUrl)};
      const store = new FileReplayStore(process.argv[1], {durability:'process'});
      console.log(JSON.stringify(await store.consume('shared-key', ${JSON.stringify(EXPIRY)},
        new Date(${JSON.stringify(NOW.toISOString())}))));`;
    const tasks = Array.from({ length: 8 }, () => new Promise<string>((resolve, reject) => {
      execFile(process.execPath, ["--input-type=module", "--eval", code, join(f.root, ".besa", "replay")],
        { timeout: 15_000 }, (error, stdout, stderr) => {
          if (error) reject(new Error(`${error.message}: ${stderr}`));
          else resolve((JSON.parse(stdout) as { status: string }).status);
        });
    }));
    const statuses = await Promise.all(tasks);
    assert.equal(statuses.filter((s) => s === "consumed").length, 1);
    assert.equal(statuses.filter((s) => s === "replay").length, 7);
  } finally { f.cleanup(); }
});

test("partial claims are spent, path substitution fails closed and records contain no raw key", async () => {
  const f = fixture();
  try {
    const path = join(f.root, ".besa", "replay");
    const store = new FileReplayStore(path, { durability: "process" });
    assert.equal((await store.consume("../../raw-secret-key", EXPIRY, NOW)).status, "consumed");
    const record = join(path, readdirSync(path)[0]!);
    assert.ok(!readFileSync(record, "utf8").includes("raw-secret-key"));
    writeFileSync(record, "");
    assert.equal((await new FileReplayStore(path, { durability: "process" })
      .consume("../../raw-secret-key", EXPIRY, NOW)).status, "replay");
    const link = join(f.root, "linked");
    symlinkSync(path, link, process.platform === "win32" ? "junction" : "dir");
    assert.equal((await new FileReplayStore(link, { durability: "process" })
      .consume("new-key", EXPIRY, NOW)).status, "unavailable");
  } finally { f.cleanup(); }
});

test("file replay rejects invalid input and never implicitly downgrades durability", async () => {
  const f = fixture();
  try {
    const store = new FileReplayStore(join(f.root, ".besa", "strict"));
    assert.equal(store.durability, "power-loss");
    const committed = await store.consume("key", EXPIRY, NOW);
    assert.equal(committed.status, process.platform === "win32" ? "unavailable" : "consumed");
    for (const [key, expiry, clock] of [
      ["", EXPIRY, NOW], ["x".repeat(513), EXPIRY, NOW], ["key", BEFORE, NOW],
      ["key", "not-time", NOW], ["key", EXPIRY, new Date(Number.NaN)],
    ] as const) assert.equal((await store.consume(key, expiry, clock)).status, "unavailable");
    assert.throws(() => new FileReplayStore(""));
    assert.throws(() => new FileReplayStore(f.root, { durability: "weak" as never }));
  } finally { f.cleanup(); }
});
