import { test } from "node:test";
import assert from "node:assert/strict";
import {
  InMemoryReplayStore,
  REPLAY_REASON,
  VerificationOnlyReplayStore,
  replayKey,
} from "../replay.js";

const ACTION_HASH = "a".repeat(64);
const EXPIRES_AT = "2026-09-21T12:05:00.000Z";
const NOW = new Date("2026-09-21T12:00:00.000Z");

test("replay keys bind both action hash and nonce", () => {
  const first = replayKey(ACTION_HASH, "nonce_0123456789abcdef");
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.notEqual(
    first,
    replayKey(ACTION_HASH, "nonce_abcdef0123456789"),
  );
});

test("verification-only mode states that one-time use is not enforced", async () => {
  const store = new VerificationOnlyReplayStore();
  const result = await store.consume("key", EXPIRES_AT, NOW);

  assert.equal(result.status, "not-enforced");
  assert.equal(result.reasonCode, REPLAY_REASON.NOT_ENFORCED);
  assert.equal(store.mode, "verification-only");
});

test("the in-memory store atomically consumes a replay key once", async () => {
  const store = new InMemoryReplayStore();
  const first = await store.consume("key", EXPIRES_AT, NOW);
  const second = await store.consume("key", EXPIRES_AT, NOW);

  assert.equal(first.status, "consumed");
  assert.equal(first.reasonCode, REPLAY_REASON.CONSUMED);
  assert.equal(second.status, "replay");
  assert.equal(second.reasonCode, REPLAY_REASON.DETECTED);
});

test("concurrent in-memory consumption has exactly one winner", async () => {
  const store = new InMemoryReplayStore();
  const results = await Promise.all(
    Array.from({ length: 100 }, () => store.consume("shared-key", EXPIRES_AT, NOW)),
  );

  assert.equal(results.filter((result) => result.status === "consumed").length, 1);
  assert.equal(results.filter((result) => result.status === "replay").length, 99);
});

test("an enforced replay store fails closed when capacity is unavailable", async () => {
  const store = new InMemoryReplayStore({ maxEntries: 1 });
  await store.consume("first", EXPIRES_AT, NOW);
  const result = await store.consume("second", EXPIRES_AT, NOW);

  assert.equal(result.status, "unavailable");
  assert.equal(result.reasonCode, REPLAY_REASON.UNAVAILABLE);
});
