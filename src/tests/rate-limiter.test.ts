import { test } from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "../server/rate-limiter.js";

test("allows requests up to the configured limit within a window", () => {
  const limiter = new RateLimiter(3, 60_000);
  const now = 1_000_000;

  assert.equal(limiter.attempt("a", now).allowed, true);
  assert.equal(limiter.attempt("a", now).allowed, true);
  assert.equal(limiter.attempt("a", now).allowed, true);

  const fourth = limiter.attempt("a", now);
  assert.equal(fourth.allowed, false);
  assert.equal(fourth.retryAfterMs, 60_000);
});

test("tracks distinct keys independently", () => {
  const limiter = new RateLimiter(1, 60_000);
  const now = 1_000_000;

  assert.equal(limiter.attempt("a", now).allowed, true);
  assert.equal(limiter.attempt("b", now).allowed, true);
  assert.equal(limiter.attempt("a", now).allowed, false);
  assert.equal(limiter.attempt("b", now).allowed, false);
});

test("resets the count once the window elapses", () => {
  const limiter = new RateLimiter(1, 1_000);
  const start = 1_000_000;

  assert.equal(limiter.attempt("a", start).allowed, true);
  assert.equal(limiter.attempt("a", start + 500).allowed, false);
  assert.equal(limiter.attempt("a", start + 1_000).allowed, true);
});

test("retryAfterMs counts down toward zero as the window elapses", () => {
  const limiter = new RateLimiter(1, 1_000);
  const start = 1_000_000;

  limiter.attempt("a", start);
  const blocked = limiter.attempt("a", start + 400);
  assert.equal(blocked.retryAfterMs, 600);
});

test("rejects a non-positive limit", () => {
  assert.throws(() => new RateLimiter(0), /positive integer/);
  assert.throws(() => new RateLimiter(-1), /positive integer/);
});

test("rejects a non-positive window", () => {
  assert.throws(() => new RateLimiter(5, 0), /positive integer/);
});

test("tracks distinct keys up to the internal bound without dropping recent ones", () => {
  const limiter = new RateLimiter(1, 60_000);
  const now = 1_000_000;

  // Below the internal 10_000-key cap, no eviction should occur yet.
  for (let i = 0; i < 100; i += 1) {
    limiter.attempt(`key-${String(i)}`, now);
  }

  assert.equal(limiter.trackedKeyCount, 100);
});
