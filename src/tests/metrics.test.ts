import { test } from "node:test";
import assert from "node:assert/strict";
import { Metrics } from "../server/metrics.js";

test("starts with zeroed counters", () => {
  const metrics = new Metrics();
  const snapshot = metrics.snapshot();

  assert.equal(snapshot.requestsTotal, 0);
  assert.deepEqual(snapshot.requestsByRoute, {});
  assert.deepEqual(snapshot.requestsByStatus, {});
  assert.equal(snapshot.rateLimitedTotal, 0);
  assert.equal(typeof snapshot.startedAt, "string");
});

test("aggregates counts by route and status", () => {
  const metrics = new Metrics();

  metrics.record("/health", 200);
  metrics.record("/health", 200);
  metrics.record("/v1/verify/manifest", 400);

  const snapshot = metrics.snapshot();

  assert.equal(snapshot.requestsTotal, 3);
  assert.equal(snapshot.requestsByRoute["/health"], 2);
  assert.equal(snapshot.requestsByRoute["/v1/verify/manifest"], 1);
  assert.equal(snapshot.requestsByStatus["200"], 2);
  assert.equal(snapshot.requestsByStatus["400"], 1);
});

test("tracks rate-limited requests separately from route/status counters", () => {
  const metrics = new Metrics();

  metrics.recordRateLimited();
  metrics.recordRateLimited();

  const snapshot = metrics.snapshot();
  assert.equal(snapshot.rateLimitedTotal, 2);
  assert.equal(snapshot.requestsTotal, 0);
});

test("uptimeSeconds reflects elapsed time since construction", () => {
  const metrics = new Metrics();
  const snapshot = metrics.snapshot(Date.now() + 5_000);
  assert.equal(snapshot.uptimeSeconds, 5);
});
