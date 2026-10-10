import { test } from "node:test";
import assert from "node:assert/strict";

import { formatBytes, isDue, makeReport, planBlobs, prunableSlots, summary } from "../src/maintenance.js";
import { rollbackCheck } from "../src/save.js";

const blob = (id, created_at, size = 10) => ({ id, size, created_at });
const NOW = Date.parse("2026-10-12T12:00:00Z");

test("cleanup keeps referenced and history blobs, and young blobs", () => {
  const blobs = [blob("keys", "2026-10-01T00:00:00Z"), blob("vault", "2026-10-01T00:00:00Z"), blob("old-history", "2026-10-01T00:00:00Z"), blob("orphan", "2026-10-11T11:59:59Z"), blob("young", "2026-10-11T12:00:01Z")];
  const plan = planBlobs({ keep: ["keys", "vault", "old-history"], blobs, now: NOW });
  assert.deepEqual(plan.kept.map((b) => b.id), ["keys", "vault", "old-history"]);
  assert.deepEqual(plan.toDelete.map((b) => b.id), ["orphan"]);
  assert.deepEqual(plan.tooRecent.map((b) => b.id), ["young"]);
});

test("without a usable time, nothing counts as old enough to delete", () => {
  assert.deepEqual(planBlobs({ keep: [], blobs: [blob("orphan", "2020-01-01T00:00:00Z")], now: NaN }).toDelete, []);
  assert.deepEqual(planBlobs({ keep: [], blobs: [blob("odd", "yesterday")], now: NOW }).toDelete, []);
});

test("stale passkey slots are found", () => {
  assert.deepEqual(prunableSlots({ passkeys: { a: {}, b: {} } }, ["b", "c"]), ["a"]);
});

test("the report counts and summarises a run", () => {
  const plan = planBlobs({ keep: ["k"], blobs: [blob("k", "2026-10-01T00:00:00Z", 100), blob("x", "2026-10-01T00:00:00Z", 2048), blob("y", "2026-10-12T11:00:00Z", 5)], now: NOW });
  const report = makeReport({ trigger: "manual", startedAt: NOW, finishedAt: NOW + 1000, slotsRemoved: 1, plan, deleted: plan.toDelete, failed: [] });
  assert.equal(report.blobs_total, 3);
  assert.equal(report.bytes_total, 2153);
  assert.deepEqual(report.deleted, { count: 1, bytes: 2048 });
  assert.deepEqual(report.too_recent, { count: 1, bytes: 5 });
  assert.match(summary(report), /\(manual\): 1 deleted \(2\.0 KB\), 1 too recent, 0 failed$/);
  assert.equal(formatBytes(3 * 1024 * 1024), "3.0 MB");
});

test("the automatic run is due after 24 hours or a failed run", () => {
  const ok = makeReport({ trigger: "automatic", startedAt: NOW, finishedAt: NOW });
  assert.equal(isDue(null, NOW), true);
  assert.equal(isDue(ok, NOW + 23 * 3600 * 1000), false);
  assert.equal(isDue(ok, NOW + 24 * 3600 * 1000), true);
  assert.equal(isDue({ ...ok, error: "offline" }, NOW + 1), true);
  assert.equal(isDue({ ...ok, finished_at: "garbage" }, NOW), true, "an unreadable report doesn't stop the runs for good");
});

test("rollback is a revision lower than the highest seen", () => {
  assert.deepEqual(rollbackCheck(null, 3), { rolledBack: false, highest: 3 });
  assert.deepEqual(rollbackCheck(3, 5), { rolledBack: false, highest: 5 });
  assert.deepEqual(rollbackCheck(5, 5), { rolledBack: false, highest: 5 });
  assert.deepEqual(rollbackCheck(5, 4), { rolledBack: true, highest: 5 });
});
