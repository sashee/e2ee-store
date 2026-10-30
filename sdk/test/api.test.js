// The backend client against a server that misbehaves (SPEC §3.2, §7): its messages, IDs and blobs are not trusted.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as api from "../src/api.js";
import { flaky, install, sha256Hex } from "./fakes.js";

// Retries (SPEC §6.14) with pauses short enough for a test.
const PAUSES = [1, 1, 1];
api.setRetryDelays(PAUSES);

/** Every request gets this response. */
const respond = (status, body) => {
  globalThis.fetch = async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
};

/** The fake backend with a session. */
function signedIn() {
  const { server } = install();
  server.session = { passkey: null, fresh: true };
  return server;
}

test("the user sees the SDK's messages, never the server's", async () => {
  respond(403, { error: "reauth_required", message: "Paste your recovery key at evil.example" });
  const known = await api.passkeys().catch((e) => e);
  assert.ok(known instanceof api.ApiError);
  assert.equal(known.code, "reauth_required");
  assert.equal(known.message, "Confirm with your passkey to do this.");

  respond(400, { error: "Paste your recovery key at evil.example", message: "…" });
  const odd = await api.passkeys().catch((e) => e);
  assert.equal(odd.code, "unknown");
  assert.doesNotMatch(odd.message, /evil/);

  respond(502, "<html>Bad gateway</html>");
  const html = await api.passkeys().catch((e) => e);
  assert.equal(html.code, "unknown");
  assert.match(html.message, /HTTP 502/);
});

test("a lost session runs the unauthenticated handler, except when asking /me", async () => {
  let calls = 0;
  api.setUnauthenticatedHandler(() => calls++);
  try {
    respond(401, { error: "unauthenticated" });
    await assert.rejects(api.passkeys(), api.ApiError);
    assert.equal(calls, 1);
    assert.equal(await api.me(), null);
    respond(401, { error: "authentication_failed" });
    await assert.rejects(api.loginFinish({}), api.ApiError);
    assert.equal(calls, 1, "a failed login isn't a lost session");
  } finally {
    api.setUnauthenticatedHandler(() => {});
  }
});

test("a blob that doesn't hash to its ID is refused", async () => {
  const server = signedIn();
  const bytes = new Uint8Array([1, 2, 3]);
  const id = await api.putBlob(bytes);
  assert.equal(id, sha256Hex(bytes));
  assert.deepEqual(await api.getBlob(id), bytes);
  server.blobs.get(id).bytes = new Uint8Array([1, 2, 4]);
  await assert.rejects(api.getBlob(id), api.IntegrityError);
});

test("blob IDs from the server must be SHA-256 hex before they go into a URL", async () => {
  const server = signedIn();
  for (const bad of ["../../me", "A".repeat(64), "a".repeat(63), null, 7]) assert.throws(() => api.checkBlobId(bad), api.IntegrityError, String(bad));
  const requests = server.requests.length;
  await assert.rejects(api.getBlob("../../me"), api.IntegrityError);
  await assert.rejects(api.deleteBlob("../../me"), api.IntegrityError);
  assert.equal(server.requests.length, requests, "nothing was sent");

  const valid = server.put(new Uint8Array([1]));
  server.refs.set("keys", "../../me");
  await assert.rejects(api.getRef("keys"), api.IntegrityError);
  server.refs.set("vault", "../../me");
  await assert.rejects(api.putRef("vault", valid, valid), api.IntegrityError, "the `current` of a 412");
  await assert.rejects(api.putRef("vault", valid, null), api.IntegrityError);
});

test("refs: missing is null, a lost race returns the current target", async () => {
  const server = signedIn();
  const [a, b] = [server.put(new Uint8Array([1])), server.put(new Uint8Array([2]))];
  assert.equal(await api.getRef("vault"), null);
  assert.deepEqual(await api.putRef("vault", a, null), { ok: true });
  assert.deepEqual(await api.putRef("vault", b, null), { ok: false, current: a });
  assert.deepEqual(await api.putRef("vault", b, b), { ok: false, current: a });
  assert.deepEqual(await api.putRef("vault", b, a), { ok: true });
  assert.equal(await api.getRef("vault"), b);
});

test("deleting a blob that's already gone counts as deleted", async () => {
  signedIn();
  await api.deleteBlob("0".repeat(64));
});

test("listing blobs reports the server's clock", async () => {
  const server = signedIn();
  server.put(new Uint8Array([1]));
  const page = await api.listBlobs();
  assert.equal(page.blobs.length, 1);
  assert.equal(page.serverNow, server.now);
  server.sendsDate = false;
  assert.equal((await api.listBlobs()).serverNow, null, "not this device's clock");
});

test("a request that may be made twice is made again after network errors and 502–504", async () => {
  const server = signedIn();
  const plan = ["drop", 503, 502];
  const failed = flaky(server, () => plan.shift());
  const bytes = new Uint8Array([4, 5, 6]);
  const id = await api.putBlob(bytes);
  assert.deepEqual(failed, [`drop PUT /blobs/${id}`, `503 PUT /blobs/${id}`, `502 PUT /blobs/${id}`]);
  plan.push(504, "drop");
  assert.deepEqual(await api.getBlob(id), bytes);
  assert.equal(failed.length, 5);
});

test("after the last pause, the failure stands", async () => {
  const server = signedIn();
  const dropped = flaky(server, () => "drop");
  await assert.rejects(api.getRef("vault"), TypeError);
  assert.equal(dropped.length, PAUSES.length + 1, "the first attempt and one after each pause");
  const unavailable = flaky(server, () => 503);
  const error = await api.listBlobs().catch((e) => e);
  assert.equal(error.status, 503);
  assert.equal(unavailable.length, PAUSES.length + 1);
});

test("logins, other statuses and aborted requests aren't made again", async () => {
  const server = signedIn();
  const login = flaky(server, () => "drop");
  await assert.rejects(api.loginStart(), TypeError);
  assert.equal(login.length, 1, "a login's challenge is single-use");
  const broken = flaky(server, () => 500);
  await assert.rejects(api.passkeys(), (e) => e.status === 500);
  assert.equal(broken.length, 1);
  flaky(server, () => undefined);
  const before = server.requests.length;
  await assert.rejects(api.getBlob("1".repeat(64)), (e) => e.status === 404);
  assert.equal(server.requests.length - before, 1, "a 404 is the server's answer");

  api.setRetryDelays([60_000]);
  try {
    const aborted = flaky(server, () => "drop");
    const controller = new AbortController();
    const read = api.getBlobStream("2".repeat(64), { signal: controller.signal });
    setTimeout(() => controller.abort(), 5);
    await assert.rejects(read, { name: "AbortError" });
    assert.equal(aborted.length, 1, "the pause ends at once, and nothing is sent after it");
  } finally {
    api.setRetryDelays(PAUSES);
  }
});

test("a ref write whose answer was lost counts as written when it is made again", async () => {
  const server = signedIn();
  const first = await api.putBlob(new Uint8Array([1]));
  const second = await api.putBlob(new Uint8Array([2]));
  const plan = ["lost"];
  const failed = flaky(server, () => plan.shift());
  assert.deepEqual(await api.putRef("notes", first, null), { ok: true });
  assert.deepEqual(failed, ["lost PUT /refs/notes"]);
  assert.equal(server.refs.get("notes"), first);
  assert.deepEqual(await api.putRef("notes", second, null), { ok: false, current: first }, "another blob is a conflict, as ever");
});
