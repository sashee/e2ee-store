// The backend client against a server that misbehaves (SPEC §3.2, §7): its messages, IDs and blobs are not trusted.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as api from "../src/api.js";
import { install, sha256Hex } from "./fakes.js";

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
