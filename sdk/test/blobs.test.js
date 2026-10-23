// putBlob and readBlob (SPEC §6.12) against the fake backend: ranges, what they fetch, salts, a misbehaving server,
// and aborting.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as api from "../src/api.js";
import { CHUNK_SIZE, putBlob, readBlob } from "../src/blobs.js";
import { contentKey } from "../src/envelope.js";
import { labels } from "../src/labels.js";
import { chunkOffset, HEADER } from "../src/stream.js";
import { install, sha256Hex } from "./fakes.js";
import { streamBlob } from "./reference.mjs";

const L = labels("test-app");
const TRACK = "test-app/track/v1";
const root = await contentKey(L, new Uint8Array(32).fill(7));
const data = (length, seed = 0) => Uint8Array.from({ length }, (_, i) => (i * 31 + seed + Math.floor(i / CHUNK_SIZE)) % 256);
const LENGTH = 3 * CHUNK_SIZE + 5000;

function signedIn(settings = {}) {
  const { server } = install();
  server.session = { passkey: null, fresh: true };
  return Object.assign(server, settings);
}

const collect = async ({ size, stream }) => ({ size, bytes: new Uint8Array(await new Response(stream).arrayBuffer()) });
const blobReads = (server) => server.requests.filter((r) => r.method === "GET" && r.path.startsWith("/blobs/"));

test("a blob round-trips whole, with its salt first", async () => {
  const server = signedIn();
  for (const length of [0, 1, 4097, CHUNK_SIZE, CHUNK_SIZE + 1, LENGTH]) {
    const { id, salt } = await putBlob(root, TRACK, data(length));
    assert.match(salt, /^[0-9a-f]{32}$/);
    assert.equal(Buffer.from(server.blobs.get(id).bytes.subarray(0, 16)).toString("hex"), salt);
    assert.deepEqual(await collect(await readBlob(root, TRACK, id)), { size: length, bytes: data(length) }, `length ${length}`);
    assert.deepEqual(await collect(await readBlob(root, TRACK, id, { salt })), { size: length, bytes: data(length) });
  }
});

test("ranges return their bytes, whatever pieces the network delivers them in", async () => {
  for (const pieceSize of [16 * 1024, 1000, 7]) {
    const server = signedIn({ pieceSize });
    const { id } = await putBlob(root, TRACK, data(LENGTH));
    const ranges = [
      [0, 10],
      [CHUNK_SIZE - 5, CHUNK_SIZE + 5],
      [CHUNK_SIZE, 2 * CHUNK_SIZE],
      [2 * CHUNK_SIZE + 100, undefined],
      [undefined, 50],
      [LENGTH - 1, LENGTH],
      [LENGTH, LENGTH],
      [100, 100],
      [0, 10 ** 9],
    ];
    for (const [from, to] of ranges) {
      const expected = data(LENGTH).subarray(from ?? 0, Math.min(to ?? LENGTH, LENGTH));
      assert.deepEqual(await collect(await readBlob(root, TRACK, id, { from, to })), { size: LENGTH, bytes: expected }, `${from}–${to} in pieces of ${pieceSize}`);
    }
  }
});

test("a range fetches only the chunks it touches, and the header if it starts after the first", async () => {
  const server = signedIn();
  const { id } = await putBlob(root, TRACK, data(LENGTH));
  const fetched = async (from, to) => {
    server.requests = [];
    await collect(await readBlob(root, TRACK, id, { from, to }));
    return blobReads(server).map((r) => r.range);
  };
  assert.deepEqual(await fetched(CHUNK_SIZE, 2 * CHUNK_SIZE), [`bytes=${chunkOffset(1)}-${chunkOffset(2) - 1}`, `bytes=0-${HEADER - 1}`]);
  assert.deepEqual(await fetched(10, CHUNK_SIZE + 1), [`bytes=0-${chunkOffset(2) - 1}`], "the first chunk comes with the header");
  assert.deepEqual(await fetched(3 * CHUNK_SIZE, undefined), [`bytes=${chunkOffset(3)}-`, `bytes=0-${HEADER - 1}`]);
  assert.deepEqual(await fetched(undefined, undefined), [undefined], "all of it: one request without a range");
});

test("a range must be one, and may not start after the end", async () => {
  const server = signedIn();
  const { id } = await putBlob(root, TRACK, data(1000));
  server.requests = [];
  for (const [from, to] of [[-1, 5], [5, 4], [1.5, 4], ["0", 4], [0, Infinity]]) {
    await assert.rejects(readBlob(root, TRACK, id, { from, to }), RangeError, `${from}–${to}`);
  }
  assert.deepEqual(blobReads(server), [], "nothing was fetched");
  await assert.rejects(readBlob(root, TRACK, id, { from: 1001 }), RangeError);
  await assert.rejects(readBlob(root, TRACK, id, { from: 10 * CHUNK_SIZE, to: 11 * CHUNK_SIZE }), RangeError, "past the padding too");
  await assert.rejects(readBlob(root, TRACK, id, { salt: "not a salt" }), TypeError);
  await assert.rejects(readBlob(root, "", id), TypeError, "a label is required");
  await assert.rejects(putBlob(root, "", data(1)), TypeError);
  await assert.rejects(readBlob(root, TRACK, "../../me"), api.IntegrityError);
});

/** Fails when it opens or while it streams, whichever comes first. */
const failsWith = (read, error) => assert.rejects(read.then(collect), error);

test("another blob in place of this one: its salt catches it in a range, its ID in a whole read", async () => {
  const server = signedIn();
  const a = await putBlob(root, TRACK, data(LENGTH, 1));
  const b = await putBlob(root, TRACK, data(LENGTH, 2));
  server.blobs.get(a.id).bytes = server.blobs.get(b.id).bytes;

  await assert.rejects(readBlob(root, TRACK, a.id, { salt: a.salt, from: CHUNK_SIZE, to: CHUNK_SIZE + 10 }), api.IntegrityError);
  await assert.rejects(readBlob(root, TRACK, a.id, { salt: a.salt }), api.IntegrityError);
  await failsWith(readBlob(root, TRACK, a.id), api.IntegrityError);
  // Without the salt, a range can't tell (SPEC §8): the bytes are the user's, of this kind and unaltered, but B's.
  const unpinned = await collect(await readBlob(root, TRACK, a.id, { from: CHUNK_SIZE, to: CHUNK_SIZE + 10 }));
  assert.deepEqual(unpinned.bytes, data(LENGTH, 2).subarray(CHUNK_SIZE, CHUNK_SIZE + 10));
});

test("damage shows up as an integrity error where it is read", async () => {
  const server = signedIn();
  const { id } = await putBlob(root, TRACK, data(LENGTH));
  const stored = server.blobs.get(id).bytes;
  server.blobs.get(id).bytes = Uint8Array.from(stored, (b, i) => (i === chunkOffset(1) + 3 ? b ^ 1 : b));
  await failsWith(readBlob(root, TRACK, id, { from: CHUNK_SIZE, to: CHUNK_SIZE + 10 }), api.IntegrityError);
  await failsWith(readBlob(root, TRACK, id), api.IntegrityError);
  assert.deepEqual((await collect(await readBlob(root, TRACK, id, { from: 0, to: 10 }))).bytes, data(10), "the other chunks are fine");
  await assert.rejects(readBlob(root, "test-app/other/v1", id), api.IntegrityError, "another kind");

  // Cut off after the third chunk: the server's sizes agree with that, but the third chunk isn't the last.
  server.blobs.get(id).bytes = stored.subarray(0, chunkOffset(3));
  await failsWith(readBlob(root, TRACK, id), api.IntegrityError);
  await failsWith(readBlob(root, TRACK, id, { from: 2 * CHUNK_SIZE, to: 3 * CHUNK_SIZE }), api.IntegrityError);
});

test("a server that ignores ranges still gives the right bytes", async () => {
  const server = signedIn({ ignoresRanges: true, pieceSize: 1000 });
  const { id } = await putBlob(root, TRACK, data(LENGTH));
  for (const [from, to] of [[CHUNK_SIZE + 5, 2 * CHUNK_SIZE + 5], [0, 10], [LENGTH - 3, undefined], [7, 7]]) {
    assert.deepEqual((await collect(await readBlob(root, TRACK, id, { from, to }))).bytes, data(LENGTH).subarray(from, to ?? LENGTH));
  }
});

test("aborting stops the requests and fails with the signal's reason", async () => {
  const server = signedIn({ pieceSize: 1000 });
  const { id } = await putBlob(root, TRACK, data(LENGTH));
  const reason = new Error("next track");

  const early = new AbortController();
  early.abort(reason);
  server.requests = [];
  await assert.rejects(readBlob(root, TRACK, id, { signal: early.signal }), (e) => e === reason);
  await assert.rejects(putBlob(root, TRACK, data(10), { signal: early.signal }), (e) => e === reason);
  assert.deepEqual(blobReads(server), []);

  for (const range of [{}, { from: CHUNK_SIZE }]) {
    const controller = new AbortController();
    const reader = (await readBlob(root, TRACK, id, { ...range, signal: controller.signal })).stream.getReader();
    assert.equal((await reader.read()).done, false);
    controller.abort(reason);
    await assert.rejects(reader.read(), (e) => e === reason);
    assert.ok(blobReads(server).every((r) => r.signal.aborted), "every request was aborted");
  }
});

test("cancelling the stream aborts its requests", async () => {
  const server = signedIn({ pieceSize: 1000 });
  const { id } = await putBlob(root, TRACK, data(LENGTH));
  server.requests = [];
  const { stream } = await readBlob(root, TRACK, id, { from: CHUNK_SIZE });
  const reader = stream.getReader();
  await reader.read();
  await reader.cancel();
  assert.ok(blobReads(server).length > 0);
  assert.ok(blobReads(server).every((r) => r.signal.aborted));
});

test("the end of a blob of whole chunks is empty, and nothing lies after it", async () => {
  signedIn();
  const { id } = await putBlob(root, TRACK, data(CHUNK_SIZE));
  assert.deepEqual(await collect(await readBlob(root, TRACK, id, { from: CHUNK_SIZE })), { size: CHUNK_SIZE, bytes: new Uint8Array(0) });
  await assert.rejects(readBlob(root, TRACK, id, { from: CHUNK_SIZE + 1 }), RangeError);
});

test("blobs of a shape the SDK never writes are integrity errors", async () => {
  const server = signedIn();
  const pastPadding = server.put(streamBlob({ masterKey: new Uint8Array(32).fill(7), namespace: "test-app", label: TRACK, salt: Buffer.alloc(16), plaintext: data(4096), length: 4097 }));
  const tooShort = server.put(new Uint8Array(30));
  for (const id of [pastPadding, tooShort]) {
    await failsWith(readBlob(root, TRACK, id), api.IntegrityError);
    await failsWith(readBlob(root, TRACK, id, { from: 0, to: 10 }), api.IntegrityError);
  }
});

/** Puts `change(response, request)` between the SDK and the fake backend's blob reads. */
function answering(server, change) {
  globalThis.fetch = async (url, init = {}) => {
    const response = await server.fetch(url, init);
    return new URL(url, "http://localhost").pathname.startsWith("/api/v1/blobs/") && (init.method ?? "GET") === "GET" ? change(response, init.headers ?? {}) : response;
  };
}

const respond = async (response, { headers = {}, body, status = response.status }) =>
  new Response(body ?? (await response.arrayBuffer()), { status, headers: { ...Object.fromEntries(response.headers), ...headers } });

test("a server that answers ranges wrongly is caught", async (t) => {
  const cases = {
    "a range that wasn't asked for": (r) => (r.status === 206 ? respond(r, { headers: { "content-range": r.headers.get("content-range").replace(/^bytes \d+/, "bytes 1") } }) : r),
    "no Content-Range": async (r) => (r.status === 206 ? new Response(await r.arrayBuffer(), { status: 206 }) : r),
    "a body shorter than its Content-Range": async (r) => (r.status === 206 ? respond(r, { body: new Uint8Array(await r.arrayBuffer()).subarray(0, 100) }) : r),
    "sizes that disagree": (r, headers) => (headers.Range === `bytes=0-${HEADER - 1}` ? respond(r, { headers: { "content-range": `bytes 0-39/${LENGTH * 2}` } }) : r),
    "unsatisfiable, though the bytes exist": (r, headers) => (headers.Range?.startsWith(`bytes=${chunkOffset(1)}`) ? new Response("{}", { status: 416 }) : r),
    "ranges ignored, and the blob cut short": async (r) => respond(r, { body: new Uint8Array(await r.arrayBuffer()).subarray(0, 1000) }),
  };
  for (const [name, change] of Object.entries(cases)) {
    await t.test(name, async () => {
      const server = signedIn({ ignoresRanges: name.startsWith("ranges ignored") });
      const { id } = await putBlob(root, TRACK, data(LENGTH));
      answering(server, change);
      await failsWith(readBlob(root, TRACK, id, { from: CHUNK_SIZE, to: CHUNK_SIZE + 10 }), api.IntegrityError);
    });
  }
});
