// The stream format (SPEC §3.2): sizes, round trips, and blobs that are damaged or made by another writer.

import { test } from "node:test";
import assert from "node:assert/strict";

import { DecryptError, hexEncode } from "../src/crypto.js";
import { contentKey } from "../src/envelope.js";
import { labels } from "../src/labels.js";
import { CHUNK_SIZE, chunkOffset, HEADER, layoutOf, nonce, open, SEALED_CHUNK, seal } from "../src/stream.js";
import { streamBlob } from "./reference.mjs";

const L = labels("test-app");
const FILE = "test-app/file/v1";
const masterKey = new Uint8Array(32).fill(7);
const root = await contentKey(L, masterKey);
const data = (length) => Uint8Array.from({ length }, (_, i) => (i * 31 + Math.floor(i / CHUNK_SIZE)) % 256);
const LENGTHS = [0, 1, 4095, 4096, 4097, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 5000];

test("blobs are padded to 4 KiB and split into 64 KiB chunks, each with its tag", async () => {
  for (const length of LENGTHS) {
    const padded = Math.max(4096, Math.ceil(length / 4096) * 4096);
    const chunks = Math.ceil(padded / CHUNK_SIZE);
    const blob = await seal(root, FILE, data(length));
    assert.equal(blob.length, HEADER + padded + 16 * chunks, `length ${length}`);
    assert.deepEqual(layoutOf(blob.length), { chunks, padded });
    assert.deepEqual(await open(root, FILE, blob), data(length), `length ${length}`);
  }
});

test("sizes no blob can have", () => {
  for (const size of [0, HEADER, HEADER + 16, HEADER + SEALED_CHUNK + 16, HEADER + 2 * SEALED_CHUNK + 1, 1.5, -1]) assert.equal(layoutOf(size), null, String(size));
  assert.deepEqual(layoutOf(HEADER + 17), { chunks: 1, padded: 1 });
  assert.deepEqual(layoutOf(HEADER + SEALED_CHUNK + 17), { chunks: 2, padded: CHUNK_SIZE + 1 });
});

test("nonces are the index in 11 bytes and a flag", () => {
  assert.equal(hexEncode(nonce(0, 2)), "000000000000000000000002");
  assert.equal(hexEncode(nonce(1, 0)), "000000000000000000000100");
  assert.equal(hexEncode(nonce(2 ** 32 + 5, 1)), "000000000000010000000501");
});

test("every blob has its own salt", async () => {
  const [a, b] = [await seal(root, FILE, data(10)), await seal(root, FILE, data(10))];
  assert.notDeepEqual(a.subarray(0, 16), b.subarray(0, 16));
  assert.notDeepEqual(a.subarray(16), b.subarray(16));
});

test("blobs made from the SPEC alone open", async () => {
  const salt = Buffer.alloc(16, 9);
  for (const length of LENGTHS) {
    const blob = streamBlob({ masterKey, namespace: "test-app", label: FILE, salt, plaintext: data(length) });
    assert.deepEqual(await open(root, FILE, new Uint8Array(blob)), data(length), `length ${length}`);
  }
  // Another writer's padding: not a multiple of 4 KiB, and a chunk of padding alone.
  const other = streamBlob({ masterKey, namespace: "test-app", label: FILE, salt, plaintext: data(10), padded: 2 * CHUNK_SIZE + 100 });
  assert.deepEqual(await open(root, FILE, new Uint8Array(other)), data(10));
});

test("a blob opens only with its key and label, and with its own salt when one is given", async () => {
  const blob = await seal(root, FILE, data(100));
  await assert.rejects(open(await contentKey(L, new Uint8Array(32)), FILE, blob), DecryptError, "another master key");
  await assert.rejects(open(await contentKey(labels("other-app"), masterKey), FILE, blob), DecryptError, "another app");
  await assert.rejects(open(root, L.dir, blob), DecryptError, "another kind");
  assert.deepEqual(await open(root, FILE, blob, blob.subarray(0, 16)), data(100));
  await assert.rejects(open(root, FILE, blob, new Uint8Array(16)), DecryptError, "another salt");
});

test("damaged, reordered, shortened and lengthened blobs don't open", async () => {
  const blob = await seal(root, FILE, data(3 * CHUNK_SIZE + 5000));
  const other = await seal(root, FILE, data(3 * CHUNK_SIZE + 5000));
  const flip = (at) => Uint8Array.from(blob, (b, i) => (i === at ? b ^ 1 : b));
  const chunk = (from, i) => from.subarray(chunkOffset(i), Math.min(chunkOffset(i + 1), from.length));
  const join = (...parts) => Uint8Array.from(parts.flatMap((p) => [...p]));
  const damaged = {
    "the salt": flip(0),
    "the length block": flip(20),
    "the first chunk": flip(chunkOffset(0) + 5),
    "the last chunk": flip(blob.length - 1),
    "two chunks swapped": join(blob.subarray(0, HEADER), chunk(blob, 1), chunk(blob, 0), chunk(blob, 2), chunk(blob, 3)),
    "the last chunk dropped": blob.subarray(0, chunkOffset(3)),
    "a middle chunk dropped": join(blob.subarray(0, chunkOffset(1)), chunk(blob, 2), chunk(blob, 3)),
    "a chunk of another blob": join(blob.subarray(0, chunkOffset(1)), chunk(other, 1), chunk(blob, 2), chunk(blob, 3)),
    "a chunk appended": join(blob, chunk(blob, 0)),
    "the header alone": blob.subarray(0, HEADER),
  };
  for (const [what, bytes] of Object.entries(damaged)) await assert.rejects(open(root, FILE, bytes), DecryptError, what);
});

test("a length past the padding is refused", async () => {
  const blob = streamBlob({ masterKey, namespace: "test-app", label: FILE, salt: Buffer.alloc(16), plaintext: data(4096), length: 4097 });
  await assert.rejects(open(root, FILE, new Uint8Array(blob)), DecryptError);
});
