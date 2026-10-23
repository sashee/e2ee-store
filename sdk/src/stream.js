// The encrypted blob format (SPEC §3.2): the plaintext in chunks of 64 KiB, each sealed on its own, so any part of a
// blob can be read and checked without the rest.
//
//   salt (16) ‖ length block (8 + 16) ‖ chunk_0 ‖ … ‖ chunk_n-1
//
// Every blob has its own key, HKDF(root key, salt, kind label). A chunk's nonce is its index and whether it is the
// last one, so chunks can't be reordered, dropped or cut off. The plaintext is padded with zeros to a multiple of
// 4 KiB; the length block says where it ends. No I/O here: blobs.js reads and writes blobs through the API.

import { aesGcmDecrypt, aesGcmEncrypt, concat, DecryptError, equalBytes, hkdfSaltedAesKey, randomBytes } from "./crypto.js";

/** Plaintext bytes per chunk. Part of the format: reading whole, aligned chunks fetches nothing that isn't needed. */
export const CHUNK_SIZE = 64 * 1024;
export const SALT = 16;
const TAG = 16;
const LENGTH = 8;
export const HEADER = SALT + LENGTH + TAG;
export const SEALED_CHUNK = CHUNK_SIZE + TAG;
/** What `seal` pads to. It is the writer's choice: readers take any padding. */
const PADDING = 4096;
const NO_AAD = new Uint8Array(0);
const LAST = 1;
const LENGTH_BLOCK = 2;

/** The index as 11 bytes, big-endian, then a flag: 1 for the last chunk, 0 for the others, 2 for the length block. */
export function nonce(index, flag) {
  const out = new Uint8Array(12);
  const view = new DataView(out.buffer);
  view.setUint32(3, Math.floor(index / 2 ** 32));
  view.setUint32(7, index % 2 ** 32);
  out[11] = flag;
  return out;
}

function lengthBytes(length) {
  const out = new Uint8Array(LENGTH);
  const view = new DataView(out.buffer);
  view.setUint32(0, Math.floor(length / 2 ** 32));
  view.setUint32(4, length % 2 ** 32);
  return out;
}

function readLength(data) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return view.getUint32(0) * 2 ** 32 + view.getUint32(4);
}

/** Where chunk `index` starts in a sealed blob. */
export const chunkOffset = (index) => HEADER + index * SEALED_CHUNK;

/** Where chunk `index` ends in a sealed blob of `size` bytes. */
export const chunkEnd = (size, index) => Math.min(chunkOffset(index + 1), size);

/**
 * The shape of a sealed blob of `size` bytes: its number of chunks and the padded plaintext's length; null if no
 * blob has that size. Every chunk but the last is full, and the last holds at least one byte.
 */
export function layoutOf(size) {
  const body = size - HEADER;
  if (!Number.isSafeInteger(size) || body <= TAG) return null;
  const chunks = Math.ceil(body / SEALED_CHUNK);
  return body - (chunks - 1) * SEALED_CHUNK > TAG ? { chunks, padded: body - chunks * TAG } : null;
}

const encrypt = async (key, iv, plaintext) => (await aesGcmEncrypt(key, plaintext, NO_AAD, iv)).ciphertext;

/** Encrypts `plaintext` as a blob of kind `label` (an HKDF info, e.g. `labels.vault`), under a fresh salt. */
export async function seal(rootKey, label, plaintext) {
  const salt = randomBytes(SALT);
  const key = await hkdfSaltedAesKey(rootKey, salt, label);
  const padded = Math.max(PADDING, Math.ceil(plaintext.length / PADDING) * PADDING);
  const count = Math.ceil(padded / CHUNK_SIZE);
  const chunk = (index) => {
    const out = new Uint8Array(Math.min(CHUNK_SIZE, padded - index * CHUNK_SIZE));
    out.set(plaintext.subarray(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE));
    return out;
  };
  const sealed = await Promise.all([
    encrypt(key, nonce(0, LENGTH_BLOCK), lengthBytes(plaintext.length)),
    ...Array.from({ length: count }, (_, index) => encrypt(key, nonce(index, index === count - 1 ? LAST : 0), chunk(index))),
  ]);
  return concat([salt, ...sealed]);
}

/**
 * The key and the plaintext's length from a blob's first HEADER bytes. A `salt` that is given (e.g. from the
 * directory that lists the blob) must be the blob's own: then no other blob can stand in for it.
 */
export async function openHeader(rootKey, label, header, salt = null) {
  if (header.length !== HEADER) throw new DecryptError();
  const own = header.subarray(0, SALT);
  if (salt !== null && !equalBytes(own, salt)) throw new DecryptError();
  const key = await hkdfSaltedAesKey(rootKey, own, label);
  return { key, length: readLength(await aesGcmDecrypt(key, nonce(0, LENGTH_BLOCK), header.subarray(SALT), NO_AAD)) };
}

/** The padded plaintext of chunk `index`; `last` says whether it ends the blob. */
export const openChunk = (key, index, last, sealed) => aesGcmDecrypt(key, nonce(index, last ? LAST : 0), sealed, NO_AAD);

/** Decrypts a whole blob. Throws `DecryptError` if any part doesn't authenticate or the blob isn't shaped like one. */
export async function open(rootKey, label, blob, salt = null) {
  const layout = layoutOf(blob.length);
  if (!layout) throw new DecryptError();
  const { key, length } = await openHeader(rootKey, label, blob.subarray(0, HEADER), salt);
  if (length > layout.padded) throw new DecryptError();
  const chunks = await Promise.all(
    Array.from({ length: layout.chunks }, (_, index) => openChunk(key, index, index === layout.chunks - 1, blob.subarray(chunkOffset(index), chunkEnd(blob.length, index)))),
  );
  return concat(chunks).subarray(0, length);
}
