// Encrypted blobs through the backend (SPEC §6.12): `putBlob` seals and uploads, `readBlob` downloads and opens all
// of a blob or a range of it, as a stream. `makeFlows` binds both to a session's content key.

import * as api from "./api.js";
import { bytes, concat, DecryptError, hexDecode, hexEncode, sha256Hex } from "./crypto.js";
import * as stream from "./stream.js";

export { CHUNK_SIZE } from "./stream.js";

/** Seals `data` as a blob of kind `label` and uploads it. → { id, salt, size, sha256 }: the salt in hex, and the plaintext's length and SHA-256. */
export async function putBlob(rootKey, label, data, { signal } = {}) {
  checkLabel(label);
  const plaintext = bytes(data);
  const sealed = await stream.seal(rootKey, label, plaintext);
  const id = await api.putBlob(sealed, { signal });
  return { id, salt: hexEncode(sealed.subarray(0, stream.SALT)), size: plaintext.length, sha256: await sha256Hex(plaintext) };
}

/**
 * All of blob `id`'s plaintext, returned only once the whole blob is checked against its ID: for code that acts on what
 * it reads, e.g. `keep` walking a tree of blobs (SPEC §5).
 */
export async function openBlob(rootKey, label, id) {
  checkLabel(label);
  const sealed = await api.getBlob(id);
  try {
    return await stream.open(rootKey, label, sealed);
  } catch (error) {
    throw error instanceof DecryptError ? new api.IntegrityError(`blob ${id} doesn't decrypt`) : error;
  }
}

function checkLabel(label) {
  if (typeof label !== "string" || label.length === 0) throw new TypeError("A blob's label is a non-empty string, e.g. `<namespace>/track/v1`");
}

function saltBytes(salt) {
  if (typeof salt !== "string" || !/^[0-9a-f]{32}$/.test(salt)) throw new TypeError("A salt is 32 lowercase hex characters");
  return hexDecode(salt);
}

/**
 * Reads blob `id`: all of it, or plaintext bytes [from, to), where either may be left out.
 * → { size, stream }: the length of the whole plaintext, and the requested bytes as they are decrypted.
 *
 * - All of it: one request. Before the stream closes, the blob is checked against its ID; until then, the bytes are
 *   the user's and of this kind, unaltered and in order, but could be another blob's.
 * - A range: only the chunks it touches, and the header if it starts after the first. The same guarantee, unless
 *   `salt` is given: then the bytes are certainly blob `id`'s.
 * - `signal` aborts the requests, and so does cancelling the stream. An abort fails with the signal's reason.
 */
export async function readBlob(rootKey, label, id, { salt = null, from, to, signal } = {}) {
  checkLabel(label);
  api.checkBlobId(id);
  const pinned = salt === null ? null : saltBytes(salt);
  const start = from ?? 0;
  if (!Number.isSafeInteger(start) || start < 0 || (to !== undefined && !(Number.isSafeInteger(to) && to >= start))) {
    throw new RangeError(`Not a range of bytes: ${from}–${to}`);
  }
  signal?.throwIfAborted();
  const controller = new AbortController();
  const abort = () => controller.abort(signal.reason);
  signal?.addEventListener("abort", abort, { once: true });
  const done = () => {
    signal?.removeEventListener("abort", abort);
    controller.abort();
  };
  const fail = (error) => (signal?.aborted ? signal.reason : error instanceof DecryptError ? new api.IntegrityError(`blob ${id} doesn't decrypt`) : error);
  const request = { rootKey, label, id, pinned, start, to, signal: controller.signal };
  try {
    const opened = await (from === undefined && to === undefined ? openWhole(request) : openRange(request));
    return { size: opened.size, stream: toStream(guarded(opened.chunks, controller.signal, fail, done), () => controller.abort()) };
  } catch (error) {
    done();
    throw fail(error);
  }
}

async function openWhole({ rootKey, label, id, pinned, signal }) {
  const reader = exactReader((await api.getBlobStream(id, { signal })).body);
  const header = await reader.read(stream.HEADER);
  const { key, length } = await stream.openHeader(rootKey, label, header, pinned);
  return { size: length, chunks: wholeBlob({ reader, header, key, length, id }) };
}

/** The plaintext of a whole blob, then its check: shape, length and hash, before the stream may close. */
async function* wholeBlob({ reader, header, key, length, id }) {
  const sealed = [header];
  const kept = async function* (chunks) {
    for await (const chunk of chunks) {
      sealed.push(chunk.data);
      yield chunk;
    }
  };
  yield* plaintextOf(kept(sealedChunks(reader, 0, null)), key, 0, length, true);
  const blob = concat(sealed);
  const layout = stream.layoutOf(blob.length);
  if (!layout || length > layout.padded) throw new DecryptError();
  if ((await sha256Hex(blob)) !== id) throw new api.IntegrityError(`blob ${id}`);
}

async function openRange({ rootKey, label, id, pinned, start, to, signal }) {
  const first = Math.floor(start / stream.CHUNK_SIZE);
  const wanted = to === undefined || to > start;
  const range = { from: first === 0 ? 0 : stream.chunkOffset(first), to: to === undefined ? null : stream.chunkOffset(Math.floor((to - 1) / stream.CHUNK_SIZE) + 1) };
  const [body, head] = await Promise.all([
    wanted ? api.getBlobStream(id, { range, signal }).catch((e) => (e.status === 416 ? null : Promise.reject(e))) : null,
    wanted && first === 0 ? null : api.getBlobStream(id, { range: { from: 0, to: stream.HEADER }, signal }),
  ]);
  const bodyReader = body && exactReader(body.body);
  const headReader = head && exactReader(head.body);
  // The header comes with the body when that starts at 0: a range in the first chunk, or a server ignoring ranges.
  const header = await (body?.start === 0 ? bodyReader : headReader ?? emptyReader).read(stream.HEADER);
  await headReader?.cancel();
  const { key, length } = await stream.openHeader(rootKey, label, header, pinned);
  const totals = [body?.total, head?.total].filter((total) => total != null);
  if (totals.some((total) => total !== totals[0])) throw new DecryptError();
  const total = totals[0] ?? null;
  const layout = total === null ? null : stream.layoutOf(total);
  if (total !== null && (!layout || length > layout.padded)) throw new DecryptError();
  if (start > length) throw new RangeError(`The range starts after the end of the blob (${length} bytes)`);
  const end = Math.min(to ?? length, length);
  if (end <= start) {
    await bodyReader?.cancel();
    return { size: length, chunks: nothing() };
  }
  if (!body) throw new DecryptError(); // "unsatisfiable", but the length block says the bytes exist
  const at = body.start === 0 ? stream.HEADER : body.start;
  return { size: length, chunks: rangeOf({ reader: bodyReader, skip: stream.chunkOffset(first) - at, first, total, key, start, end }) };
}

async function* rangeOf({ reader, skip, first, total, key, start, end }) {
  if ((await reader.read(skip)).length !== skip) throw new DecryptError();
  yield* plaintextOf(sealedChunks(reader, first, total), key, start, end, false);
}

async function* nothing() {}

/**
 * The sealed chunks from `first` on, as the body delivers them. `total`, the blob's size, says which one is the last;
 * without it, the last one is where the body ends.
 */
async function* sealedChunks(reader, first, total) {
  const layout = total === null ? null : stream.layoutOf(total);
  for (let index = first; ; index++) {
    const size = layout ? stream.chunkEnd(total, index) - stream.chunkOffset(index) : stream.SEALED_CHUNK;
    const data = await reader.read(size);
    if (layout && data.length !== size) throw new DecryptError();
    const last = layout ? index === layout.chunks - 1 : data.length < size || (await reader.atEnd());
    yield { index, data, last };
    if (last) return;
  }
}

/** Decrypts the chunks and yields their plaintext within [start, end); stops after `end` unless `toEnd`. */
async function* plaintextOf(chunks, key, start, end, toEnd) {
  for await (const { index, data, last } of chunks) {
    const plaintext = await stream.openChunk(key, index, last, data);
    const offset = index * stream.CHUNK_SIZE;
    const part = plaintext.subarray(Math.max(0, start - offset), Math.max(0, end - offset));
    if (part.length > 0) yield part;
    if (!toEnd && offset + plaintext.length >= end) return;
  }
}

/**
 * Passes nothing on once aborted, even what has already arrived; turns errors into what `readBlob` reports; and lets
 * go of the requests when the chunks end, however they end.
 */
async function* guarded(chunks, signal, fail, done) {
  try {
    for await (const part of chunks) {
      signal.throwIfAborted();
      yield part;
    }
  } catch (error) {
    throw fail(error);
  } finally {
    done();
  }
}

/** Pulls a chunk only when one is read, so nothing waits in the stream's queue when it is aborted. */
const toStream = (chunks, cancel) =>
  new ReadableStream({
    async pull(controller) {
      try {
        const { value, done } = await chunks.next();
        if (done) controller.close();
        else controller.enqueue(value);
      } catch (error) {
        controller.error(error);
      }
    },
    async cancel(reason) {
      cancel(reason);
      await chunks.return();
    },
  }, { highWaterMark: 0 });

/** A response body read in pieces of exact sizes; a piece is shorter only at the end of the body. */
function exactReader(body) {
  const reader = body.getReader();
  let pending = new Uint8Array(0);
  const fill = async (size) => {
    while (pending.length < size) {
      const { value, done } = await reader.read();
      if (done) return;
      pending = concat([pending, value]);
    }
  };
  return {
    async read(size) {
      await fill(size);
      const piece = pending.subarray(0, size);
      pending = pending.subarray(size);
      return piece;
    },
    async atEnd() {
      await fill(1);
      return pending.length === 0;
    },
    cancel: () => reader.cancel().catch(() => {}),
  };
}

const emptyReader = { read: async () => new Uint8Array(0) };
