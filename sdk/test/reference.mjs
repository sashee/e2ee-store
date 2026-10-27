// The blob format as SPEC §3.2 describes it, written with node:crypto alone, not with the SDK: for the
// vectors (make-vectors.mjs), and for tests that need blobs the SDK would never write.

import { createCipheriv, createHash, hkdfSync } from "node:crypto";

export const hkdf = (ikm, info, length, salt = Buffer.alloc(0)) => Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** AES-256-GCM: ciphertext ‖ 16-byte tag. */
export function seal(key, nonce, plaintext, aad = Buffer.alloc(0)) {
  const cipher = createCipheriv("aes-256-gcm", key, nonce).setAAD(Buffer.from(aad));
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

/** §3.2: the index as 11 bytes, big-endian, then the flag. */
function nonce(index, flag) {
  const out = Buffer.alloc(12);
  out.writeUIntBE(index, 5, 6);
  out[11] = flag;
  return out;
}

/** §3.2's padding: at least 4096, else Padmé as its paper writes it (E = ⌊log₂ L⌋, S = ⌊log₂ E⌋ + 1), then to whole 4 KiB. */
export function padded(length) {
  if (length <= 4096) return 4096;
  const e = Math.floor(Math.log2(length));
  const s = Math.floor(Math.log2(e)) + 1;
  const mask = (1n << BigInt(e - s)) - 1n;
  const padme = Number((BigInt(length) + mask) & ~mask);
  return Math.ceil(padme / 4096) * 4096;
}

/**
 * §3.2: salt ‖ length block ‖ chunks, with the key HKDF(HKDF(MK, "<ns>/stream/v1"), salt, label). `padded` (the
 * padded plaintext's length) and `length` (the length block's value) default to what the SDK writes, and can be set
 * to anything, e.g. another writer's padding, or a length past the padding.
 */
export function streamBlob({ masterKey, namespace, label, salt, plaintext, padded: size = padded(plaintext.length), length = plaintext.length }) {
  const key = hkdf(hkdf(masterKey, `${namespace}/stream/v1`, 32), label, 32, salt);
  const body = Buffer.alloc(size);
  Buffer.from(plaintext).copy(body);
  const count = Math.ceil(size / 65536);
  const lengthField = Buffer.alloc(8);
  lengthField.writeBigUInt64BE(BigInt(length));
  const chunks = Array.from({ length: count }, (_, i) => seal(key, nonce(i, i === count - 1 ? 1 : 0), body.subarray(i * 65536, (i + 1) * 65536)));
  return Buffer.concat([salt, seal(key, nonce(0, 2), lengthField), ...chunks]);
}
