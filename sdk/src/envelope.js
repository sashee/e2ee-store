// Encrypted documents (SPEC §3.2): nonce ‖ AES-256-GCM(content key, padded JSON) ‖ tag. Nothing else in clear.

import { aesGcmDecrypt, aesGcmEncrypt, hkdfAesKey, td, te } from "./crypto.js";

const BLOCK = 4096;
const NONCE = 12;

export const contentKey = (labels, masterKey) => hkdfAesKey(masterKey, labels.content);

/** Pads with spaces to a multiple of 4096 bytes; JSON ignores trailing whitespace. */
export function pad(data) {
  const length = Math.max(BLOCK, Math.ceil(data.length / BLOCK) * BLOCK);
  const out = new Uint8Array(length).fill(0x20);
  out.set(data);
  return out;
}

/** `aad` names what the blob is (e.g. `labels.vault`), so a blob of one kind can't be passed off as another. */
export async function sealDocument(key, aad, doc) {
  const { nonce, ciphertext } = await aesGcmEncrypt(key, pad(te.encode(JSON.stringify(doc))), te.encode(aad));
  const out = new Uint8Array(NONCE + ciphertext.length);
  out.set(nonce);
  out.set(ciphertext, NONCE);
  return out;
}

/** Throws `DecryptError` if the blob doesn't decrypt with this key and AAD. */
export async function openDocument(key, aad, blob) {
  const plaintext = await aesGcmDecrypt(key, blob.subarray(0, NONCE), blob.subarray(NONCE), te.encode(aad));
  return JSON.parse(td.decode(plaintext));
}
