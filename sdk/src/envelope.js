// Encrypted documents (SPEC §3.2): JSON in an encrypted blob, whose padding hides small changes in size. The content
// key is the root every blob's key is derived from.

import { aesGcmDecrypt, hkdfAesKey, hkdfBaseKey, td, te } from "./crypto.js";
import * as stream from "./stream.js";

/** HKDF(MK, labels.stream), non-extractable: the root of every blob's key (SPEC §3.1). */
export const contentKey = (labels, masterKey) => hkdfBaseKey(masterKey, labels.stream);

/** `label` names what the blob is (e.g. `labels.vault`), so a blob of one kind can't be passed off as another. */
export const sealDocument = (key, label, doc) => stream.seal(key, label, te.encode(JSON.stringify(doc)));

/** Throws `DecryptError` if the blob doesn't decrypt with this key and label. */
export async function openDocument(key, label, blob) {
  return JSON.parse(td.decode(await stream.open(key, label, blob)));
}

// ---------------------------------------------------------------- the format before streams (SPEC §3.5)
// Transitional: read-only, for upgrading vaults written before the stream format (flows' `upgradeVault`). It goes
// once every vault is upgraded.

const NONCE = 12;

export const legacyContentKey = (labels, masterKey) => hkdfAesKey(masterKey, labels.content);

/** nonce ‖ AES-256-GCM(legacy content key, JSON padded with spaces) ‖ tag, with `aad` naming the kind. */
export async function openLegacyDocument(key, aad, blob) {
  const plaintext = await aesGcmDecrypt(key, blob.subarray(0, NONCE), blob.subarray(NONCE), te.encode(aad));
  return JSON.parse(td.decode(plaintext));
}
