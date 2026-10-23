// Encrypted documents (SPEC §3.2): JSON in an encrypted blob, whose padding hides small changes in size. The content
// key is the root every blob's key is derived from.

import { hkdfBaseKey, td, te } from "./crypto.js";
import * as stream from "./stream.js";

/** HKDF(MK, labels.stream), non-extractable: the root of every blob's key (SPEC §3.1). */
export const contentKey = (labels, masterKey) => hkdfBaseKey(masterKey, labels.stream);

/** `label` names what the blob is (e.g. `labels.vault`), so a blob of one kind can't be passed off as another. */
export const sealDocument = (key, label, doc) => stream.seal(key, label, te.encode(JSON.stringify(doc)));

/** Throws `DecryptError` if the blob doesn't decrypt with this key and label. */
export async function openDocument(key, label, blob) {
  return JSON.parse(td.decode(await stream.open(key, label, blob)));
}
