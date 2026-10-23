// The content key (SPEC §3.1): the root every blob's key is derived from.

import { hkdfBaseKey, td } from "./crypto.js";
import * as stream from "./stream.js";

/** HKDF(MK, labels.stream), non-extractable: the root of every blob's key (SPEC §3.1). */
export const contentKey = (labels, masterKey) => hkdfBaseKey(masterKey, labels.stream);

/**
 * Transitional (SPEC §6.13): a vault document of the layout before the tree, JSON in a blob labelled `labels.vault`.
 * Throws `DecryptError` if the blob doesn't decrypt with this key and label.
 */
export async function openDocument(key, label, blob) {
  return JSON.parse(td.decode(await stream.open(key, label, blob)));
}
