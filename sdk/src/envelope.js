// The content key (SPEC §3.1): the root every blob's key is derived from.

import { hkdfBaseKey } from "./crypto.js";

/** HKDF(MK, labels.stream), non-extractable: the root of every blob's key (SPEC §3.1). */
export const contentKey = (labels, masterKey) => hkdfBaseKey(masterKey, labels.stream);
