// The recovery key (SPEC §3.4): 32 random bytes as 64 lowercase hex characters.

import { hexDecode, hexEncode, randomBytes } from "./crypto.js";

export const generateRecoveryKey = () => randomBytes(32);

export const formatRecoveryKey = (key) => hexEncode(key);

/** The key's bytes, or null unless the text is exactly 64 hex characters (whitespace ignored). */
export function parseRecoveryKey(text) {
  const normalized = text.replace(/\s+/g, "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(normalized) ? hexDecode(normalized) : null;
}
