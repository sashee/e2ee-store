// The keys document (SPEC §3.3): the master key wrapped once per passkey and once for the recovery key.
// Operations are pure: (doc, now) → doc. `labels` (labels.js) are the app's.

import { aesGcmDecrypt, aesGcmEncrypt, b64urlDecode, b64urlEncode, hkdfAesKey, td, te } from "./crypto.js";

export const VERSION = 1;

export class WrongKeyError extends Error {
  constructor(kind) {
    super(kind === "recovery" ? "Wrong recovery key" : "This passkey's key doesn't unlock the vault");
    this.name = "WrongKeyError";
  }
}

/** Both kinds of secret (a PRF output, the recovery key) and the master key are 32 random bytes. */
function check32(value, what) {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error(`${what} must be 32 bytes`);
}

/** Wraps the master key with the KEK derived from `secret` (a PRF output or the recovery key). */
export async function wrap(labels, kind, secret, masterKey, now) {
  check32(secret, "The key-encryption secret");
  check32(masterKey, "The master key");
  const kek = await hkdfAesKey(secret, labels.kek[kind]);
  const { nonce, ciphertext } = await aesGcmEncrypt(kek, masterKey, te.encode(labels.slot[kind]));
  return { nonce: b64urlEncode(nonce), wrapped_key: b64urlEncode(ciphertext), created_at: new Date(now).toISOString() };
}

export async function unwrap(labels, kind, secret, slot) {
  check32(secret, "The key-encryption secret");
  const kek = await hkdfAesKey(secret, labels.kek[kind]);
  try {
    return await aesGcmDecrypt(kek, b64urlDecode(slot.nonce), b64urlDecode(slot.wrapped_key), te.encode(labels.slot[kind]));
  } catch {
    throw new WrongKeyError(kind);
  }
}

export const emptyKeys = (labels) => ({ format: labels.keysFormat, version: VERSION, recovery: null, passkeys: {} });

const plainObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const isSlot = (slot) => plainObject(slot) && typeof slot.nonce === "string" && typeof slot.wrapped_key === "string";

/**
 * Returns the document, or throws if it isn't one, so a damaged slot isn't taken for a wrong key later. `writable`
 * is false for newer versions.
 */
export function readKeys(labels, doc) {
  const slotsValid = plainObject(doc?.passkeys) && Object.values(doc.passkeys).every(isSlot) && (doc.recovery === null || isSlot(doc.recovery));
  if (doc?.format !== labels.keysFormat || !Number.isInteger(doc.version) || doc.version < 1 || !slotsValid) {
    throw new Error("Not a keys document");
  }
  return { doc, writable: doc.version <= VERSION };
}

export const encodeKeys = (doc) => te.encode(JSON.stringify(doc));
export const decodeKeys = (labels, data) => readKeys(labels, JSON.parse(td.decode(data)));

export const setPasskey = (credentialId, slot) => (doc) => ({ ...doc, passkeys: { ...doc.passkeys, [credentialId]: slot } });

export const removePasskey = (credentialId) => (doc) => {
  const { [credentialId]: _removed, ...passkeys } = doc.passkeys;
  return { ...doc, passkeys };
};

export const setRecovery = (slot) => (doc) => ({ ...doc, recovery: slot });

/** Drops slots of passkeys the server no longer has. */
export const prune = (existingCredentialIds) => (doc) => ({
  ...doc,
  passkeys: Object.fromEntries(Object.entries(doc.passkeys).filter(([id]) => existingCredentialIds.includes(id))),
});
