// Writes vectors.json: a keys blob and a vault blob of format version 1, built from SPEC.md §2–§3 with
// node:crypto alone, not with the SDK, from fixed keys and nonces. vectors.test.js checks that the SDK opens them,
// so a change to the format (labels, HKDF, padding, layout) can't go unnoticed: data written today must open
// forever (SPEC §2). The output never changes; rerunning this is only for reading how the vectors were made.
//
//   node sdk/test/make-vectors.mjs > sdk/test/vectors.json

import { createCipheriv, createHash, hkdfSync } from "node:crypto";

const namespace = "test-vectors";
const filled = (length, byte) => Buffer.alloc(length, byte);

const masterKey = filled(32, 0x11);
const prfOutput = filled(32, 0x22);
const recoveryKey = filled(32, 0x33);
const credentialId = filled(16, 0x44).toString("base64url");

const hkdf = (ikm, info, length) => Buffer.from(hkdfSync("sha256", ikm, Buffer.alloc(0), info, length));
/** AES-256-GCM: ciphertext ‖ 16-byte tag. */
function seal(key, nonce, plaintext, aad) {
  const cipher = createCipheriv("aes-256-gcm", key, nonce).setAAD(Buffer.from(aad));
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

// §3.3: the master key wrapped under each KEK, with the slot's label as AAD.
const slot = (secret, kind, nonce) => ({
  nonce: nonce.toString("base64url"),
  wrapped_key: seal(hkdf(secret, `${namespace}/kek/${kind}/v1`, 32), nonce, masterKey, `${namespace}/keys/v1/${kind}`).toString("base64url"),
  created_at: "2026-10-10T00:00:00.000Z",
});
const keys = {
  format: `${namespace}/keys`,
  version: 1,
  recovery: slot(recoveryKey, "recovery", filled(12, 0x01)),
  passkeys: { [credentialId]: slot(prfOutput, "passkey", filled(12, 0x02)) },
  // §3.3: unknown fields are preserved.
  added_by_a_later_version: true,
};
const keysBlob = Buffer.from(JSON.stringify(keys));

// §3.2: nonce ‖ AES-256-GCM(content key, JSON padded with spaces to a multiple of 4096) with the vault label as AAD.
const vaultDocument = { format: "test-vectors/notes", revision: 7, notes: ["plain", "ü", "📝"] };
const json = Buffer.from(JSON.stringify(vaultDocument));
const padded = Buffer.concat([json, filled(Math.ceil(json.length / 4096) * 4096 - json.length, 0x20)]);
const vaultNonce = filled(12, 0x03);
const vaultBlob = Buffer.concat([vaultNonce, seal(hkdf(masterKey, `${namespace}/content/v1`, 32), vaultNonce, padded, `${namespace}/vault/v1`)]);

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const vectors = {
  namespace,
  prfInput: `${namespace}/prf/v1`,
  masterKey: masterKey.toString("hex"),
  prfOutput: prfOutput.toString("hex"),
  recoveryKey: recoveryKey.toString("hex"),
  credentialId,
  stateId: hkdf(masterKey, `${namespace}/device-state-id/v1`, 16).toString("hex"),
  keysBlobId: sha256(keysBlob),
  keysBlob: keysBlob.toString("base64"),
  vaultBlobId: sha256(vaultBlob),
  vaultBlob: vaultBlob.toString("base64"),
  vaultDocument,
};
process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);
