// Writes vectors.json: a keys blob, a vault blob, and the recipe and ID of a file blob that spans two chunks, built
// from SPEC.md §2–§3 with node:crypto alone (reference.mjs), not with the SDK, from fixed keys, nonces and salts.
// vectors.test.js checks that the SDK opens them, so a change to a format (labels, HKDF, padding, layout) can't go
// unnoticed: data written today must open forever (SPEC §2). The output never changes; rerunning this is only for
// reading how the vectors were made.
//
//   node sdk/test/make-vectors.mjs > sdk/test/vectors.json

import { hkdf, seal, sha256, streamBlob } from "./reference.mjs";

const namespace = "test-vectors";
const filled = (length, byte) => Buffer.alloc(length, byte);

const masterKey = filled(32, 0x11);
const prfOutput = filled(32, 0x22);
const recoveryKey = filled(32, 0x33);
const credentialId = filled(16, 0x44).toString("base64url");

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

const vaultDocument = { format: "test-vectors/notes", revision: 7, notes: ["plain", "ü", "📝"] };
// §3.2: the vault document in an encrypted blob.
const vaultBlob = streamBlob({ masterKey, namespace, label: `${namespace}/vault/v1`, salt: filled(16, 0x05), plaintext: Buffer.from(JSON.stringify(vaultDocument)) });

// §3.2: a file of 70,000 bytes, byte i being i mod 251: a full chunk and one of 8192 padded bytes. Only its ID is
// stored; the test makes it again with reference.mjs.
const file = { label: `${namespace}/file/v1`, salt: filled(16, 0x06).toString("hex"), length: 70000 };
const fileBlob = streamBlob({ masterKey, namespace, label: file.label, salt: Buffer.from(file.salt, "hex"), plaintext: Buffer.from(Array.from({ length: file.length }, (_, i) => i % 251)) });

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
  file: { ...file, blobId: sha256(fileBlob) },
};
process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);
