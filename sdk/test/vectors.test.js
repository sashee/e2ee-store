// Data made by make-vectors.mjs from the SPEC without the SDK must open forever (SPEC §2): keys of version 1, a vault in
// the stream format and one in the format before it, and a file blob.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { hexDecode } from "../src/crypto.js";
import { openDocument } from "../src/envelope.js";
import { makeFlows } from "../src/flows.js";
import { decodeKeys } from "../src/keys.js";
import { labels } from "../src/labels.js";
import { parseRecoveryKey } from "../src/recovery-key.js";
import { install } from "./fakes.js";
import { sha256, streamBlob } from "./reference.mjs";

const v = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const L = labels(v.namespace);
const flows = makeFlows({
  labels: L,
  document: { empty: () => assert.fail("a vault exists"), read: (doc) => ({ doc, writable: true }), commit: () => assert.fail("not saved"), revision: (doc) => doc.revision, keep: () => [] },
});

/** The fake backend with the vectors' blobs, and an authenticator holding the vectors' passkey. */
function stored({ vault = v.vaultBlobId } = {}) {
  const { server, authenticator } = install();
  const ids = [server.put(Buffer.from(v.keysBlob, "base64")), server.put(Buffer.from(v.vaultBlob, "base64")), server.put(Buffer.from(v.streamVaultBlob, "base64"))];
  assert.deepEqual(ids, [v.keysBlobId, v.vaultBlobId, v.streamVaultBlobId], "the vectors are intact");
  server.refs.set("keys", v.keysBlobId);
  server.refs.set("vault", vault);
  server.passkeys.set(v.credentialId, { name: "Vectors" });
  authenticator.add(v.credentialId, (input) => {
    assert.equal(new TextDecoder().decode(input), v.prfInput, "the PRF input");
    return hexDecode(v.prfOutput);
  });
  return server;
}

const opened = (session, { legacy = true } = {}) => {
  assert.deepEqual(session.masterKey, hexDecode(v.masterKey));
  assert.deepEqual(session.vault.doc, v.vaultDocument);
  assert.equal(session.vault.legacy, legacy);
  assert.equal(session.stateId, v.stateId, "what the device remembers is filed under the same ID");
  assert.equal(session.keys.writable, true);
};

test("the passkey opens version 1 data", async () => {
  stored();
  const result = await flows.unlockWithPasskey();
  assert.equal(result.kind, "unlocked");
  opened(result.session);
});

test("the recovery key opens version 1 data, and rewriting the keys keeps fields from later versions", async () => {
  const server = stored();
  server.session = { passkey: null, fresh: true };
  const session = await flows.unlockWithRecoveryKey(await flows.loadKeys(), parseRecoveryKey(v.recoveryKey));
  opened(session);
  await flows.replaceRecoveryKey(session, flows.newSecrets().recoveryKey);
  assert.equal(decodeKeys(L, server.read("keys")).doc.added_by_a_later_version, true);
});

test("the passkey opens a vault in the stream format", async () => {
  stored({ vault: v.streamVaultBlobId });
  const result = await flows.unlockWithPasskey();
  opened(result.session, { legacy: false });
  assert.deepEqual(await openDocument(result.session.contentKey, L.vault, Buffer.from(v.streamVaultBlob, "base64")), v.vaultDocument);
});

test("a file blob in the stream format reads whole and in ranges", async () => {
  const server = stored({ vault: v.streamVaultBlobId });
  const content = Uint8Array.from({ length: v.file.length }, (_, i) => i % 251);
  const blob = streamBlob({ masterKey: Buffer.from(v.masterKey, "hex"), namespace: v.namespace, label: v.file.label, salt: Buffer.from(v.file.salt, "hex"), plaintext: content });
  assert.equal(sha256(blob), v.file.blobId, "reference.mjs still makes the vector's blob");
  server.put(blob);
  const { session } = await flows.unlockWithPasskey();
  const read = async (options) => {
    const { size, stream } = await flows.readBlob(session, v.file.label, v.file.blobId, options);
    return { size, bytes: new Uint8Array(await new Response(stream).arrayBuffer()) };
  };
  assert.deepEqual(await read(), { size: v.file.length, bytes: content });
  assert.deepEqual(await read({ salt: v.file.salt, from: 65000, to: 66000 }), { size: v.file.length, bytes: content.subarray(65000, 66000) });
});
