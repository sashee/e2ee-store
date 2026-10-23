// Data made by make-vectors.mjs from the SPEC without the SDK must open forever (SPEC §2): keys of version 1, a root
// directory and the file it lists.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { hexDecode } from "../src/crypto.js";
import { makeFlows } from "../src/flows.js";
import { decodeKeys } from "../src/keys.js";
import { labels } from "../src/labels.js";
import { parseRecoveryKey } from "../src/recovery-key.js";
import { install } from "./fakes.js";
import { sha256, streamBlob } from "./reference.mjs";

const v = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const L = labels(v.namespace);
const flows = makeFlows({ labels: L });
const content = Uint8Array.from({ length: v.file.length }, (_, i) => i % 251);

/** The fake backend with the vectors' blobs, and an authenticator holding the vectors' passkey. */
function stored() {
  const { server, authenticator } = install();
  const file = streamBlob({ masterKey: Buffer.from(v.masterKey, "hex"), namespace: v.namespace, label: v.file.label, salt: Buffer.from(v.file.salt, "hex"), plaintext: content });
  assert.equal(sha256(file), v.file.blobId, "reference.mjs still makes the vector's file blob");
  const ids = [v.keysBlob, v.rootBlob].map((blob) => server.put(Buffer.from(blob, "base64")));
  assert.deepEqual([...ids, server.put(file)], [v.keysBlobId, v.rootBlobId, v.file.blobId], "the vectors are intact");
  server.refs.set("keys", v.keysBlobId);
  server.refs.set("vault", v.rootBlobId);
  server.passkeys.set(v.credentialId, { name: "Vectors" });
  authenticator.add(v.credentialId, (input) => {
    assert.equal(new TextDecoder().decode(input), v.prfInput, "the PRF input");
    return hexDecode(v.prfOutput);
  });
  return server;
}

const opened = (session) => {
  assert.deepEqual(session.masterKey, hexDecode(v.masterKey));
  assert.deepEqual({ ...session.root, blobId: undefined, writable: undefined }, { ...v.root, blobId: undefined, writable: undefined });
  assert.equal(session.root.writable, true);
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

test("the file the root lists reads whole and in ranges", async () => {
  stored();
  const { session } = await flows.unlockWithPasskey();
  const [entry] = await flows.list(session, []);
  const read = async (options) => {
    const { size, stream } = await flows.read(session, entry, options);
    return { size, bytes: new Uint8Array(await new Response(stream).arrayBuffer()) };
  };
  assert.deepEqual(await read(), { size: v.file.length, bytes: content });
  assert.deepEqual(await read({ from: 65000, to: 66000 }), { size: v.file.length, bytes: content.subarray(65000, 66000) });
});

