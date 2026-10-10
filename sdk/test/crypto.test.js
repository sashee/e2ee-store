import { test } from "node:test";
import assert from "node:assert/strict";

import { aesGcmDecrypt, aesGcmEncrypt, b64urlDecode, b64urlEncode, DecryptError, hexDecode, hexEncode, hkdfAesKey, sha256Hex, te } from "../src/crypto.js";
import { contentKey, openDocument, pad, sealDocument } from "../src/envelope.js";
import { WrongKeyError, unwrap, wrap } from "../src/keys.js";
import { labels } from "../src/labels.js";

const L = labels("test-app");

test("encodings round-trip and reject other alphabets", () => {
  const data = Uint8Array.from([0, 1, 250, 251, 252, 253, 254, 255]);
  assert.equal(b64urlEncode(data), "AAH6-_z9_v8");
  assert.deepEqual(b64urlDecode("AAH6-_z9_v8"), data);
  assert.throws(() => b64urlDecode("AAH6+/z9"));
  assert.equal(hexEncode(data), "0001fafbfcfdfeff");
  assert.deepEqual(hexDecode("0001fafbfcfdfeff"), data);
  assert.throws(() => hexDecode("0001FA"));
  assert.throws(() => hexDecode("abc"));
});

test("sha256 matches the known answer", async () => {
  assert.equal(await sha256Hex(te.encode("hello")), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
});

test("HKDF derives the same key for the same inputs and different ones otherwise", async () => {
  const ikm = new Uint8Array(32).fill(1);
  const aad = te.encode("aad");
  const { nonce, ciphertext } = await aesGcmEncrypt(await hkdfAesKey(ikm, "info-a"), te.encode("secret"), aad);
  assert.equal(new TextDecoder().decode(await aesGcmDecrypt(await hkdfAesKey(ikm, "info-a"), nonce, ciphertext, aad)), "secret");
  await assert.rejects(aesGcmDecrypt(await hkdfAesKey(ikm, "info-b"), nonce, ciphertext, aad), DecryptError);
});

test("tampering with the nonce, ciphertext or AAD fails", async () => {
  const key = await hkdfAesKey(new Uint8Array(32), "k");
  const aad = te.encode("aad");
  const { nonce, ciphertext } = await aesGcmEncrypt(key, te.encode("secret"), aad);
  const flip = (a, i) => Uint8Array.from(a, (b, j) => (j === i ? b ^ 1 : b));
  await assert.rejects(aesGcmDecrypt(key, flip(nonce, 0), ciphertext, aad), DecryptError);
  await assert.rejects(aesGcmDecrypt(key, nonce, flip(ciphertext, 3), aad), DecryptError);
  await assert.rejects(aesGcmDecrypt(key, nonce, ciphertext, te.encode("other")), DecryptError);
});

test("documents are padded to 4 KiB and round-trip", async () => {
  assert.equal(pad(new Uint8Array(1)).length, 4096);
  assert.equal(pad(new Uint8Array(4096)).length, 4096);
  assert.equal(pad(new Uint8Array(4097)).length, 8192);
  const key = await contentKey(L, new Uint8Array(32).fill(7));
  const doc = { format: "test-app/vault", entries: [{ title: "ü" }] };
  const blob = await sealDocument(key, L.vault, doc);
  assert.equal(blob.length, 12 + 4096 + 16, "nonce, one padded block, tag");
  assert.deepEqual(await openDocument(key, L.vault, blob), doc);
  await assert.rejects(openDocument(await contentKey(L, new Uint8Array(32)), L.vault, blob), DecryptError);
  await assert.rejects(openDocument(key, "test-app/other/v1", blob), DecryptError, "the AAD names the kind of blob");
  await assert.rejects(openDocument(await contentKey(labels("other-app"), new Uint8Array(32).fill(7)), L.vault, blob), DecryptError, "another app's content key");
});

test("keyslots unwrap only with the right secret and kind", async () => {
  const masterKey = new Uint8Array(32).fill(9);
  const prf = new Uint8Array(32).fill(3);
  const slot = await wrap(L, "passkey", prf, masterKey, 0);
  assert.equal(slot.created_at, "1970-01-01T00:00:00.000Z");
  assert.deepEqual(await unwrap(L, "passkey", prf, slot), masterKey);
  await assert.rejects(unwrap(L, "passkey", new Uint8Array(32), slot), WrongKeyError);
  await assert.rejects(unwrap(L, "recovery", prf, slot), WrongKeyError, "the kind is bound through the AAD and the KEK");
  await assert.rejects(unwrap(labels("other-app"), "passkey", prf, slot), WrongKeyError, "the app is bound through the labels");
});

import { hkdfBytes } from "../src/crypto.js";
import { prfResult, UserFacingError } from "../src/passkeys.js";

test("keyslots refuse secrets that aren't 32 bytes", async () => {
  const masterKey = new Uint8Array(32).fill(9);
  for (const secret of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33)]) {
    await assert.rejects(wrap(L, "passkey", secret, masterKey, 0), /32 bytes/);
    await assert.rejects(unwrap(L, "passkey", secret, { nonce: "AAAAAAAAAAAAAAAA", wrapped_key: "AA" }), /32 bytes/);
  }
  await assert.rejects(wrap(L, "passkey", new Uint8Array(32), new Uint8Array(16), 0), /master key/);
});

test("PRF outputs must be 32 bytes in an ArrayBuffer or a view", () => {
  const credential = (first) => ({ getClientExtensionResults: () => ({ prf: { results: { first } } }) });
  const buffer = new Uint8Array(32).fill(5).buffer;
  assert.deepEqual(prfResult(credential(buffer)), new Uint8Array(32).fill(5));
  const view = new Uint8Array(40).fill(6).subarray(4, 36);
  assert.deepEqual(prfResult(credential(view)), new Uint8Array(32).fill(6));
  assert.equal(prfResult(credential(undefined)), null);
  assert.equal(prfResult({ getClientExtensionResults: () => ({}) }), null);
  for (const bad of ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", new ArrayBuffer(0), new Uint8Array(16), { length: 32 }, 32]) {
    assert.throws(() => prfResult(credential(bad)), UserFacingError, String(bad));
  }
});

test("HKDF bytes are deterministic and separated by info", async () => {
  const ikm = new Uint8Array(32).fill(1);
  assert.deepEqual(await hkdfBytes(ikm, "a", 16), await hkdfBytes(ikm, "a", 16));
  assert.notDeepEqual(await hkdfBytes(ikm, "a", 16), await hkdfBytes(ikm, "b", 16));
});

test("labels are derived from the namespace, which must be a plain name", () => {
  assert.deepEqual(labels("notes"), {
    prf: "notes/prf/v1",
    keysFormat: "notes/keys",
    kek: { passkey: "notes/kek/passkey/v1", recovery: "notes/kek/recovery/v1" },
    slot: { passkey: "notes/keys/v1/passkey", recovery: "notes/keys/v1/recovery" },
    content: "notes/content/v1",
    vault: "notes/vault/v1",
    stateId: "notes/device-state-id/v1",
  });
  for (const ok of ["1", "my-app", "a.b_c-d", "x".repeat(64)]) assert.equal(labels(ok).vault, `${ok}/vault/v1`);
  for (const bad of ["", "Notes", "a/b", "-x", ".x", "x".repeat(65), undefined]) assert.throws(() => labels(bad), /namespace/, String(bad));
});
