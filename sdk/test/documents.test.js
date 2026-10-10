import { test } from "node:test";
import assert from "node:assert/strict";

import { decodeKeys, emptyKeys, encodeKeys, prune, removePasskey, setPasskey, setRecovery } from "../src/keys.js";
import { labels } from "../src/labels.js";
import { formatRecoveryKey, generateRecoveryKey, parseRecoveryKey } from "../src/recovery-key.js";
import { parseSetupFragment, parseSetupInput, setupFragment } from "../src/setup-link.js";

const L = labels("test-app");

test("keys operations", () => {
  const slot = { nonce: "n", wrapped_key: "w", created_at: "t" };
  const doc = setRecovery(slot)(setPasskey("cred-a", slot)(setPasskey("cred-b", slot)(emptyKeys(L))));
  assert.deepEqual(Object.keys(doc.passkeys).sort(), ["cred-a", "cred-b"]);
  assert.deepEqual(Object.keys(removePasskey("cred-a")(doc).passkeys), ["cred-b"]);
  assert.deepEqual(Object.keys(prune(["cred-b", "cred-z"])(doc).passkeys), ["cred-b"]);
  assert.deepEqual(decodeKeys(L, encodeKeys(doc)).doc, doc);
  assert.equal(decodeKeys(L, encodeKeys({ ...doc, version: 2 })).writable, false);
  assert.throws(() => decodeKeys(L, new TextEncoder().encode("{}")));
});

test("recovery keys are 64 hex characters", () => {
  const key = generateRecoveryKey();
  const text = formatRecoveryKey(key);
  assert.match(text, /^[0-9a-f]{64}$/);
  assert.deepEqual(parseRecoveryKey(text), key);
  assert.deepEqual(parseRecoveryKey(` ${text.toUpperCase().slice(0, 32)}\n${text.slice(32)} `), key);
  assert.equal(parseRecoveryKey(text.slice(1)), null);
  assert.equal(parseRecoveryKey(text.slice(1) + "g"), null);
});

test("setup fragments", () => {
  assert.equal(parseSetupFragment("#setup=abc-_123"), "abc-_123");
  assert.equal(parseSetupFragment(setupFragment("tok")), "tok");
  assert.equal(parseSetupFragment(""), null);
  assert.equal(parseSetupFragment("#other=1"), null);
});

test("pasted setup links, fragments and bare tokens", () => {
  const token = "6GDSfvBvNAUfwS4kReEyY94243FhcBg8SjwKZy6C17A";
  assert.equal(parseSetupInput(`http://localhost:8080/#setup=${token}`), token);
  assert.equal(parseSetupInput(` /#setup=${token}\n`), token);
  assert.equal(parseSetupInput(`setup=${token}`), token);
  assert.equal(parseSetupInput(token), token);
  assert.equal(parseSetupInput("hello"), null);
  assert.equal(parseSetupInput("https://example.com/#other=1"), null);
});

test("keys documents need a version from 1 up and well-formed slots", () => {
  const damaged = [{ nonce: "n" }, { nonce: 1, wrapped_key: "w" }, "slot", null];
  const docs = [{ version: 0 }, { version: -1 }, { version: 1.5 }, { passkeys: [] }, { passkeys: null }, { recovery: undefined }, ...damaged.flatMap((slot) => [{ recovery: slot ?? 1 }, { passkeys: { a: slot } }])];
  for (const doc of docs) {
    assert.throws(() => decodeKeys(L, encodeKeys({ ...emptyKeys(L), ...doc })), /Not a keys document/, JSON.stringify(doc));
  }
});

test("a keys document of another app is refused", () => {
  assert.throws(() => decodeKeys(labels("other-app"), encodeKeys(emptyKeys(L))), /Not a keys document/);
});
