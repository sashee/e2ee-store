// The flows (SPEC §6) against the fake backend and authenticator (fakes.js).

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import * as api from "../src/api.js";
import { contentKey, openDocument } from "../src/envelope.js";
import { makeFlows } from "../src/flows.js";
import { decodeKeys, encodeKeys, WrongKeyError } from "../src/keys.js";
import { labels } from "../src/labels.js";
import { UserFacingError } from "../src/passkeys.js";
import { RollbackError } from "../src/save.js";
import { BOB, fakeAuthenticator, install, useAuthenticator } from "./fakes.js";
import { legacyDocument } from "./reference.mjs";

const L = labels("test-app");
const HOUR = 3600 * 1000;

/** A small vault document: notes, and the two previous versions as history, which `keep` lists. */
const notes = {
  empty: () => ({ format: "test-app/notes", version: 1, revision: 1, notes: [], history: [] }),
  read: (doc) => {
    if (doc?.format !== "test-app/notes") throw new Error("Not a notes document");
    return { doc, writable: doc.version <= 1 };
  },
  commit: (doc, operation, now, loadedBlobId) => ({ ...operation(doc, now), revision: doc.revision + 1, history: [loadedBlobId, ...doc.history].slice(0, 2) }),
  revision: (doc) => doc.revision,
  keep: async (doc) => doc.history,
};
const add = (text) => (doc) => ({ ...doc, notes: [...doc.notes, text] });

const flows = makeFlows({ labels: L, document: notes });
const keysOf = (server) => decodeKeys(L, server.read("keys")).doc;
const lock = (server) => {
  server.session = null;
};
/** Another device rewrites the keys document. */
const writeKeys = (server, doc) => server.refs.set("keys", server.put(encodeKeys(doc)));

/** A setup-token session, as after opening a setup link. */
async function signedUp(options) {
  const fakes = install(options);
  fakes.server.setupToken = "token";
  await api.exchangeSetupToken("token");
  return fakes;
}

/** A new account with its vault, created on this device. */
async function newAccount(options) {
  const fakes = await signedUp(options);
  const registered = await flows.registerPasskey("Laptop");
  const prfOutput = registered.prfOutput ?? (await flows.prfFromPasskey(registered.credentialId));
  const secrets = flows.newSecrets();
  const created = await flows.createVault({ ...secrets, credentialId: registered.credentialId, prfOutput });
  assert.equal(created.kind, "created");
  return { ...fakes, secrets, credentialId: registered.credentialId, session: created.session };
}

test("a new vault unlocks with the passkey that created it, and no secret reaches the server", async () => {
  const { server, secrets, credentialId, session } = await newAccount();
  const keys = keysOf(server);
  assert.deepEqual(Object.keys(keys.passkeys), [credentialId]);
  assert.ok(keys.recovery);
  const { session: saved } = await flows.saveVault(session, add("a secret note"));

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.kind, "unlocked");
  assert.deepEqual(unlocked.session.masterKey, secrets.masterKey);
  assert.deepEqual(unlocked.session.vault.doc, saved.vault.doc);
  assert.equal(unlocked.session.stateId, session.stateId);
  assert.match(session.stateId, /^[0-9a-f]{32}$/);

  // The PRF output never leaves the browser, and the vault's content is only stored encrypted.
  const credentials = server.requests.filter((r) => r.json?.credential).map((r) => r.json.credential);
  assert.equal(credentials.length, 2, "the registration and the unlock's login");
  assert.ok(credentials.every((c) => !("prf" in c.clientExtensionResults)));
  const secret = Buffer.from("a secret note");
  assert.ok([...server.blobs.values()].every(({ bytes }) => Buffer.from(bytes).indexOf(secret) === -1));
});

test("an authenticator that gives the PRF output only at sign-in gets one more prompt", async () => {
  const { server, authenticator, credentialId } = await newAccount({ prfAtCreate: false });
  assert.deepEqual(authenticator.signIns, [[credentialId]], "the extra sign-in is limited to the new passkey");
  lock(server);
  assert.equal((await flows.unlockWithPasskey()).kind, "unlocked");
});

test("an authenticator without PRF is refused before its passkey is registered or used", async () => {
  const { server } = await signedUp({ prf: false });
  await assert.rejects(flows.registerPasskey("Key"), UserFacingError);
  assert.equal(server.passkeys.size, 0);

  const { server: other, authenticator } = await newAccount();
  authenticator.prf = false;
  lock(other);
  await assert.rejects(flows.unlockWithPasskey(), UserFacingError);
  assert.equal(other.session, null, "no login without a PRF output");
});

test("unlocking without a vault, and with a vault whose keys are missing", async () => {
  const { server } = await signedUp();
  await flows.registerPasskey("Laptop");
  assert.deepEqual(await flows.unlockWithPasskey(), { kind: "no-vault" });
  server.refs.set("vault", server.put(new Uint8Array([1, 2, 3])));
  assert.deepEqual(await flows.unlockWithPasskey(), { kind: "keys-missing" });
});

test("a vault without its keys is never replaced by a new one", async () => {
  const { server } = await signedUp();
  const registered = await flows.registerPasskey("Laptop");
  const orphan = server.put(new Uint8Array([1, 2, 3]));
  server.refs.set("vault", orphan);
  const blobs = server.blobs.size;
  const result = await flows.createVault({ ...flows.newSecrets(), ...registered });
  assert.deepEqual(result, { kind: "keys-missing" });
  assert.equal(server.refs.has("keys"), false);
  assert.equal(server.refs.get("vault"), orphan);
  assert.equal(server.blobs.size, blobs, "nothing was uploaded");
});

test("the vault another device created first wins", async () => {
  const { server, authenticator } = await newAccount();
  const keys = server.refs.get("keys");
  const prfOutput = authenticator.credentials.get(authenticator.newest)(new Uint8Array(1));
  const result = await flows.createVault({ ...flows.newSecrets(), credentialId: authenticator.newest, prfOutput });
  assert.deepEqual(result, { kind: "exists" });
  assert.equal(server.refs.get("keys"), keys);
});

test("an interrupted creation gets its empty vault at the next unlock", async () => {
  const { server } = await newAccount();
  server.refs.delete("vault");
  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.kind, "unlocked");
  assert.deepEqual(unlocked.session.vault.doc, notes.empty());
  assert.equal(server.refs.get("vault"), unlocked.session.vault.blobId);
});

test("a passkey without a slot unlocks with the recovery key and then gets its slot", async () => {
  const { server, secrets } = await newAccount();
  useAuthenticator(fakeAuthenticator());
  const phone = await flows.registerPasskey("Phone");
  lock(server);
  const result = await flows.unlockWithPasskey();
  assert.equal(result.kind, "no-slot");
  assert.equal(result.credentialId, phone.credentialId);

  await assert.rejects(flows.unlockWithRecoveryKey(result.keys, new Uint8Array(32)), WrongKeyError);
  const recovered = await flows.unlockWithRecoveryKey(result.keys, secrets.recoveryKey);
  await flows.addPasskeySlot(recovered, result.credentialId, result.prfOutput);
  lock(server);
  assert.equal((await flows.unlockWithPasskey()).kind, "unlocked");
});

test("a credential ID that is also an object property isn't taken for a slot", async () => {
  for (const id of ["constructor", "__proto__", "toString"]) {
    const { server, authenticator } = await newAccount();
    authenticator.add(id, () => new Uint8Array(32).fill(1));
    server.passkeys.set(id, { name: id });
    lock(server);
    assert.equal((await flows.unlockWithPasskey()).kind, "no-slot", id);
  }
});

test("a save that conflicts with another device's is applied on top of it", async () => {
  const { session: laptop } = await newAccount();
  const { session: phone } = await flows.unlockWithPasskey();
  await flows.saveVault(laptop, add("from the laptop"));
  const { session, base } = await flows.saveVault(phone, add("from the phone"));
  assert.deepEqual(base.notes, ["from the laptop"], "what the operation was finally applied to");
  assert.deepEqual(session.vault.doc.notes, ["from the laptop", "from the phone"]);
  assert.equal(session.vault.doc.revision, 3);
});

test("a save that runs into an older vault stops and writes nothing", async () => {
  const { server, session } = await newAccount();
  const { session: second } = await flows.saveVault(session, add("one"));
  const { session: third } = await flows.saveVault(second, add("two"));
  server.refs.set("vault", second.vault.blobId);
  await assert.rejects(flows.saveVault(third, add("three")), RollbackError);
  assert.equal(server.refs.get("vault"), second.vault.blobId);
});

test("a vault from a newer version is read-only and never saved over", async () => {
  const { server, session } = await newAccount();
  const { session: newer } = await flows.saveVault(session, (doc) => ({ ...doc, version: 2 }));
  const current = server.refs.get("vault");
  await assert.rejects(flows.saveVault(session, add("stale")), UserFacingError, "a conflict with a newer version");
  assert.equal(server.refs.get("vault"), current);

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.session.vault.writable, false);
  await assert.rejects(flows.saveVault(unlocked.session, add("x")), UserFacingError);
  assert.equal(newer.vault.blobId, current);
});

test("keys from a newer version are never saved over", async () => {
  const { server, session, credentialId } = await newAccount();
  // Another device, on a newer version of the app, rewrites the keys after this session loaded them.
  writeKeys(server, { ...keysOf(server), version: 2 });
  const current = server.refs.get("keys");
  await assert.rejects(flows.removePasskeySlot(session, credentialId), UserFacingError);
  await assert.rejects(flows.replaceRecoveryKey(session, flows.newSecrets().recoveryKey), UserFacingError);
  assert.equal(server.refs.get("keys"), current);

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.session.keys.writable, false);
  await assert.rejects(flows.removePasskeySlot(unlocked.session, credentialId), UserFacingError);
});

test("keys from a newer version make the vault read-only, as their version covers its format", async () => {
  const { server, secrets } = await newAccount();
  writeKeys(server, { ...keysOf(server), version: 2 });
  const vault = server.refs.get("vault");

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.session.vault.writable, false);
  await assert.rejects(flows.saveVault(unlocked.session, add("x")), /read-only/);
  const recovered = await flows.unlockWithRecoveryKey(await flows.loadKeys(), secrets.recoveryKey);
  assert.equal(recovered.vault.writable, false);
  await assert.rejects(flows.saveVault(recovered, add("x")), /read-only/);
  assert.equal(server.refs.get("vault"), vault);
});

test("a newer version's interrupted creation isn't completed in this version's format", async () => {
  const { server } = await newAccount();
  writeKeys(server, { ...keysOf(server), version: 2 });
  server.refs.delete("vault");
  lock(server);
  await assert.rejects(flows.unlockWithPasskey(), /newer version/);
  assert.equal(server.refs.has("vault"), false);
});

test("a save stops when another device has moved the keys to a newer version since the unlock", async () => {
  const { server, session: laptop } = await newAccount();
  const { session: phone } = await flows.unlockWithPasskey();
  await flows.saveVault(phone, add("from the phone"));
  writeKeys(server, { ...keysOf(server), version: 2 });
  const vault = server.refs.get("vault");
  await assert.rejects(flows.saveVault(laptop, add("from the laptop")), /newer version/);
  assert.equal(server.refs.get("vault"), vault);
});

test("replacing the recovery key retires the old one", async () => {
  const { server, session, secrets } = await newAccount();
  const replacement = flows.newSecrets().recoveryKey;
  const replaced = await flows.replaceRecoveryKey(session, replacement);
  assert.equal(await flows.testRecoveryKey(replaced, replacement), "ok");
  assert.equal(await flows.testRecoveryKey(replaced, secrets.recoveryKey), "wrong");
  const keys = await flows.loadKeys();
  await assert.rejects(flows.unlockWithRecoveryKey(keys, secrets.recoveryKey), WrongKeyError);
  assert.deepEqual((await flows.unlockWithRecoveryKey(keys, replacement)).masterKey, secrets.masterKey);

  writeKeys(server, { ...keysOf(server), recovery: null });
  assert.equal(await flows.testRecoveryKey(replaced, replacement), "missing");
});

test("an old session logs in again before it adds a passkey", async () => {
  const { server, session } = await newAccount();
  server.session.fresh = false;
  await assert.rejects(flows.registerPasskey("Phone"), (e) => e instanceof api.ApiError && e.code === "reauth_required");
  await flows.reauthenticate(session);
  assert.equal(server.session.fresh, true);
  await assert.rejects(flows.registerPasskey("Again"), /already has a passkey/, "this device's authenticator has one");
  useAuthenticator(fakeAuthenticator());
  await flows.registerPasskey("Phone");
  assert.equal(server.passkeys.size, 2);
});

test("logging in again with another account's passkey doesn't switch accounts", async () => {
  const { server, session } = await newAccount();
  // Bob's passkey on the same host, in another authenticator the browser offers.
  const bobs = useAuthenticator(fakeAuthenticator());
  bobs.add("Ym9icyBwYXNza2V5", () => new Uint8Array(32).fill(9));
  server.passkeys.set("Ym9icyBwYXNza2V5", { name: "Bob's", user: BOB });
  server.session.fresh = false;
  await assert.rejects(flows.reauthenticate(session), /another account/);
  assert.equal(server.session, null, "Bob's login doesn't stay");
});

/** An account with five saved versions and a passkey deleted on another device, then a day later. */
async function aDayOfUse() {
  const account = await newAccount();
  const { server } = account;
  useAuthenticator(fakeAuthenticator());
  const phone = await flows.registerPasskey("Phone");
  useAuthenticator(account.authenticator);
  let session = await flows.addPasskeySlot(account.session, phone.credentialId, phone.prfOutput);
  const versions = [session.vault.blobId];
  for (const text of ["a", "b", "c", "d"]) {
    session = (await flows.saveVault(session, add(text))).session;
    versions.push(session.vault.blobId);
  }
  server.passkeys.delete(phone.credentialId);
  server.now += 25 * HOUR;
  return { ...account, session, versions, phone: phone.credentialId };
}

test("cleanup prunes stale slots and deletes old blobs nothing needs, by the server's clock", async () => {
  const { server, session, versions, phone } = await aDayOfUse();
  const young = server.put(new Uint8Array([7]));
  server.pageSize = 2;

  const { session: cleaned, report } = await flows.maintain(session, "manual");
  assert.equal(report.error, null);
  assert.equal(report.slots_removed, 1);
  assert.equal(phone in keysOf(server).passkeys, false);
  assert.equal(cleaned.keys.blobId, server.refs.get("keys"));

  // Kept: the current keys and vault, and the two versions in the history. Deleted: the older versions and
  // the replaced keys blobs. The young blob would be old by the client's clock, which is years ahead.
  const remaining = new Set(server.blobs.keys());
  assert.deepEqual(
    versions.map((id) => remaining.has(id)),
    [false, false, true, true, true],
  );
  assert.ok(remaining.has(young));
  assert.equal(remaining.size, 5);
  assert.equal(report.too_recent.count, 1);
  assert.equal(report.kept.count, 4);
  assert.equal(report.deleted.count, report.blobs_total - 5);
  lock(server);
  assert.deepEqual((await flows.unlockWithPasskey()).session.vault.doc, session.vault.doc);
});

const deletions = (server) => server.requests.filter((r) => r.method === "DELETE" && r.path.startsWith("/blobs/"));

test("cleanup deletes nothing when the server's data can't be trusted", async (t) => {
  const cases = {
    "the server's vault is older than the session's": ({ server, versions }) => server.refs.set("vault", versions[3]),
    "a ref is missing": ({ server }) => server.refs.delete("keys"),
    "the server doesn't say what time it is": ({ server }) => {
      server.sendsDate = false;
    },
    "the server lists an invalid blob ID": ({ server }) => server.blobs.set("../../me", { bytes: new Uint8Array(1), created_at: 0 }),
    "the vault was saved by a newer version": ({ session }) => flows.saveVault(session, (doc) => ({ ...doc, version: 2 })),
    "the keys were saved by a newer version since the unlock": ({ server, phone }) => {
      server.passkeys.set(phone, { name: "Phone" }); // no slot to prune: only the version check stops it
      writeKeys(server, { ...keysOf(server), version: 2 });
    },
  };
  for (const [name, tamper] of Object.entries(cases)) {
    await t.test(name, async () => {
      const account = await aDayOfUse();
      await tamper(account);
      const { report } = await flows.maintain(account.session, "automatic");
      assert.notEqual(report.error, null);
      assert.deepEqual(deletions(account.server), []);
    });
  }
});

test("a failed deletion is reported and the others go ahead", async () => {
  const { server, session, versions } = await aDayOfUse();
  server.failingDeletes.add(versions[0]);
  const { report } = await flows.maintain(session, "manual");
  assert.equal(report.error, null);
  assert.deepEqual(report.failed.map((f) => f.id), [versions[0]]);
  assert.equal(server.blobs.has(versions[1]), false);
});

test("cleanup stops when the session ends", async () => {
  const { server, session } = await aDayOfUse();
  server.session = null;
  const { report } = await flows.maintain(session, "automatic");
  assert.notEqual(report.error, null);
  assert.deepEqual(deletions(server), []);
});

test("putBlob and readBlob use the session's key", async () => {
  const { session } = await newAccount();
  const content = Uint8Array.from({ length: 100_000 }, (_, i) => i % 7);
  const { id, salt } = await flows.putBlob(session, "test-app/file/v1", content);
  const read = async (options, as = session) => new Uint8Array(await new Response((await flows.readBlob(as, "test-app/file/v1", id, options)).stream).arrayBuffer());
  assert.deepEqual(await read(), content);
  assert.deepEqual(await read({ salt, from: 70_000, to: 70_010 }), content.subarray(70_000, 70_010));
  const stranger = { ...session, contentKey: await contentKey(L, new Uint8Array(32)) };
  await assert.rejects(read({}, stranger), api.IntegrityError, "another master key");
});

/** A vault written before the stream format (SPEC §3.5), with its two earlier versions in its history. */
async function legacyAccount() {
  const account = await newAccount();
  const { server, secrets } = account;
  const legacy = (doc) => server.put(legacyDocument({ masterKey: secrets.masterKey, namespace: "test-app", label: L.vault, nonce: randomBytes(12), doc }));
  const first = { format: "test-app/notes", version: 1, revision: 5, notes: ["a"], history: [] };
  const second = { ...first, revision: 6, notes: ["a", "b"], history: [legacy(first)] };
  const current = { ...first, revision: 7, notes: ["a", "b", "c"], history: [legacy(second), second.history[0]] };
  server.refs.set("vault", legacy(current));
  lock(server);
  const { session } = await flows.unlockWithPasskey();
  return { ...account, session, current, second };
}

/** Rewrites the history the notes document keeps after the next commit: the newest earlier version. */
const resealHistory = async (doc, reseal) => ({ ...doc, history: await Promise.all(doc.history.slice(0, 1).map((id) => reseal(id))) });

test("a vault from before the stream format opens, and upgrading rewrites it and its history", async () => {
  const { server, session, current, second } = await legacyAccount();
  assert.equal(session.vault.legacy, true);
  assert.deepEqual(session.vault.doc, current);

  const upgraded = await flows.upgradeVault(session, resealHistory);
  assert.equal(upgraded.vault.legacy, false);
  assert.equal(server.refs.get("vault"), upgraded.vault.blobId);
  assert.deepEqual(upgraded.vault.doc.notes, current.notes);
  assert.equal(upgraded.vault.doc.revision, current.revision + 1);
  // The history: the loaded vault, then its newest earlier version, both rewritten in the stream format.
  const opened = await Promise.all(upgraded.vault.doc.history.map((id) => openDocument(session.contentKey, L.vault, server.blobs.get(id).bytes)));
  assert.deepEqual(opened, [current, second]);

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.session.vault.legacy, false);
  assert.deepEqual(unlocked.session.vault.doc, upgraded.vault.doc);
  server.requests = [];
  assert.equal(await flows.upgradeVault(unlocked.session, resealHistory), unlocked.session, "nothing left to upgrade");
  assert.deepEqual(server.requests, []);
});

test("an upgrade that runs into another device's save changes nothing", async () => {
  const { server, session } = await legacyAccount();
  const other = server.put(new Uint8Array([1]));
  server.refs.set("vault", other);
  assert.equal(await flows.upgradeVault(session, resealHistory), session);
  assert.equal(server.refs.get("vault"), other);
});

test("a vault from before the stream format is saved in the stream format", async () => {
  const { server, session } = await legacyAccount();
  const { session: saved } = await flows.saveVault(session, add("d"));
  assert.equal(saved.vault.legacy, false);
  assert.deepEqual((await openDocument(session.contentKey, L.vault, server.read("vault"))).notes, ["a", "b", "c", "d"]);
});

test("a read-only vault from before the stream format isn't upgraded", async () => {
  const { server } = await legacyAccount();
  writeKeys(server, { ...keysOf(server), version: 2 });
  const vault = server.refs.get("vault");
  const { session } = await flows.unlockWithPasskey();
  assert.equal(session.vault.writable, false);
  assert.equal(await flows.upgradeVault(session, resealHistory), session);
  assert.equal(server.refs.get("vault"), vault);
});

test("a vault that opens in neither format, or isn't JSON, is an integrity error, and nothing is written", async () => {
  const { server, session } = await newAccount();
  const notJson = (await flows.putBlob(session, L.vault, new TextEncoder().encode("not JSON"))).id;
  for (const vault of [server.put(randomBytes(4152)), notJson]) {
    server.refs.set("vault", vault);
    const before = new Map(server.refs);
    lock(server);
    await assert.rejects(flows.unlockWithPasskey(), api.IntegrityError);
    assert.deepEqual(server.refs, before);
  }
});

test("an upgrade that can't read a blob it rewrites stops, changing nothing", async () => {
  const { server, session, current } = await legacyAccount();
  server.blobs.delete(current.history[0]);
  const vault = server.refs.get("vault");
  await assert.rejects(flows.upgradeVault(session, resealHistory), api.ApiError);
  assert.equal(server.refs.get("vault"), vault);
});

test("after the upgrade, cleanup deletes the blobs of the old format", async () => {
  const { server, session, current } = await legacyAccount();
  const old = [session.vault.blobId, ...current.history];
  const upgraded = await flows.upgradeVault(session, resealHistory);
  server.now += 25 * HOUR;
  const { report } = await flows.maintain(upgraded, "manual");
  assert.equal(report.error, null);
  assert.deepEqual(old.filter((id) => server.blobs.has(id)), [], "the old-format blobs are gone");
  assert.ok([upgraded.vault.blobId, ...upgraded.vault.doc.history].every((id) => server.blobs.has(id)), "the upgraded ones stay");
  lock(server);
  assert.deepEqual((await flows.unlockWithPasskey()).session.vault.doc, upgraded.vault.doc);
});
