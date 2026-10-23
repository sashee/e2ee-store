// The flows (SPEC §6) against the fake backend and authenticator (fakes.js).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

import * as api from "../src/api.js";
import { contentKey } from "../src/envelope.js";
import { makeFlows } from "../src/flows.js";
import { decodeKeys, encodeKeys, WrongKeyError } from "../src/keys.js";
import { labels } from "../src/labels.js";
import { UserFacingError } from "../src/passkeys.js";
import { RollbackError } from "../src/save.js";
import * as stream from "../src/stream.js";
import { TreeError } from "../src/tree.js";
import { BOB, fakeAuthenticator, install, useAuthenticator } from "./fakes.js";

const L = labels("test-app");
const HOUR = 3600 * 1000;
const flows = makeFlows({ labels: L });

const te = new TextEncoder();
const td = new TextDecoder();
const encode = (value) => te.encode(JSON.stringify(value));
const decode = (bytes) => (bytes === null ? null : JSON.parse(td.decode(bytes)));
const NOTES = ["notes.json"];
/** A step adding a note to notes.json, as it is when the step runs. */
const add = (text) => async (tx) => tx.put(NOTES, tx.upload(encode([...(decode(await tx.read(NOTES)) ?? []), text])));
const collect = async (opened) => new Uint8Array(await new Response((await opened).stream).arrayBuffer());
/** The notes in a session's tree. */
async function notesOf(session) {
  const entry = (await flows.list(session, [])).find((e) => e.name === "notes.json");
  return entry ? decode(await collect(flows.read(session, entry))) : null;
}
const rootOf = ({ blobId: _blobId, writable: _writable, ...doc }) => doc;

const keysOf = (server) => decodeKeys(L, server.read("keys")).doc;
const lock = (server) => {
  server.session = null;
};
/** Another device rewrites the keys document. */
const writeKeys = (server, doc) => server.refs.set("keys", server.put(encodeKeys(doc)));
/** Another device writes this root directory, e.g. one of a newer version. */
async function writeRoot(server, session, doc) {
  server.refs.set("vault", server.put(await stream.seal(session.contentKey, L.dir, encode(doc))));
}

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
  assert.deepEqual(rootOf(session.root), { version: 1, revision: 1, entries: [] });
  const { session: saved } = await flows.save(session, [add("a secret note")]);

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.kind, "unlocked");
  assert.deepEqual(unlocked.session.masterKey, secrets.masterKey);
  assert.deepEqual(unlocked.session.root, saved.root);
  assert.deepEqual(await notesOf(unlocked.session), ["a secret note"]);
  assert.equal(unlocked.session.stateId, session.stateId);
  assert.match(session.stateId, /^[0-9a-f]{32}$/);

  // The PRF output never leaves the browser, and the vault's content is only stored encrypted.
  const credentials = server.requests.filter((r) => r.json?.credential).map((r) => r.json.credential);
  assert.equal(credentials.length, 2, "the registration and the unlock's login");
  assert.ok(credentials.every((c) => !("prf" in c.clientExtensionResults)));
  for (const secret of ["a secret note", "notes.json"]) {
    assert.ok([...server.blobs.values()].every(({ bytes }) => Buffer.from(bytes).indexOf(Buffer.from(secret)) === -1), secret);
  }
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

test("a newer version's interrupted creation isn't completed in this version's format", async () => {
  const { server } = await newAccount();
  writeKeys(server, { ...keysOf(server), version: 2 });
  server.refs.delete("vault");
  lock(server);
  await assert.rejects(flows.unlockWithPasskey(), /newer version/);
  assert.equal(server.refs.has("vault"), false);
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

test("an interrupted creation gets its empty root at the next unlock", async () => {
  const { server } = await newAccount();
  server.refs.delete("vault");
  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.kind, "unlocked");
  assert.deepEqual(rootOf(unlocked.session.root), { version: 1, revision: 1, entries: [] });
  assert.equal(server.refs.get("vault"), unlocked.session.root.blobId);
});

test("files saved in the tree read whole and in ranges, with the session's key", async () => {
  const { session } = await newAccount();
  const content = Uint8Array.from({ length: 100_000 }, (_, i) => i % 7);
  const { session: saved } = await flows.save(session, [(tx) => tx.put(["Music", "a.bin"], tx.upload(content, { app: { tag: 1 } }))]);
  const [entry] = await flows.list(saved, ["Music"]);
  assert.deepEqual([entry.name, entry.size, entry.app], ["a.bin", 100_000, { tag: 1 }]);
  assert.equal(entry.sha256, createHash("sha256").update(content).digest("hex"));
  assert.deepEqual(await collect(flows.read(saved, entry)), content);
  assert.deepEqual(await collect(flows.read(saved, entry, { from: 70_000, to: 70_010 })), content.subarray(70_000, 70_010));
  const stranger = { ...saved, contentKey: await contentKey(L, new Uint8Array(32)) };
  await assert.rejects(collect(flows.read(stranger, entry)), api.IntegrityError, "another master key");
  assert.throws(() => flows.read(saved, { id: entry.id }), TypeError, "a ref has a salt");
  await assert.rejects(flows.list(saved, ["Music", "a.bin"]), /is a file/);
});

test("a save that conflicts with another device's runs its steps again on top of it", async () => {
  const { session: laptop } = await newAccount();
  const { session: phone } = await flows.unlockWithPasskey();
  await flows.save(laptop, [add("from the laptop")]);
  const { session } = await flows.save(phone, [add("from the phone")]);
  assert.deepEqual(await notesOf(session), ["from the laptop", "from the phone"]);
  assert.equal(session.root.revision, 3);
});

test("after a conflict, the steps can put back entries of the newer root", async () => {
  const { session: laptop } = await newAccount();
  const { session: phone } = await flows.unlockWithPasskey();
  await flows.save(laptop, [add("from the laptop")]);
  // Keeps a copy of the notes before changing them, as an app keeping versions does: the copy is of the newer root's.
  const backup = async (tx) => {
    const current = await tx.entry(NOTES);
    return current ? tx.put([`notes@${tx.revision}`], current) : tx;
  };
  const { session } = await flows.save(phone, [backup, add("from the phone")]);
  assert.deepEqual((await flows.list(session, [])).map((e) => e.name), ["notes.json", "notes@2"]);
  const copy = (await flows.list(session, [])).find((e) => e.name === "notes@2");
  assert.deepEqual(decode(await collect(flows.read(session, copy))), ["from the laptop"]);
  assert.deepEqual(await notesOf(session), ["from the laptop", "from the phone"]);
});

test("after a conflict the steps run again, but what they upload is uploaded once", async () => {
  const { server, session: laptop } = await newAccount();
  const { session: phone } = await flows.unlockWithPasskey();
  await flows.save(laptop, [add("from the laptop")]);
  const big = new Uint8Array(200_000).fill(7);
  server.requests = [];
  const { session } = await flows.save(phone, [(tx) => tx.put(["big.bin"], tx.upload(big))]);
  const uploads = server.requests.filter((r) => r.method === "PUT" && r.path.startsWith("/blobs/"));
  assert.equal(uploads.length, 3, "the file once, and a root for each of the two attempts");
  assert.deepEqual((await flows.list(session, [])).map((e) => e.name), ["big.bin", "notes.json"]);
});

test("a save reports its uploads, and an abort before the ref moves changes nothing", async () => {
  const { server, session } = await newAccount();
  const progress = [];
  const { session: saved } = await flows.save(
    session,
    [(tx) => tx.put(["a"], tx.upload(new Uint8Array(10))).put(["b"], tx.upload(new Uint8Array(20)))],
    { onProgress: (p) => progress.push(p) },
  );
  assert.deepEqual(progress[0], { files: 0, bytes: 0, totalFiles: 2, totalBytes: 30 });
  assert.deepEqual(progress.at(-1), { files: 2, bytes: 30, totalFiles: 2, totalBytes: 30 });

  const vault = server.refs.get("vault");
  const controller = new AbortController();
  const reason = new Error("stop");
  const aborting = (tx) => {
    controller.abort(reason);
    return tx.put(["c"], tx.upload(new Uint8Array(5)));
  };
  await assert.rejects(flows.save(saved, [aborting], { signal: controller.signal }), (e) => e === reason);
  await assert.rejects(flows.save(saved, [add("x")], { signal: controller.signal }), (e) => e === reason, "already aborted");
  assert.equal(server.refs.get("vault"), vault);
  await assert.rejects(flows.save(saved, [(tx) => tx.put(["d"], null)]), /nothing to put/);
  await assert.rejects(flows.save(saved, [() => "not a tx"]), TypeError);
  assert.equal(server.refs.get("vault"), vault);
});

test("a file over the backend's limit fails the whole save, naming it, and moves nothing", async () => {
  const { server, session } = await newAccount();
  server.maxBlobSize = 10_000;
  const vault = server.refs.get("vault");
  const steps = [(tx) => tx.put(["small.txt"], tx.upload(encode("fits"))), (tx) => tx.put(["Big", "film.bin"], tx.upload(new Uint8Array(20_000)))];
  await assert.rejects(flows.save(session, steps), (e) => e instanceof TreeError && e.code === "too_large" && e.path.join("/") === "Big/film.bin");
  assert.equal(server.refs.get("vault"), vault);
  assert.deepEqual(await flows.list(session, []), []);
});

test("a Blob is read only when it's uploaded, and counts in the progress by its size", async () => {
  const { session } = await newAccount();
  const content = Uint8Array.from({ length: 70_000 }, (_, i) => i % 13);
  const blob = new Blob([content]);
  const progress = [];
  const { session: saved } = await flows.save(session, [(tx) => tx.put(["blob.bin"], tx.upload(blob))], { onProgress: (p) => progress.push(p) });
  assert.deepEqual(progress.at(-1), { files: 1, bytes: 70_000, totalFiles: 1, totalBytes: 70_000 });
  const [entry] = await flows.list(saved, []);
  assert.equal(entry.size, 70_000);
  assert.deepEqual(await collect(flows.read(saved, entry)), content);
});

test("files can be offloadable, their directories and the root never are, and the flag changes by blob ID", async () => {
  const { server, session } = await newAccount();
  const content = encode("a song");
  const { session: saved } = await flows.save(session, [(tx) => tx.put(["Music", "a.flac"], tx.upload(content, { offloadable: true })).put(NOTES, tx.upload(encode([])))]);
  const flag = (id) => server.blobs.get(id).offloadable;
  const [song] = await flows.list(saved, ["Music"]);
  const [music, notes] = await flows.list(saved, []);
  assert.deepEqual([flag(song.id), flag(notes.id), flag(music.id), flag(saved.root.blobId)], [true, false, false, false]);
  assert.equal("offloadable" in song, false, "entries don't record the flag");
  assert.deepEqual(await collect(flows.read(saved, song)), content, "an offloadable file reads like any other");

  await flows.setOffloadable(saved, [song.id], false);
  await flows.setOffloadable(saved, [notes.id, song.id], true);
  assert.deepEqual([flag(song.id), flag(notes.id)], [true, true]);
  const patches = () => server.requests.filter((r) => r.method === "PATCH").length;
  const sent = patches();
  await assert.rejects(flows.setOffloadable(saved, [song.id, music.id], true), TypeError, "a directory the session knows");
  assert.equal(patches(), sent, "nothing is sent then");
  await assert.rejects(flows.setOffloadable(saved, [saved.root.blobId], true), (e) => e.code === "blob_offloadable" && e.message === "The vault's root has to stay in the server's database.");
  assert.equal(flag(saved.root.blobId), false);
  await flows.setOffloadable(saved, [music.id], false);
  await assert.rejects(flows.setOffloadable(saved, song.id, true), TypeError);
  await assert.rejects(flows.setOffloadable(saved, [song.id], "true"), TypeError);
});

test("the same content uploaded offloadable and not is two files, each uploaded once", async () => {
  const { server, session } = await newAccount();
  const source = encode("same");
  const progress = [];
  const step = (tx) => tx.put(["a"], tx.upload(source, { offloadable: true })).put(["b"], tx.upload(source)).put(["c"], tx.upload(source, { offloadable: true }));
  server.requests = [];
  const { session: saved } = await flows.save(session, [step], { onProgress: (p) => progress.push(p) });
  const uploads = server.requests.filter((r) => r.method === "PUT" && r.path.startsWith("/blobs/"));
  assert.equal(uploads.length, 3, "two files and the root");
  const [a, b, c] = await flows.list(saved, []);
  assert.equal(c.id, a.id);
  assert.notEqual(b.id, a.id);
  assert.deepEqual([server.blobs.get(a.id).offloadable, server.blobs.get(b.id).offloadable], [true, false]);
  assert.deepEqual(progress.at(-1), { files: 2, bytes: 12, totalFiles: 2, totalBytes: 12 });
});

test("a file the server has lost is a BlobLostError naming its blob", async () => {
  const { server, session } = await newAccount();
  const { session: saved } = await flows.save(session, [(tx) => tx.put(["a.flac"], tx.upload(new Uint8Array(100_000), { offloadable: true }))]);
  const [entry] = await flows.list(saved, []);
  server.lost.add(entry.id);
  const isLost = (e) => e instanceof api.BlobLostError && e instanceof api.ApiError && e.id === entry.id && e.code === "blob_lost" && e.status === 410;
  for (const range of [{}, { from: 0, to: 10 }, { from: 70_000, to: 70_010 }]) {
    await assert.rejects(collect(flows.read(saved, entry, range)), isLost, JSON.stringify(range));
  }
  await assert.rejects(flows.save(saved, [async (tx) => (await tx.read(["a.flac"])) && tx]), isLost);
});

test("a save takes an array of step functions", async () => {
  const { server, session } = await newAccount();
  const vault = server.refs.get("vault");
  for (const steps of [(tx) => tx, [add("x"), "not a step"], undefined]) await assert.rejects(flows.save(session, steps), TypeError, String(steps));
  assert.equal(server.refs.get("vault"), vault);
});

test("a save that runs into an older root stops and writes nothing", async () => {
  const { server, session } = await newAccount();
  const { session: second } = await flows.save(session, [add("one")]);
  const { session: third } = await flows.save(second, [add("two")]);
  server.refs.set("vault", second.root.blobId);
  await assert.rejects(flows.save(third, [add("three")]), RollbackError);
  assert.equal(server.refs.get("vault"), second.root.blobId);
});

test("a tree from a newer version is read-only and never saved over", async () => {
  const { server, session } = await newAccount();
  await writeRoot(server, session, { version: 2, revision: 2, entries: [] });
  const current = server.refs.get("vault");
  await assert.rejects(flows.save(session, [add("stale")]), UserFacingError, "a conflict with a newer version");
  assert.equal(server.refs.get("vault"), current);

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.session.root.writable, false);
  await assert.rejects(flows.save(unlocked.session, [add("x")]), UserFacingError);
  assert.deepEqual(await flows.list(unlocked.session, []), [], "it can still be read");
  assert.equal(server.refs.get("vault"), current);
});

test("keys from a newer version make the tree read-only, as their version covers its format", async () => {
  const { server, secrets } = await newAccount();
  writeKeys(server, { ...keysOf(server), version: 2 });
  const vault = server.refs.get("vault");

  lock(server);
  const unlocked = await flows.unlockWithPasskey();
  assert.equal(unlocked.session.root.writable, false);
  await assert.rejects(flows.save(unlocked.session, [add("x")]), /read-only/);
  const recovered = await flows.unlockWithRecoveryKey(await flows.loadKeys(), secrets.recoveryKey);
  assert.equal(recovered.root.writable, false);
  await assert.rejects(flows.save(recovered, [add("x")]), /read-only/);
  assert.equal(server.refs.get("vault"), vault);
});

test("a save stops when another device has moved the keys to a newer version since the unlock", async () => {
  const { server, session: laptop } = await newAccount();
  const { session: phone } = await flows.unlockWithPasskey();
  await flows.save(phone, [add("from the phone")]);
  writeKeys(server, { ...keysOf(server), version: 2 });
  const vault = server.refs.get("vault");
  await assert.rejects(flows.save(laptop, [add("from the laptop")]), /newer version/);
  assert.equal(server.refs.get("vault"), vault);
});

test("a vault that doesn't decrypt, or isn't a directory, is an integrity error, and nothing is written", async () => {
  const { server, session } = await newAccount();
  const notADirectory = server.put(await stream.seal(session.contentKey, L.dir, encode({ notes: [] })));
  for (const vault of [server.put(randomBytes(4152)), notADirectory]) {
    server.refs.set("vault", vault);
    const before = new Map(server.refs);
    lock(server);
    await assert.rejects(flows.unlockWithPasskey(), api.IntegrityError);
    assert.deepEqual(server.refs, before);
  }
});

test("a directory that isn't one, or a file where a directory should be, is an integrity error", async () => {
  const { server, session } = await newAccount();
  const notADirectory = server.put(await stream.seal(session.contentKey, L.dir, encode({ entries: "no" })));
  const { session: saved } = await flows.save(session, [(tx) => tx.put(["f"], tx.upload(encode("a file")))]);
  const [file] = await flows.list(saved, []);
  for (const id of [notADirectory, file.id]) {
    await writeRoot(server, saved, { version: 1, revision: 9, entries: [{ name: "d", kind: "dir", id, salt: file.salt }] });
    lock(server);
    const { session: unlocked } = await flows.unlockWithPasskey();
    await assert.rejects(flows.list(unlocked, ["d"]), api.IntegrityError, id);
  }
});

/**
 * An account a day old: five saves of notes.json, a copy of its second version kept in history/, and a passkey
 * deleted on another device.
 */
async function aDayOfUse() {
  const account = await newAccount();
  const { server } = account;
  useAuthenticator(fakeAuthenticator());
  const phone = await flows.registerPasskey("Phone");
  useAuthenticator(account.authenticator);
  let session = await flows.addPasskeySlot(account.session, phone.credentialId, phone.prfOutput);
  const roots = [session.root.blobId];
  const versions = [];
  for (const text of ["a", "b", "c", "d"]) {
    session = (await flows.save(session, [add(text)])).session;
    roots.push(session.root.blobId);
    versions.push((await flows.list(session, [])).find((e) => e.name === "notes.json"));
  }
  session = (await flows.save(session, [(tx) => tx.put(["history", "notes-2.json"], versions[1])])).session;
  roots.push(session.root.blobId);
  server.passkeys.delete(phone.credentialId);
  server.now += 25 * HOUR;
  return { ...account, session, roots, versions, history: (await flows.list(session, [])).find((e) => e.name === "history"), phone: phone.credentialId };
}

test("cleanup prunes stale slots and deletes what the tree doesn't reach, by the server's clock", async () => {
  const { server, session, roots, versions, history, phone } = await aDayOfUse();
  const young = server.put(new Uint8Array([7]));
  server.pageSize = 2;

  const { session: cleaned, report } = await flows.maintain(session, "manual");
  assert.equal(report.error, null);
  assert.equal(report.slots_removed, 1);
  assert.equal(phone in keysOf(server).passkeys, false);
  assert.equal(cleaned.keys.blobId, server.refs.get("keys"));

  // Kept: the current keys and root, the latest notes, the history directory and the version it keeps. Deleted: the
  // earlier roots and keys, and the notes nothing lists. The young blob would be old by the client's clock.
  const remaining = new Set(server.blobs.keys());
  assert.deepEqual(roots.map((id) => remaining.has(id)), [false, false, false, false, false, true]);
  assert.deepEqual(versions.map((v) => remaining.has(v.id)), [false, true, false, true]);
  assert.ok(remaining.has(history.id));
  assert.ok(remaining.has(young));
  assert.equal(remaining.size, 6);
  assert.equal(report.too_recent.count, 1);
  assert.equal(report.kept.count, 5);
  assert.equal(report.deleted.count, report.blobs_total - 6);
  lock(server);
  const unlocked = (await flows.unlockWithPasskey()).session;
  assert.deepEqual(await notesOf(unlocked), ["a", "b", "c", "d"]);
  assert.deepEqual(decode(await collect(flows.read(unlocked, (await flows.list(unlocked, ["history"]))[0]))), ["a", "b"]);
});

const deletions = (server) => server.requests.filter((r) => r.method === "DELETE" && r.path.startsWith("/blobs/"));

test("cleanup deletes nothing when the server's data can't be trusted", async (t) => {
  const cases = {
    "the server's root is older than the session's": ({ server, roots }) => server.refs.set("vault", roots[3]),
    "a ref is missing": ({ server }) => server.refs.delete("keys"),
    "the server doesn't say what time it is": ({ server }) => {
      server.sendsDate = false;
    },
    "the server lists an invalid blob ID": ({ server }) => server.blobs.set("../../me", { bytes: new Uint8Array(1), created_at: 0 }),
    "the root was saved by a newer version": ({ server, session }) => writeRoot(server, session, { version: 2, revision: 99, entries: [] }),
    "the keys were saved by a newer version since the unlock": ({ server, phone }) => {
      server.passkeys.set(phone, { name: "Phone" }); // no slot to prune: only the version check stops it
      writeKeys(server, { ...keysOf(server), version: 2 });
    },
    "a directory of the tree doesn't match its ID": ({ server, history }) => {
      const { bytes } = server.blobs.get(history.id);
      server.blobs.get(history.id).bytes = Uint8Array.from(bytes, (b, i) => (i === bytes.length - 1 ? b ^ 1 : b));
    },
    "a directory of the tree is missing": ({ server, history }) => server.blobs.delete(history.id),
  };
  for (const [name, tamper] of Object.entries(cases)) {
    await t.test(name, async () => {
      const account = await aDayOfUse();
      await tamper(account);
      // A device that wrote a directory keeps it in memory; a fresh unlock has to read it from the server.
      const fresh = name.startsWith("a directory");
      if (fresh) lock(account.server);
      const session = fresh ? (await flows.unlockWithPasskey()).session : account.session;
      const { report } = await flows.maintain(session, "automatic");
      assert.notEqual(report.error, null);
      assert.doesNotMatch(report.error, /session has ended/, "stopped by the check, not by a lost session");
      assert.deepEqual(deletions(account.server), []);
    });
  }
});

test("a failed deletion is reported and the others go ahead", async () => {
  const { server, session, roots } = await aDayOfUse();
  server.failingDeletes.add(roots[0]);
  const { report } = await flows.maintain(session, "manual");
  assert.equal(report.error, null);
  assert.deepEqual(report.failed.map((f) => f.id), [roots[0]]);
  assert.equal(server.blobs.has(roots[1]), false);
});

test("cleanup stops when the session ends", async () => {
  const { server, session } = await aDayOfUse();
  server.session = null;
  const { report } = await flows.maintain(session, "automatic");
  assert.notEqual(report.error, null);
  assert.deepEqual(deletions(server), []);
});
