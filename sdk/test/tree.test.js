// The tree's transactions (SPEC §5, §6.4) against an in-memory store: what reads see, what a commit writes, and
// what put accepts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

import { begin, commit, parseDir, reachable, TreeError, uploads, validName } from "../src/tree.js";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const T0 = Date.UTC(2026, 9, 23, 12, 0, 0);
const bytes = (text) => new TextEncoder().encode(text);

/** An in-memory store behind tree.js's io; `calls` records what it was asked to do. */
function store() {
  const dirs = new Map();
  const files = new Map();
  const known = new Map();
  const calls = { loadDir: [], upload: [], writeDir: [] };
  const flags = new Map(); // file ID → whether it was uploaded offloadable
  const remember = (doc) => doc.entries.forEach((entry) => known.set(entry.id, entry));
  const io = {
    loadDir: async (id) => {
      calls.loadDir.push(id);
      if (!dirs.has(id)) throw new Error(`no directory ${id}`);
      return dirs.get(id);
    },
    readFile: async (entry) => files.get(entry.id),
    known: (id) => known.get(id),
    upload: async (source, { offloadable }) => {
      const content = source instanceof Uint8Array ? source : new Uint8Array(await source.arrayBuffer());
      calls.upload.push(content);
      if (io.tooLarge) throw Object.assign(new Error("too large"), { code: "blob_too_large" });
      const id = hex(randomBytes(32));
      files.set(id, content);
      flags.set(id, offloadable);
      return { id, salt: hex(randomBytes(16)), size: content.length, sha256: sha(content) };
    },
    writeDir: async (doc) => {
      calls.writeDir.push(doc);
      const id = hex(randomBytes(32));
      dirs.set(id, doc);
      remember(doc);
      return { id, salt: hex(randomBytes(16)) };
    },
  };
  /** Stores a file or a directory as if written earlier; → its entry under `name`. */
  const file = (name, text, more = {}) => {
    const id = hex(randomBytes(32));
    files.set(id, bytes(text));
    return { name, kind: "file", id, salt: hex(randomBytes(16)), size: bytes(text).length, sha256: sha(bytes(text)), modified: new Date(T0).toISOString(), ...more };
  };
  const dir = (name, entries, version = 1) => {
    const id = hex(randomBytes(32));
    const doc = { version, entries: [...entries].sort((a, b) => (a.name < b.name ? -1 : 1)) };
    dirs.set(id, doc);
    remember(doc);
    return { name, kind: "dir", id, salt: hex(randomBytes(16)) };
  };
  const root = (entries, revision = 5) => {
    const doc = { version: 1, revision, entries: [...entries].sort((a, b) => (a.name < b.name ? -1 : 1)) };
    remember(doc);
    return doc;
  };
  return { io, calls, flags, dirs, files, file, dir, root };
}

/** Music/a.flac and notes.txt under a root at revision 5. */
function library() {
  const s = store();
  const a = s.file("a.flac", "song a", { app: { duration: 1 } });
  const music = s.dir("Music", [a]);
  const notes = s.file("notes.txt", "hello");
  return { ...s, a, music, notes, tx: begin(s.root([music, notes]), s.io, T0) };
}

const names = async (tx, path = []) => (await tx.list(path)).map((e) => e.name);
const steps = (tx, ...fns) => fns.reduce(async (t, fn) => fn(await t), Promise.resolve(tx));

test("writes return new transactions, and reads see the writes before them", async () => {
  const { tx } = library();
  const made = tx.mkdir(["Inbox"]);
  const put = made.put(["Inbox", "new.txt"], made.upload(bytes("new")));
  assert.deepEqual(await names(tx), ["Music", "notes.txt"], "the first tx is unchanged");
  assert.deepEqual(await names(made), ["Inbox", "Music", "notes.txt"]);
  assert.equal(await made.entry(["Inbox", "new.txt"]), null);
  assert.deepEqual(await put.read(["Inbox", "new.txt"]), bytes("new"));
  assert.deepEqual(await put.read(["Music", "a.flac"]), bytes("song a"), "stored files read through io");
  assert.equal(put.revision, 5);
});

test("a commit uploads new files, writes only changed directories bottom-up, and bumps the revision", async () => {
  const { tx: fresh, io, calls: own, music: m, notes: n } = library();
  const root = await commit(fresh.put(["Inbox", "Deep", "x.txt"], fresh.upload(bytes("x"), { modified: T0 + 1000, app: { tag: 1 } })), io);
  assert.equal(root.revision, 6);
  assert.deepEqual(root.entries.map((e) => e.name), ["Inbox", "Music", "notes.txt"]);
  assert.deepEqual(root.entries[1], m, "an unchanged directory keeps its blob");
  assert.deepEqual(root.entries[2], n);
  assert.equal(own.upload.length, 1);
  assert.deepEqual(own.writeDir.map((d) => d.entries.map((e) => e.name)), [["x.txt"], ["Deep"]], "the deepest first");
  const file = own.writeDir[0].entries[0];
  assert.deepEqual(Object.keys(file), ["name", "kind", "id", "salt", "size", "sha256", "modified", "app"]);
  assert.equal(file.sha256, sha(bytes("x")));
  assert.equal(file.modified, new Date(T0 + 1000).toISOString());
  assert.deepEqual(own.loadDir, [], "nothing that wasn't needed was loaded");
});

test("put makes parents and replaces; remove and mkdir", async () => {
  const { tx, io, a } = library();
  const t1 = tx.put(["Music", "a.flac"], tx.upload(bytes("song a, again")));
  assert.deepEqual(await t1.read(["Music", "a.flac"]), bytes("song a, again"), "put replaces");
  const t2 = t1.remove(["Nowhere", "x"]).remove(["notes.txt"]).mkdir(["Music"]);
  assert.deepEqual(await names(t2), ["Music"], "removing what isn't there changes nothing; mkdir of a directory neither");
  const t3 = t2.remove(["Music"]);
  assert.deepEqual(await names(t3), []);
  const root = await commit(t3, io);
  assert.deepEqual(root.entries, []);
  await assert.rejects(tx.mkdir(["notes.txt"]).list([]), (e) => e instanceof TreeError && e.code === "not_a_directory");
  await assert.rejects(tx.put(["notes.txt", "x"], tx.upload(bytes("x"))).list([]), (e) => e.code === "not_a_directory");
  assert.ok(a);
});

test("a move re-points the blob: nothing is uploaded, and a directory moves whole", async () => {
  const { tx, io, calls, a, music } = library();
  const moved = await steps(
    tx,
    async (t) => t.put(["Old music"], await t.entry(["Music"])),
    async (t) => t.put(["Archive", "a.flac"], await t.entry(["Music", "a.flac"])),
    (t) => t.remove(["Music", "a.flac"]),
  );
  const root = await commit(moved, io);
  assert.equal(calls.upload.length, 0);
  const archive = calls.writeDir.find((d) => d.entries.some((e) => e.name === "a.flac"));
  assert.deepEqual(archive.entries[0], a, "the same entry, same blob");
  assert.equal(root.entries.find((e) => e.name === "Old music").id, music.id, "a directory taken before it changed keeps its blob");
  assert.notEqual(root.entries.find((e) => e.name === "Music").id, music.id, "the one that changed gets a new one");
});

test("an entry put back may change its modified time and app data, and nothing else", async () => {
  const { tx, io, a } = library();
  const entry = await tx.entry(["Music", "a.flac"]);
  const retagged = await commit(tx.put(["Music", "a.flac"], { ...entry, app: { duration: 2 }, modified: new Date(T0 + 5).toISOString() }), io);
  assert.ok(retagged);
  for (const forged of [{ ...entry, size: 1 }, { ...entry, sha256: "0".repeat(64) }, { ...entry, salt: "0".repeat(32) }, { ...entry, id: "1".repeat(64) }, { ...entry, kind: "dir" }, { ...entry, app: "x" }]) {
    assert.throws(() => tx.put(["b.flac"], forged), (e) => e.code === "invalid_content", JSON.stringify(forged));
  }
  assert.throws(() => tx.put(["b.flac"], null), (e) => e.code === "no_content");
  assert.ok(a);
});

test("content made in a save can be put elsewhere in it, and is written once", async () => {
  const { tx, io, calls } = library();
  const source = bytes("shared");
  const saved = await steps(
    tx,
    (t) => t.mkdir(["New"]).put(["New", "s.txt"], t.upload(source)),
    async (t) => t.put(["Copy"], await t.entry(["New"])),
    async (t) => t.put(["s2.txt"], { ...(await t.entry(["New", "s.txt"])), app: { copy: true } }),
    (t) => t.put(["s3.txt"], t.upload(source)),
  );
  assert.deepEqual(await uploads(saved), [{ source, offloadable: false }]);
  const root = await commit(saved, io);
  assert.equal(calls.upload.length, 1, "the same source is uploaded once");
  assert.equal(calls.writeDir.length, 1, "the same new directory is written once");
  const byName = Object.fromEntries(root.entries.map((e) => [e.name, e]));
  assert.equal(byName.Copy.id, byName.New.id);
  assert.equal(byName["s2.txt"].id, byName["s3.txt"].id);
  assert.deepEqual(byName["s2.txt"].app, { copy: true });
});

test("uploads can be offloadable, and the same source with the other flag is another upload", async () => {
  const { tx, io, calls, flags } = library();
  const source = bytes("track");
  const saved = await steps(
    tx,
    (t) => t.put(["a.flac"], t.upload(source, { offloadable: true })).put(["b.flac"], t.upload(source)),
    async (t) => t.put(["c.flac"], { ...(await t.entry(["a.flac"])), app: { copy: true } }),
    (t) => t.put(["d.flac"], t.upload(source, { offloadable: true })),
  );
  assert.deepEqual(await uploads(saved), [{ source, offloadable: true }, { source, offloadable: false }]);
  assert.equal("offloadable" in (await saved.entry(["a.flac"])), false, "entries don't record the flag");
  const root = await commit(saved, io);
  assert.equal(calls.upload.length, 2);
  const byName = Object.fromEntries(root.entries.map((e) => [e.name, e]));
  assert.equal(byName["c.flac"].id, byName["a.flac"].id, "put elsewhere, an upload keeps its flag");
  assert.equal(byName["d.flac"].id, byName["a.flac"].id);
  assert.notEqual(byName["b.flac"].id, byName["a.flac"].id);
  assert.deepEqual([flags.get(byName["a.flac"].id), flags.get(byName["b.flac"].id)], [true, false]);
  assert.ok(root.entries.every((e) => !("offloadable" in e)));
  assert.throws(() => tx.upload(source, { offloadable: "yes" }), TypeError);
});

test("names are checked and normalised to NFC", async () => {
  for (const ok of ["a", "é", "é", "vault@41", "x".repeat(255), "ü".repeat(127)]) assert.equal(validName(ok), true, ok);
  for (const bad of ["", ".", "..", "a/b", "a\nb", "a\u0000", "\u007f", "x".repeat(256), "ü".repeat(128), 7, null]) assert.equal(validName(bad), false, String(bad));
  const { tx, io } = library();
  const root = await commit(tx.put(["Café"], tx.upload(bytes("x"))), io);
  assert.equal(root.entries[0].name, "Café");
  assert.equal(await tx.put(["Café"], tx.upload(bytes("x"))).read(["Café"]).then((b) => b.length), 1);
  assert.throws(() => tx.put(["ok", "a/b"], tx.upload(bytes("x"))), (e) => e instanceof TreeError && e.code === "invalid_name" && e.path.join() === "ok,a/b");
  await assert.rejects(tx.entry([]), TypeError);
  assert.throws(() => tx.put("a/b", tx.upload(bytes("x"))), TypeError, "a path is an array");
});

test("reads: missing paths, paths through files, and directories read as files", async () => {
  const { tx } = library();
  assert.equal(await tx.read(["nothing"]), null);
  assert.equal(await tx.entry(["Music", "nothing"]), null);
  await assert.rejects(tx.list(["nothing"]), (e) => e.code === "not_found" && e.path.join() === "nothing");
  await assert.rejects(tx.list(["notes.txt"]), (e) => e.code === "not_a_directory");
  await assert.rejects(tx.entry(["notes.txt", "x"]), (e) => e.code === "not_a_directory");
  await assert.rejects(tx.read(["Music"]), (e) => e.code === "is_a_directory");
  assert.equal((await tx.entry(["Music"])).kind, "dir");
});

test("a directory of a newer version can be read but not changed", async () => {
  const s = store();
  const newer = s.dir("Newer", [s.file("x.txt", "x")], 2);
  const tx = begin(s.root([newer]), s.io, T0);
  assert.deepEqual((await tx.list(["Newer"])).map((e) => e.name), ["x.txt"]);
  await assert.rejects(commit(tx.put(["Newer", "y.txt"], tx.upload(bytes("y"))), s.io), (e) => e.code === "read_only" && e.path.join() === "Newer");
  assert.ok(await commit(tx.put(["Other"], tx.upload(bytes("y"))), s.io), "elsewhere is fine");
  const newerRoot = begin({ version: 2, revision: 1, entries: [] }, s.io, T0);
  await assert.rejects(commit(newerRoot.mkdir(["a"]), s.io), (e) => e.code === "read_only");
  await assert.rejects(commit(newerRoot, s.io), (e) => e.code === "read_only");
});

test("a file over the backend's limit fails the commit, naming it", async () => {
  const { tx, io } = library();
  io.tooLarge = true;
  await assert.rejects(commit(tx.put(["Big", "film.mkv"], tx.upload(bytes("x"))), io), (e) => e.code === "too_large" && e.path.join("/") === "Big/film.mkv");
});

test("a step must return a tx", async () => {
  const { io } = library();
  await assert.rejects(commit({ put: () => {} }, io), TypeError);
  await assert.rejects(uploads(undefined), TypeError);
});

test("reachable lists every directory and file, opening each directory once", async () => {
  const s = store();
  const shared = s.dir("Shared", [s.file("s.txt", "s")]);
  const a = s.dir("A", [{ ...shared }, s.file("a.txt", "a")]);
  const b = s.dir("B", [{ ...shared }]);
  const root = s.root([a, b, s.file("r.txt", "r")]);
  const ids = await reachable(root, s.io.loadDir);
  assert.equal(new Set(ids).size, 6, "A, B, Shared and three files");
  assert.equal(s.calls.loadDir.filter((id) => id === shared.id).length, 1);
});

test("stored directories are checked", () => {
  const entry = { name: "a", kind: "file", id: "a".repeat(64), salt: "b".repeat(32), size: 1, sha256: "c".repeat(64), modified: "2026-10-23T12:00:00.000Z" };
  const doc = (entries, more = {}) => JSON.stringify({ version: 1, entries, ...more });
  assert.deepEqual(parseDir(doc([entry])).entries, [entry]);
  assert.equal(parseDir(doc([entry], { revision: 3 }), { root: true }).revision, 3);
  const bad = {
    "a root without a revision": () => parseDir(doc([]), { root: true }),
    "no version": () => parseDir(JSON.stringify({ entries: [] })),
    "unsorted": () => parseDir(doc([{ ...entry, name: "b" }, entry])),
    "a duplicate": () => parseDir(doc([entry, entry])),
    "a name that isn't NFC": () => parseDir(doc([{ ...entry, name: "é" }])),
    "a short id": () => parseDir(doc([{ ...entry, id: "a" }])),
    "a file without its hash": () => parseDir(doc([{ ...entry, sha256: undefined }])),
    "an unknown kind": () => parseDir(doc([{ ...entry, kind: "link" }])),
    "not JSON": () => parseDir("{"),
  };
  for (const [name, parse] of Object.entries(bad)) assert.throws(parse, Error, name);
  assert.ok(parseDir(doc([{ name: "d", kind: "dir", id: "a".repeat(64), salt: "b".repeat(32) }])));
});

test("uploads take Blobs too, read only when needed; bad arguments are refused", async () => {
  const { tx, io, calls } = library();
  const blob = new Blob([bytes("from a blob")]);
  const handle = tx.upload(blob, { modified: new Date(T0 + 7) });
  assert.equal(handle.size, 11);
  const put = tx.put(["b.txt"], handle);
  assert.deepEqual(await put.read(["b.txt"]), bytes("from a blob"));
  const pending = await put.entry(["b.txt"]);
  assert.deepEqual([pending.id, pending.size, pending.modified], [null, 11, new Date(T0 + 7).toISOString()]);
  const moved = put.put(["c.txt"], { ...pending, modified: new Date(T0 + 9).toISOString() }).remove(["b.txt"]).remove(["Music", "nothing"]);
  const root = await commit(moved, io);
  assert.deepEqual(calls.upload, [bytes("from a blob")]);
  assert.equal(root.entries.find((e) => e.name === "c.txt").modified, new Date(T0 + 9).toISOString());
  assert.deepEqual(root.entries.find((e) => e.name === "Music"), (await tx.entry(["Music"])), "removing nothing below a directory leaves it as stored");

  assert.throws(() => tx.upload("text"), TypeError);
  assert.throws(() => tx.upload(bytes("x"), { app: [1] }), TypeError);
  assert.throws(() => tx.upload(bytes("x"), { modified: "not a time" }), TypeError);
  assert.throws(() => tx.put(["x"], { kind: "file" }), (e) => e.code === "invalid_content");
});

