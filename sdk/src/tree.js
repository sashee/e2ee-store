// The tree (SPEC §5): the `vault` ref names the root directory, and directories list files and directories by blob ID
// and salt. A save works on a transaction, `tx`, that never changes: every write returns a new one, and reads see the
// writes before them. Nothing here does I/O by itself; the caller passes it in:
//
//   io.loadDir(id) → doc                  a stored directory, parsed and checked
//   io.readFile(entry) → Uint8Array       a stored file, whole and checked against its ID
//   io.known(id) → entry | undefined      a stored entry the caller has seen, to vet entries an app puts back
//   io.upload(source, { offloadable }) → { id, salt, size, sha256 }
//   io.writeDir(doc) → { id, salt }

import { te } from "./crypto.js";

export const VERSION = 1;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
/** What a tx hands out for content that has no blob yet: a new upload, or a directory changed in this save. */
const PENDING = Symbol("pending");
const MATERIALIZE = Symbol("materialize");

// ---------------------------------------------------------------- errors

const shown = (path) => `/${path.join("/")}`;
const MESSAGES = {
  invalid_name: (path) => `"${path.at(-1)}" can't be a name: names aren't empty, "." or "..", have no "/" or control characters, and are at most 255 bytes`,
  not_found: (path) => `Nothing is at ${shown(path)}`,
  not_a_directory: (path) => `${shown(path)} is a file, not a folder`,
  is_a_directory: (path) => `${shown(path)} is a folder, not a file`,
  no_content: (path) => `There is nothing to put at ${shown(path)}`,
  invalid_content: (path) => `What was put at ${shown(path)} is neither new content nor an entry of this vault`,
  read_only: (path) => `${shown(path)} was saved by a newer version of the app; update this one to change it`,
  too_large: (path) => `${shown(path)} is too large to store`,
};

/** A path the operation can't use. `code` is one of MESSAGES' keys; `path` the path it is about. */
export class TreeError extends Error {
  constructor(code, path) {
    super(MESSAGES[code](path));
    this.name = "TreeError";
    this.code = code;
    this.path = path;
  }
}

// ---------------------------------------------------------------- names and the format

/** Whether `name`, normalised to NFC, can name an entry. */
export function validName(name) {
  if (typeof name !== "string") return false;
  const nfc = name.normalize("NFC");
  return nfc.length > 0 && nfc !== "." && nfc !== ".." && !/[/\u0000-\u001f\u007f]/.test(nfc) && te.encode(nfc).length <= 255;
}

/** The path with its names normalised to NFC; [] is the root, which only `list` takes. */
function checkPath(path, { root = false } = {}) {
  if (!Array.isArray(path) || (!root && path.length === 0)) throw new TypeError("A path is an array of names, and only `list` takes the root ([])");
  path.forEach((name, i) => {
    if (!validName(name)) throw new TreeError("invalid_name", path.slice(0, i + 1));
  });
  return path.map((name) => name.normalize("NFC"));
}

const isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const isTime = (value) => typeof value === "string" && !Number.isNaN(Date.parse(value));

function validEntry(entry) {
  const named = isObject(entry) && validName(entry.name) && entry.name === entry.name.normalize("NFC") && HEX64.test(entry.id) && HEX32.test(entry.salt);
  const file =
    entry?.kind === "file" && Number.isSafeInteger(entry.size) && entry.size >= 0 && HEX64.test(entry.sha256) && isTime(entry.modified) && (entry.app === undefined || isObject(entry.app));
  return named && (file || entry.kind === "dir");
}

/** A stored directory, parsed and checked; a root also has a revision. Throws on anything malformed. */
export function parseDir(text, { root = false } = {}) {
  const doc = JSON.parse(text);
  const shape = isObject(doc) && Number.isInteger(doc.version) && doc.version >= 1 && Array.isArray(doc.entries);
  if (!shape || (root && !(Number.isInteger(doc.revision) && doc.revision >= 1))) throw new Error("Not a directory");
  if (!doc.entries.every(validEntry)) throw new Error("A directory entry is malformed");
  if (doc.entries.some((entry, i) => i > 0 && !(doc.entries[i - 1].name < entry.name))) throw new Error("A directory's entries aren't sorted and unique");
  return doc;
}

/** Whether this version can change a directory. */
export const writable = (doc) => doc.version <= VERSION;

export const emptyRoot = (revision) => ({ version: VERSION, revision, entries: [] });

// ---------------------------------------------------------------- the tree a transaction holds
//
// A directory node is { meta, children }: `meta` is the stored document without its entries, `children` maps names to
//   { file: entry }                          a stored file
//   { dir: entry }                           a stored directory, not loaded
//   { node }                                 a directory changed (or made) in this save
//   { upload: { source, offloadable, modified, app } }    a file put in this save

const childOf = (entry) => (entry.kind === "dir" ? { dir: entry } : { file: entry });
const nodeOf = ({ entries, ...meta }) => ({ meta, children: new Map(entries.map((entry) => [entry.name, childOf(entry)])) });
const EMPTY = Object.freeze({ meta: { version: VERSION }, children: new Map() });

async function asNode(child, io, path) {
  if (child.node) return child.node;
  if (child.dir) return nodeOf(await io.loadDir(child.dir.id));
  throw new TreeError("not_a_directory", path);
}

/** The child at `path` below `node`, loading stored directories on the way; null if nothing is there. */
async function childAt(node, path, io, depth = 0) {
  const child = node.children.get(path[depth]) ?? null;
  if (child === null || depth === path.length - 1) return child;
  return childAt(await asNode(child, io, path.slice(0, depth + 1)), path, io, depth + 1);
}

/**
 * `node` with `change(existing child | null)` at `path`: the new child, null to remove it, or the existing one for no
 * change. Directories on the way are made if `create`, and copied, so `node` itself is never modified.
 */
async function edit(node, path, change, create, io, depth = 0) {
  if (!writable(node.meta)) throw new TreeError("read_only", path.slice(0, depth));
  const name = path[depth];
  const existing = node.children.get(name) ?? null;
  const next = depth === path.length - 1 ? change(existing) : await editBelow(existing, path, change, create, io, depth);
  if (next === existing) return node;
  const children = new Map(node.children);
  if (next === null) children.delete(name);
  else children.set(name, next);
  return { ...node, children };
}

async function editBelow(existing, path, change, create, io, depth) {
  if (existing === null && !create) return existing;
  const sub = existing === null ? EMPTY : await asNode(existing, io, path.slice(0, depth + 1));
  const edited = await edit(sub, path, change, create, io, depth + 1);
  return edited === sub ? existing : { node: edited };
}

const sizeOf = (source) => (source instanceof Uint8Array ? source.length : source.size);
const withoutName = ({ name: _name, ...rest }) => rest;

/** An entry as reads hand it out. Content without a blob yet has no ID; it can still be put elsewhere in this save. */
function entryOf(name, child) {
  if (child.file) return { name, ...withoutName(child.file) };
  if (child.dir) return { name, ...withoutName(child.dir) };
  if (child.node) return { name, kind: "dir", id: null, salt: null, [PENDING]: child };
  const { source, modified, app } = child.upload;
  return { name, kind: "file", id: null, salt: null, size: sizeOf(source), sha256: null, modified, ...(app === undefined ? {} : { app }), [PENDING]: child };
}

/** A file's own fields an app may change when it puts an entry back: when it was modified, and its `app` data. */
function ownFields(content, fallback, path) {
  const modified = content.modified ?? fallback.modified;
  if (!isTime(modified) || !(content.app === undefined || isObject(content.app))) throw new TreeError("invalid_content", path);
  return { modified, ...(content.app === undefined ? {} : { app: content.app }) };
}

/**
 * The child that `put` places, from what the app passes: new content from `upload`, or an entry it read. A stored
 * entry must be one the SDK has seen, unchanged but for `modified` and `app`, so an entry never disagrees with its blob.
 */
function childFrom(content, path, io) {
  if (content === null || content === undefined) throw new TreeError("no_content", path);
  const pending = content[PENDING];
  if (pending?.node) return pending;
  if (pending?.upload) return { upload: { ...pending.upload, ...ownFields(content, pending.upload, path) } };
  const known = typeof content.id === "string" ? io.known(content.id) : undefined;
  const same = known && known.kind === content.kind && known.salt === content.salt && (known.kind === "dir" || (known.size === content.size && known.sha256 === content.sha256));
  if (!same) throw new TreeError("invalid_content", path);
  if (known.kind === "dir") return { dir: { kind: "dir", id: known.id, salt: known.salt } };
  const { app: _app, modified: _modified, ...file } = withoutName(known);
  return { file: { ...file, ...ownFields(content, known, path) } };
}

const toTime = (value, now) => {
  const time = value === undefined ? new Date(now) : value instanceof Date ? value : new Date(value);
  if (Number.isNaN(time.getTime())) throw new TypeError("`modified` is a Date, a time in milliseconds or an ISO string");
  return time.toISOString();
};

// ---------------------------------------------------------------- the transaction

const once = (compute) => {
  let result = null;
  return () => (result ??= compute());
};

/**
 * A transaction on the tree under `root` (a parsed root document), at the start of a save. `now` is the save's time:
 * the `modified` of uploads that don't give one.
 */
export const begin = (root, io, now) => txOf(async () => nodeOf(root), root.revision, io, now);

function txOf(compute, revision, io, now) {
  const materialize = once(compute);
  const write = (path, create, makeChange) => {
    const full = checkPath(path);
    const change = makeChange(full);
    return txOf(async () => edit(await materialize(), full, change, create, io), revision, io, now);
  };
  const at = async (path) => childAt(await materialize(), path, io);
  return Object.freeze({
    /** The revision the save is based on; the root it writes has the next one. */
    revision,
    put: (path, content) => write(path, true, (full) => {
      const child = childFrom(content, full, io);
      return () => child;
    }),
    remove: (path) => write(path, false, () => () => null),
    mkdir: (path) => write(path, true, (full) => (existing) => {
      if (existing === null) return { node: EMPTY };
      if (existing.file || existing.upload) throw new TreeError("not_a_directory", full);
      return existing;
    }),
    upload: (source, { modified, app, offloadable = false } = {}) => {
      if (!(source instanceof Uint8Array || source instanceof Blob)) throw new TypeError("An upload is a Uint8Array or a Blob");
      if (!(app === undefined || isObject(app))) throw new TypeError("`app` is a plain object");
      if (typeof offloadable !== "boolean") throw new TypeError("`offloadable` is true or false");
      const fields = { modified: toTime(modified, now), ...(app === undefined ? {} : { app }) };
      const upload = { source, offloadable, ...fields };
      return Object.freeze({ kind: "file", size: sizeOf(source), source, ...fields, [PENDING]: { upload } });
    },
    entry: async (path) => {
      const full = checkPath(path);
      const child = await at(full);
      return child && entryOf(full.at(-1), child);
    },
    list: async (path) => {
      const full = checkPath(path, { root: true });
      const node = full.length === 0 ? await materialize() : await asNode((await at(full)) ?? notFound(full), io, full);
      return [...node.children].sort(byName).map(([name, child]) => entryOf(name, child));
    },
    read: async (path) => {
      const full = checkPath(path);
      const child = await at(full);
      if (child === null) return null;
      if (child.node || child.dir) throw new TreeError("is_a_directory", full);
      if (child.file) return io.readFile(child.file);
      const { source } = child.upload;
      return source instanceof Uint8Array ? source : new Uint8Array(await source.arrayBuffer());
    },
    [MATERIALIZE]: materialize,
  });
}

const notFound = (path) => {
  throw new TreeError("not_found", path);
};
const byName = ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0);

// ---------------------------------------------------------------- committing

/**
 * What `make` returns for `source` uploaded with this `offloadable`, made the first time it's asked for and kept in
 * `cache` (a Map or a WeakMap). An upload is the same one only with the same source and the same flag.
 */
export function perUpload(cache, { source, offloadable }, make) {
  if (!cache.has(source)) cache.set(source, new Map());
  const byFlag = cache.get(source);
  if (!byFlag.has(offloadable)) byFlag.set(offloadable, make());
  return byFlag.get(offloadable);
}

/**
 * The root document a transaction leads to, revision + 1. Its new files are uploaded and its changed directories
 * written first, bottom-up; a directory or upload that appears twice is written once.
 */
export async function commit(tx, io) {
  const root = await materialized(tx);
  if (!writable(root.meta)) throw new TreeError("read_only", []);
  const written = { dirs: new WeakMap(), uploads: new WeakMap() };
  return { ...root.meta, version: VERSION, revision: tx.revision + 1, entries: await committed(root, io, [], written) };
}

async function committed(node, io, path, written) {
  const entries = [...node.children].sort(byName).map(async ([name, child]) => {
    const at = [...path, name];
    if (child.file || child.dir) return { name, ...withoutName(child.file ?? child.dir) };
    if (child.upload) {
      const { modified, app } = child.upload;
      const blob = await perUpload(written.uploads, child.upload, () => uploaded(io, child.upload, at));
      return { name, kind: "file", ...blob, modified, ...(app === undefined ? {} : { app }) };
    }
    if (!written.dirs.has(child.node)) {
      written.dirs.set(child.node, committed(child.node, io, at, written).then((sub) => io.writeDir({ ...child.node.meta, version: VERSION, entries: sub })));
    }
    return { name, kind: "dir", ...(await written.dirs.get(child.node)) };
  });
  return Promise.all(entries);
}

async function uploaded(io, { source, offloadable }, path) {
  try {
    return await io.upload(source, { offloadable });
  } catch (error) {
    throw error?.code === "blob_too_large" ? new TreeError("too_large", path) : error;
  }
}

/** What a transaction will upload when committed, as { source, offloadable }: for progress, before anything is uploaded. */
export async function uploads(tx) {
  const found = new Map();
  const walk = (node) =>
    node.children.forEach((child) => {
      if (child.upload) perUpload(found, child.upload, () => ({ source: child.upload.source, offloadable: child.upload.offloadable }));
      if (child.node) walk(child.node);
    });
  walk(await materialized(tx));
  return [...found.values()].flatMap((byFlag) => [...byFlag.values()]);
}

function materialized(tx) {
  if (typeof tx?.[MATERIALIZE] !== "function") throw new TypeError("Every step of a save returns a tx");
  return tx[MATERIALIZE]();
}

// ---------------------------------------------------------------- cleanup

/** The IDs of every directory and file below the directory `doc`, opening each directory once. */
export async function reachable(doc, loadDir) {
  const seen = new Set();
  const walk = async (dir) => {
    const ids = await Promise.all(
      dir.entries.map(async (entry) => {
        if (entry.kind === "file") return [entry.id];
        if (seen.has(entry.id)) return [];
        seen.add(entry.id);
        return [entry.id, ...(await walk(await loadDir(entry.id)))];
      }),
    );
    return ids.flat();
  };
  return walk(doc);
}
