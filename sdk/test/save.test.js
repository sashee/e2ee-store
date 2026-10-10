import { test } from "node:test";
import assert from "node:assert/strict";

import { saveWithRetry, TooManyConflictsError } from "../src/save.js";

/** An in-memory ref store with blobs as JSON, and a hook to simulate another writer. */
function fakeStore(initial) {
  const blobs = new Map([["b0", JSON.stringify(initial)]]);
  let ref = "b0";
  let counter = 0;
  const store = {
    beforePut: () => {},
    io: {
      putBlob: async (data) => {
        const id = `b${++counter}`;
        blobs.set(id, data);
        return id;
      },
      putRef: async (_name, id, expected) => {
        store.beforePut();
        if (ref !== expected) return { ok: false, current: ref };
        ref = id;
        return { ok: true };
      },
      getBlob: async (id) => blobs.get(id),
    },
    write: (doc) => {
      const id = `x${++counter}`;
      blobs.set(id, JSON.stringify(doc));
      ref = id;
    },
    current: () => JSON.parse(blobs.get(ref)),
  };
  return store;
}

const options = (store, apply) => ({
  ref: "vault",
  loaded: { doc: { items: [] }, blobId: "b0" },
  apply,
  encode: async (doc) => JSON.stringify(doc),
  decode: async (data) => JSON.parse(data),
});

test("a save without conflicts writes once", async () => {
  const store = fakeStore({ items: [] });
  const saved = await saveWithRetry(store.io, options(store, (doc) => ({ items: [...doc.items, "mine"] })));
  assert.deepEqual(saved.doc.items, ["mine"]);
  assert.deepEqual(store.current().items, ["mine"]);
});

test("on conflict the operation is re-applied to the newest version", async () => {
  const store = fakeStore({ items: [] });
  let raced = false;
  store.beforePut = () => {
    if (!raced) {
      raced = true;
      store.write({ items: ["theirs"] });
    }
  };
  const seen = [];
  const saved = await saveWithRetry(store.io, options(store, (doc, base) => (seen.push(base), { items: [...doc.items, "mine"] })));
  assert.deepEqual(store.current().items, ["theirs", "mine"]);
  assert.deepEqual(saved.doc.items, ["theirs", "mine"]);
  assert.equal(seen.length, 2);
  assert.equal(seen[0], "b0");
});

test("it gives up after five conflicts", async () => {
  const store = fakeStore({ items: [] });
  store.beforePut = () => store.write({ items: ["someone else"] });
  await assert.rejects(saveWithRetry(store.io, options(store, (doc) => doc)), TooManyConflictsError);
});

import { RollbackError } from "../src/save.js";

test("a conflict pointing at an older document is a rollback, not something to save over", async () => {
  const store = fakeStore({ items: [], revision: 10 });
  // The server answers the save with a conflict whose current document is older (revision 3).
  store.beforePut = () => store.write({ items: ["old"], revision: 3 });
  const opts = { ...options(store, (doc) => ({ ...doc, items: [...doc.items, "mine"], revision: doc.revision + 1 })), loaded: { doc: { items: [], revision: 10 }, blobId: "b0" } };
  await assert.rejects(saveWithRetry(store.io, { ...opts, accept: (conflict, base) => conflict.revision > base.revision }), (e) => e instanceof RollbackError && e.conflict.revision === 3 && e.base.revision === 10);
  assert.deepEqual(store.current().items, ["old"], "nothing was written on top of the old document");
});

test("the operation may be async (e.g. it uploads blobs of its own)", async () => {
  const store = fakeStore({ items: [] });
  const saved = await saveWithRetry(store.io, options(store, async (doc) => ({ items: [...doc.items, await Promise.resolve("mine")] })));
  assert.deepEqual(saved.doc.items, ["mine"]);
  assert.deepEqual(store.current().items, ["mine"]);
});
