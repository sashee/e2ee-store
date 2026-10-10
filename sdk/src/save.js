// Saving a document by compare-and-swap (SPEC §6.4) and rollback detection (§6.5). The I/O is passed in, so the
// retry logic is testable.

export const MAX_ATTEMPTS = 5;

/** The server answered a conflict with a document that can't be newer than the one being saved over. */
export class RollbackError extends Error {
  constructor(conflict, base) {
    super("The server returned an older version during a save. Saving is paused; your change wasn't saved.");
    this.name = "RollbackError";
    this.conflict = conflict;
    this.base = base;
  }
}

export class TooManyConflictsError extends Error {
  constructor() {
    super("Too many other changes at the same time; try again");
    this.name = "TooManyConflictsError";
  }
}

/**
 * Applies `apply(doc, blobId)` (sync or async) to the loaded document and writes it; on a conflict, applies the same change
 * to the newest version and tries again.
 *
 * io.putBlob(bytes) → blob id
 * io.putRef(ref, blobId, expectedBlobId) → { ok: true } | { ok: false, current: blobId | null }
 * io.getBlob(blobId) → bytes (hash-verified)
 *
 * `accept(conflict, base)` vets the document a conflict points to; returning false throws RollbackError.
 */
export async function saveWithRetry(io, { ref, loaded, apply, encode, decode, accept = () => true, attempts = MAX_ATTEMPTS }) {
  let base = loaded;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const doc = await apply(base.doc, base.blobId);
    const blobId = await io.putBlob(await encode(doc));
    const result = await io.putRef(ref, blobId, base.blobId);
    if (result.ok) return { doc, blobId, previous: base };
    if (!result.current) throw new Error(`The ${ref} ref disappeared`);
    const conflict = await decode(await io.getBlob(result.current));
    if (!accept(conflict, base.doc)) throw new RollbackError(conflict, base.doc);
    base = { doc: conflict, blobId: result.current };
  }
  throw new TooManyConflictsError();
}

/** A vault older than the highest revision this device has seen is a rollback (SPEC §6.5). */
export const rollbackCheck = (highestSeen, revision) => ({
  rolledBack: highestSeen !== null && revision < highestSeen,
  highest: Math.max(highestSeen ?? 0, revision),
});
