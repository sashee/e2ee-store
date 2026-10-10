// Cleanup (SPEC §6.11): what to delete, and the report of a run. Pure.

export const GRACE_MS = 24 * 3600 * 1000;
export const RUN_EVERY_MS = 24 * 3600 * 1000;

/** Passkey slots whose passkey the server no longer has. */
export const prunableSlots = (keysDoc, existingCredentialIds) => Object.keys(keysDoc.passkeys).filter((id) => !existingCredentialIds.includes(id));

/**
 * Splits the blobs: those in `keep`, those to delete, and unreferenced ones too recent to delete (another
 * device may have uploaded them and not yet written the ref). `now` is the server's time.
 */
export function planBlobs({ keep, blobs, now }) {
  const keepSet = new Set(keep);
  const unreferenced = blobs.filter((b) => !keepSet.has(b.id));
  const old = (b) => Date.parse(b.created_at) < now - GRACE_MS;
  return { kept: blobs.filter((b) => keepSet.has(b.id)), toDelete: unreferenced.filter(old), tooRecent: unreferenced.filter((b) => !old(b)) };
}

const tally = (blobs) => ({ count: blobs.length, bytes: blobs.reduce((n, b) => n + b.size, 0) });

export function makeReport({ trigger, startedAt, finishedAt, slotsRemoved = 0, plan = null, deleted = [], failed = [], error = null }) {
  const all = plan ? [...plan.kept, ...plan.toDelete, ...plan.tooRecent] : [];
  return {
    trigger,
    started_at: new Date(startedAt).toISOString(),
    finished_at: new Date(finishedAt).toISOString(),
    slots_removed: slotsRemoved,
    blobs_total: all.length,
    bytes_total: tally(all).bytes,
    kept: tally(plan?.kept ?? []),
    deleted: tally(deleted),
    too_recent: tally(plan?.tooRecent ?? []),
    failed,
    error,
  };
}

/** Whether the automatic run is due: never ran, last run failed or can't be read, or 24 hours passed. */
export const isDue = (lastReport, now) => !lastReport || lastReport.error !== null || !(now - Date.parse(lastReport.finished_at) < RUN_EVERY_MS);

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export const summary = (report) =>
  `${new Date(report.finished_at).toLocaleString()} (${report.trigger}): ${report.deleted.count} deleted (${formatBytes(report.deleted.bytes)}), ` +
  `${report.too_recent.count} too recent, ${report.failed.length} failed${report.error ? ` — stopped: ${report.error}` : ""}`;
