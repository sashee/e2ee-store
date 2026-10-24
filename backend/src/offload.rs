//! Moving offloadable blobs between the database and the storage backends, and between backends (SPEC §7.4): on
//! upload, when a flag changes, and in a pass at startup and every hour, which also deletes objects no blob owns and
//! returns freed pages to the file system. Moves into the database need the room for it (SPEC §7.5).
//!
//! Every move puts the content where it goes before the row says it's there, and the row is only changed if the blob
//! is still as it was (compare-and-swap), so a crash or a race leaves at worst an object nobody owns. Whatever writes
//! or deletes an object holds its key's lock, and deletes it only if the database, read under that lock, says no
//! blob owns it: so an object a move or an upload is about to own is never deleted.

use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

use axum::body::Bytes;

use crate::config::Target;
use crate::domain::{BlobId, ByteRange};
use crate::http::{ApiError, AppState};
use crate::objects::ObjectError;
use crate::remotes::Remote;
use crate::store::{self, BackendRecord, BlobMeta, Location, Usage, UserId};
use crate::{db, disk};

/// How often blobs that aren't where they belong are moved, and freed pages returned.
pub const PASS_EVERY: Duration = Duration::from_secs(60 * 60);
/// Pages returned to the file system per step; each step holds the write lock only that long.
const RECLAIM_STEP: u32 = 1024;

#[derive(Debug)]
pub enum MoveError {
    /// The object is gone, or isn't the blob any more.
    Lost,
    Unavailable(String),
    /// The database's file system hasn't the room: `needed` bytes free, of which there are `free`.
    Full {
        needed: u64,
        free: u64,
    },
    Db(ApiError),
}

/// One writer at a time per object key.
#[derive(Default)]
pub struct KeyLocks {
    busy: Mutex<HashSet<String>>,
    freed: Notify,
}

pub struct KeyGuard<'a> {
    locks: &'a KeyLocks,
    key: String,
}

impl KeyLocks {
    pub async fn lock(&self, key: String) -> KeyGuard<'_> {
        loop {
            // Created before the check, so a release between the two still wakes it.
            let freed = self.freed.notified();
            let free = self
                .busy
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key.clone());
            if free {
                return KeyGuard { locks: self, key };
            }
            freed.await;
        }
    }
}

impl Drop for KeyGuard<'_> {
    fn drop(&mut self) {
        self.locks
            .busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
        self.locks.freed.notify_waiters();
    }
}

impl From<ApiError> for MoveError {
    fn from(e: ApiError) -> Self {
        Self::Db(e)
    }
}

impl From<ObjectError> for MoveError {
    fn from(e: ObjectError) -> Self {
        match e {
            ObjectError::NotFound => Self::Lost,
            ObjectError::Unavailable(why) => Self::Unavailable(why),
        }
    }
}

impl From<MoveError> for ApiError {
    fn from(e: MoveError) -> Self {
        match e {
            MoveError::Lost => ApiError::blob_lost(),
            MoveError::Unavailable(why) => ApiError::storage_unavailable(why),
            MoveError::Full { needed, free } => ApiError::storage_full(needed, free),
            MoveError::Db(e) => e,
        }
    }
}

/// Refuses to serve if blobs are in a backend the server can't reach them in: one that isn't configured, or one
/// whose name now stands for another type or location than the one they went to. Otherwise all of them would read as
/// lost, and nothing could move them.
pub fn check_backends(
    usage: &[Usage],
    recorded: &[BackendRecord],
    configured: &[BackendRecord],
) -> anyhow::Result<()> {
    let find = |list: &[BackendRecord], name: &str| list.iter().find(|b| b.name == name).cloned();
    for (name, blobs) in usage.iter().filter_map(|u| match &u.location {
        Location::Backend(name) if u.blobs > 0 => Some((name, u.blobs)),
        _ => None,
    }) {
        let Some(here) = find(configured, name) else {
            anyhow::bail!(
                "{blobs} blobs are in backend {name:?}, which isn't configured: configure it, so they can be read and moved"
            );
        };
        if !find(recorded, name).is_some_and(|there| same_place(&there, &here)) {
            anyhow::bail!(
                "{blobs} blobs are in backend {name:?}, but its configuration names another type or location than the one they went to"
            );
        }
    }
    Ok(())
}

/// The same type and identity, compared as JSON rather than as text.
fn same_place(a: &BackendRecord, b: &BackendRecord) -> bool {
    let parse = |identity: &str| serde_json::from_str::<serde_json::Value>(identity).ok();
    a.kind == b.kind && parse(&a.identity).is_some() && parse(&a.identity) == parse(&b.identity)
}

/// Whether writing `total` bytes into the database, the `largest` at a time, leaves `min_free_space` free.
fn room(state: &AppState, total: u64, largest: u64) -> Result<(), MoveError> {
    let free = (state.free_space)(&state.config.database)
        .map_err(|e| MoveError::Unavailable(format!("the free space is unknown: {e}")))?;
    let reserve = state.config.min_free_space;
    if disk::fits(free, total, largest, reserve) {
        Ok(())
    } else {
        Err(MoveError::Full {
            needed: total.saturating_add(largest).saturating_add(reserve),
            free,
        })
    }
}

/// Whether one blob of `bytes` fits in the database.
pub fn room_for(state: &AppState, bytes: u64) -> Result<(), MoveError> {
    room(state, bytes, bytes)
}

/// What a backend's object is locked under: its key, in that backend.
fn lock_name(remote: &Remote, key: &str) -> String {
    format!("{}\n{key}", remote.name)
}

/// A new offloadable blob, uploaded while the target is a backend: its content goes straight there. If that fails, it
/// is stored here instead, room permitting, and a later pass moves it.
pub async fn upload(
    state: &AppState,
    remote: &Remote,
    user_id: UserId,
    id: BlobId,
    content: Bytes,
    now: i64,
) -> Result<(bool, BlobMeta), ApiError> {
    if let Some(meta) = state.db(move |c| store::blob_meta(c, &user_id, id)).await? {
        return Ok((false, meta));
    }
    let key = remote.key(&user_id, id);
    let held = state.moving.lock(lock_name(remote, &key)).await;
    let record = match remote.put(&key, content.clone()).await {
        Ok(()) => Some(remote.record()),
        Err(e) => {
            room_for(state, content.len() as u64).map_err(|_| ApiError::storage_unavailable(&e))?;
            tracing::warn!("blob {id} stays in the database for now: {e}");
            None
        }
    };
    let put_there = record.is_some();
    let (created, meta) = state
        .db(move |c| store::put_blob(c, &user_id, id, &content, true, record.as_ref(), now))
        .await?;
    if put_there && meta.location == Location::Local {
        // Another upload of the same blob got there first, into the database.
        drop_unowned(state, remote, &held, user_id, id).await;
    }
    Ok((created, meta))
}

/// Moves a blob to backend `to`, from the database or from another backend, if it is still where `meta` says and
/// offloadable. → whether it moved.
pub async fn to_backend(
    state: &AppState,
    to: &Remote,
    user_id: UserId,
    meta: &BlobMeta,
) -> Result<bool, MoveError> {
    match &meta.location {
        Location::Local => from_database(state, to, user_id, meta.id).await,
        Location::Backend(name) if *name == to.name => Ok(false),
        Location::Backend(name) => {
            let from = configured(state, name)?;
            across(state, from, to, user_id, meta).await
        }
    }
}

fn configured<'a>(state: &'a AppState, name: &str) -> Result<&'a Remote, MoveError> {
    state
        .remotes
        .get(name)
        .map(|remote| &**remote)
        .ok_or_else(|| MoveError::Unavailable(format!("backend {name:?} isn't configured")))
}

async fn from_database(
    state: &AppState,
    to: &Remote,
    user_id: UserId,
    id: BlobId,
) -> Result<bool, MoveError> {
    let key = to.key(&user_id, id);
    let held = state.moving.lock(lock_name(to, &key)).await;
    let Some(content) = state
        .db(move |c| store::offloadable_content(c, &user_id, id))
        .await?
    else {
        return Ok(false);
    };
    to.put(&key, content.into()).await?;
    let record = to.record();
    let moved = state
        .db(move |c| store::mark_moved(c, &user_id, id, &Location::Local, &record))
        .await?;
    if !moved {
        drop_unowned(state, to, &held, user_id, id).await;
    }
    Ok(moved)
}

/// From one backend to another, through memory, checked against the blob's ID on the way. The database never holds
/// it, so moving between backends needs no room here.
async fn across(
    state: &AppState,
    from: &Remote,
    to: &Remote,
    user_id: UserId,
    meta: &BlobMeta,
) -> Result<bool, MoveError> {
    let id = meta.id;
    let (from_key, to_key) = (from.key(&user_id, id), to.key(&user_id, id));
    let (from_lock, to_lock) = (lock_name(from, &from_key), lock_name(to, &to_key));
    // Always in the same order, so two moves in opposite directions can't each wait for the other.
    let (from_held, to_held) = if from_lock < to_lock {
        let from_held = state.moving.lock(from_lock).await;
        (from_held, state.moving.lock(to_lock).await)
    } else {
        let to_held = state.moving.lock(to_lock).await;
        (state.moving.lock(from_lock).await, to_held)
    };
    let content = match from.get_all(&from_key, meta.size).await {
        Ok(content) => content,
        Err(ObjectError::NotFound) if !located_in(state, user_id, id, from).await? => {
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    };
    if BlobId::of(&content) != id {
        return Err(MoveError::Lost);
    }
    to.put(&to_key, content).await?;
    let (source, record) = (Location::Backend(from.name.clone()), to.record());
    let moved = state
        .db(move |c| store::mark_moved(c, &user_id, id, &source, &record))
        .await?;
    if moved {
        drop_unowned(state, from, &from_held, user_id, id).await;
    } else {
        drop_unowned(state, to, &to_held, user_id, id).await;
    }
    Ok(moved)
}

/// Brings a blob back from backend `from` into the database, if it has the room, checked against its ID; `unflag`
/// also makes it not offloadable, in the same step. → whether it moved; false if it wasn't there (any more).
pub async fn to_local(
    state: &AppState,
    from: &Remote,
    user_id: UserId,
    meta: &BlobMeta,
    unflag: bool,
) -> Result<bool, MoveError> {
    room_for(state, meta.size)?;
    let id = meta.id;
    let key = from.key(&user_id, id);
    let held = state.moving.lock(lock_name(from, &key)).await;
    let content = match from.get_all(&key, meta.size).await {
        Ok(content) => content,
        Err(ObjectError::NotFound) if !located_in(state, user_id, id, from).await? => {
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    };
    if BlobId::of(&content) != id {
        return Err(MoveError::Lost);
    }
    let name = from.name.clone();
    let moved = state
        .db(move |c| store::mark_local(c, &user_id, id, &name, &content, unflag))
        .await?;
    if moved {
        drop_unowned(state, from, &held, user_id, id).await;
    }
    Ok(moved)
}

/// The bytes of a blob in backend `remote`, as it sends them; None if the blob has moved since `meta` was read.
pub async fn read(
    state: &AppState,
    remote: &Remote,
    user_id: UserId,
    meta: &BlobMeta,
    range: ByteRange,
) -> Result<Option<reqwest::Response>, MoveError> {
    let range = match range {
        ByteRange::Partial { start, end } => Some((start, end)),
        ByteRange::Full | ByteRange::Unsatisfiable => None,
    };
    match remote
        .get(&remote.key(&user_id, meta.id), range, meta.size)
        .await
    {
        Ok(response) => Ok(Some(response)),
        Err(ObjectError::NotFound) if !located_in(state, user_id, meta.id, remote).await? => {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

async fn located_in(
    state: &AppState,
    user_id: UserId,
    id: BlobId,
    remote: &Remote,
) -> Result<bool, ApiError> {
    let meta = state.db(move |c| store::blob_meta(c, &user_id, id)).await?;
    Ok(meta.is_some_and(|meta| meta.location.as_str() == remote.name))
}

/// After a blob is deleted: deletes its object in `remote`, unless an upload has put the blob back meanwhile.
pub async fn forget(state: &AppState, remote: &Remote, user_id: UserId, id: BlobId) {
    let held = state
        .moving
        .lock(lock_name(remote, &remote.key(&user_id, id)))
        .await;
    drop_unowned(state, remote, &held, user_id, id).await;
}

/// Deletes the blob's object in `remote` unless the database says the blob is there. The caller holds the key's lock,
/// so nothing can move it there in between. → whether it deleted it; if that fails, a later sweep does.
async fn drop_unowned(
    state: &AppState,
    remote: &Remote,
    _held: &KeyGuard<'_>,
    user_id: UserId,
    id: BlobId,
) -> bool {
    let result = match located_in(state, user_id, id, remote).await {
        Ok(true) => return false,
        Ok(false) => remote
            .delete(&remote.key(&user_id, id))
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.message),
    };
    result
        .inspect_err(|e| {
            tracing::warn!(
                "left an unused object in {:?} for the sweep: {e}",
                remote.name
            )
        })
        .is_ok()
}

/// What a pass did, for the log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// From the database to a backend.
    pub to_backend: u64,
    /// From one backend to another.
    pub across: u64,
    /// From a backend into the database.
    pub to_local: u64,
    /// Belong in the database, but don't fit: they stay where they are.
    pub held_back: u64,
    pub failed: u64,
    pub lost: u64,
    pub swept: u64,
    pub reclaimed_pages: u64,
}

/// Moves every blob that isn't where it belongs, deletes the objects no blob owns, and returns freed pages to the
/// file system. Never fails: what doesn't work now is tried again in the next pass.
pub async fn pass(state: &AppState) -> Pass {
    let mut done = Pass::default();
    relocate(state, &mut done).await;
    for remote in state.remotes.values() {
        match sweep(state, remote).await {
            Ok(swept) => done.swept += swept,
            Err(e) => tracing::warn!("sweeping backend {:?} failed: {e:?}", remote.name),
        }
    }
    match reclaim(state).await {
        Ok(pages) => done.reclaimed_pages = pages,
        Err(e) => tracing::warn!("returning free pages failed: {}", e.message),
    }
    if done != Pass::default() {
        tracing::info!("offloading pass: {done:?}");
    }
    done
}

async fn relocate(state: &AppState, done: &mut Pass) {
    let target = state.config.blob_target.clone();
    let misplaced = match state.db(move |c| store::misplaced_blobs(c, &target)).await {
        Ok(misplaced) => misplaced,
        Err(e) => {
            tracing::warn!("listing blobs to move failed: {}", e.message);
            return;
        }
    };
    let (home, away): (Vec<_>, Vec<_>) = misplaced
        .into_iter()
        .partition(|blob| blob.to == Location::Local);
    // All of them or none: some would fill the disk and still leave the rest out.
    let total: u64 = home.iter().map(|blob| blob.meta.size).sum();
    let largest = home.iter().map(|blob| blob.meta.size).max().unwrap_or(0);
    let home = match room(state, total, largest) {
        Ok(()) => home,
        Err(e) => {
            tracing::warn!(
                "{} blobs, {total} bytes, belong in the database but don't fit, so they stay where they are: {e:?}",
                home.len()
            );
            done.held_back = home.len() as u64;
            Vec::new()
        }
    };
    for blob in away.into_iter().chain(home) {
        let moved = match (&blob.meta.location, &blob.to) {
            (Location::Backend(name), Location::Local) => match configured(state, name) {
                Ok(from) => to_local(state, from, blob.user_id, &blob.meta, false).await,
                Err(e) => Err(e),
            },
            (_, Location::Backend(name)) => match configured(state, name) {
                Ok(to) => to_backend(state, to, blob.user_id, &blob.meta).await,
                Err(e) => Err(e),
            },
            (Location::Local, Location::Local) => Ok(false),
        };
        match moved {
            Ok(false) => {}
            Ok(true) => match (&blob.meta.location, &blob.to) {
                (Location::Local, _) => done.to_backend += 1,
                (_, Location::Local) => done.to_local += 1,
                _ => done.across += 1,
            },
            Err(MoveError::Lost) => {
                tracing::warn!(
                    "blob {} is lost: its object is gone or damaged",
                    blob.meta.id
                );
                done.lost += 1;
            }
            Err(MoveError::Full { .. }) => done.held_back += 1,
            Err(e) => {
                tracing::warn!("moving blob {} failed: {e:?}", blob.meta.id);
                done.failed += 1;
            }
        }
    }
}

/// Deletes every object of `remote` that no blob in it owns: left by crashes, by deleted blobs and users, by moves
/// away, and by older binaries. Keys that aren't ours are left alone.
async fn sweep(state: &AppState, remote: &Remote) -> Result<u64, MoveError> {
    let keys = remote.list().await?;
    let name = remote.name.clone();
    let owned = state.db(move |c| store::blobs_in(c, &name)).await?;
    let mut swept = 0;
    for (user_id, id) in keys
        .iter()
        .filter_map(|key| remote.parse_key(key))
        .filter(|blob| !owned.contains(blob))
    {
        // Checked again under the key's lock: a move may have taken it since the list.
        let held = state
            .moving
            .lock(lock_name(remote, &remote.key(&user_id, id)))
            .await;
        if drop_unowned(state, remote, &held, user_id, id).await {
            swept += 1;
        }
    }
    Ok(swept)
}

/// Returns the free pages to the file system, a step at a time. → how many.
async fn reclaim(state: &AppState) -> Result<u64, ApiError> {
    let mut reclaimed = 0;
    loop {
        let (before, after) = state
            .db(|c| {
                let before = db::free_pages(c)?;
                Ok((before, db::reclaim(c, RECLAIM_STEP)?))
            })
            .await?;
        reclaimed += before.saturating_sub(after);
        if after == 0 || after >= before {
            return Ok(reclaimed);
        }
    }
}

/// Where the blobs are, and whether bringing all of them into the database would fit: for `backend storage`.
pub fn storage_report(
    usage: &[Usage],
    target: &Target,
    free: u64,
    min_free_space: u64,
    max_blob_size: u64,
) -> String {
    let rows: String = usage
        .iter()
        .map(|u| {
            format!(
                "{:<20} {:>8} {:>12}\n",
                u.location.as_str(),
                u.blobs,
                human(u.bytes)
            )
        })
        .collect();
    let elsewhere: u64 = usage
        .iter()
        .filter(|u| u.location != Location::Local)
        .map(|u| u.bytes)
        .sum();
    let largest = max_blob_size.min(elsewhere);
    let verdict = if disk::fits(free, elsewhere, largest, min_free_space) {
        "fits"
    } else {
        "doesn't fit"
    };
    let target = match target {
        Target::Local => "local",
        Target::Backend(name) => name,
    };
    format!(
        "{:<20} {:>8} {:>12}\n{rows}\ntarget: {target} (for offloadable blobs; the others are local)\nfree: {}, of which {} stays free\nbringing everything into the database: {} more; {verdict}\n",
        "where",
        "blobs",
        "bytes",
        human(free),
        human(min_free_space),
        human(elsewhere)
    )
}

/// Bytes in binary units, to one decimal.
fn human(bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (value, unit) = units[1..]
        .iter()
        .fold((bytes as f64, units[0]), |(value, unit), next| {
            if value >= 1024.0 {
                (value / 1024.0, *next)
            } else {
                (value, unit)
            }
        });
    if unit == "B" {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {unit}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, bucket: &str) -> BackendRecord {
        BackendRecord {
            name: name.into(),
            kind: "s3".into(),
            identity: serde_json::json!({ "bucket": bucket, "endpoint": "https://s3.example.com", "prefix": "music/" })
                .to_string(),
        }
    }

    fn usage(location: Location, blobs: u64) -> Usage {
        Usage {
            location,
            blobs,
            bytes: blobs * 100,
        }
    }

    #[test]
    fn blobs_in_a_backend_need_that_backend() {
        let aws = record("aws", "music");
        let in_aws = [
            usage(Location::Local, 5),
            usage(Location::Backend("aws".into()), 3),
        ];
        assert!(
            check_backends(
                &in_aws,
                std::slice::from_ref(&aws),
                std::slice::from_ref(&aws)
            )
            .is_ok()
        );
        assert!(
            check_backends(
                &in_aws,
                std::slice::from_ref(&aws),
                &[aws.clone(), record("b2", "x")]
            )
            .is_ok()
        );
        assert!(
            check_backends(&in_aws, std::slice::from_ref(&aws), &[record("b2", "x")]).is_err(),
            "not configured"
        );
        assert!(
            check_backends(
                &in_aws,
                std::slice::from_ref(&aws),
                &[record("aws", "other")]
            )
            .is_err(),
            "another bucket"
        );
        assert!(
            check_backends(&in_aws, &[], std::slice::from_ref(&aws)).is_err(),
            "never recorded"
        );
        let other_type = BackendRecord {
            kind: "rest".into(),
            ..aws.clone()
        };
        assert!(
            check_backends(&in_aws, std::slice::from_ref(&aws), &[other_type]).is_err(),
            "another type"
        );
        let reordered = BackendRecord {
            identity: r#"{"prefix":"music/","endpoint":"https://s3.example.com","bucket":"music"}"#
                .into(),
            ..aws.clone()
        };
        assert!(
            check_backends(&in_aws, &[reordered], std::slice::from_ref(&aws)).is_ok(),
            "compared as JSON"
        );
        let empty = [
            usage(Location::Backend("aws".into()), 0),
            usage(Location::Local, 2),
        ];
        assert!(check_backends(&empty, &[], &[]).is_ok(), "nothing there");
    }

    #[test]
    fn the_report_says_whether_everything_fits_back() {
        let usage = [
            Usage {
                location: Location::Local,
                blobs: 16,
                bytes: 263_369,
            },
            Usage {
                location: Location::Backend("aws".into()),
                blobs: 120,
                bytes: 5 << 30,
            },
        ];
        let target = Target::Backend("aws".into());
        let report = storage_report(&usage, &target, 7 << 30, 1 << 30, 16 << 20);
        let row = |words: &[&str]| {
            report
                .lines()
                .any(|line| line.split_whitespace().eq(words.iter().copied()))
        };
        assert!(row(&["local", "16", "257.2", "KiB"]), "{report}");
        assert!(row(&["aws", "120", "5.0", "GiB"]), "{report}");
        assert!(report.contains("target: aws"), "{report}");
        assert!(report.contains("5.0 GiB more; fits"), "{report}");
        let tight = storage_report(&usage, &target, 6 << 30, 1 << 30, 16 << 20);
        assert!(tight.contains("doesn't fit"), "{tight}");
        assert_eq!(human(512), "512 B");
    }
}
