//! Moving offloadable blobs between the database and S3 (SPEC §7.4): on upload, when a flag changes, and in a pass
//! at startup and every hour, which also deletes objects no blob owns and returns freed pages to the file system.
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

use crate::db;
use crate::domain::{BlobId, ByteRange};
use crate::http::{ApiError, AppState};
use crate::objects::{ObjectError, Objects};
use crate::store::{self, BlobMeta, S3Location, Stored, UserId};

/// How often blobs that aren't where they belong are moved, and freed pages returned.
pub const PASS_EVERY: Duration = Duration::from_secs(60 * 60);
/// Pages returned to the file system per step; each step holds the write lock only that long.
const RECLAIM_STEP: u32 = 1024;

#[derive(Debug)]
pub enum MoveError {
    /// The object is gone, or isn't the blob any more.
    Lost,
    Unavailable(String),
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
            MoveError::Db(e) => e,
        }
    }
}

/// Refuses to serve if blobs are in S3 and the server can't reach them there: no S3, or another location than the
/// one they were moved to. Otherwise every one of them would read as lost.
pub fn check_location(
    in_s3: u64,
    recorded: Option<&S3Location>,
    configured: Option<&S3Location>,
) -> anyhow::Result<()> {
    match configured {
        _ if in_s3 == 0 => Ok(()),
        None => anyhow::bail!(
            "{in_s3} blobs are in S3, but s3_file isn't set: set it, so they can be read and moved back"
        ),
        Some(configured) if recorded != Some(configured) => anyhow::bail!(
            "{in_s3} blobs are in S3, but s3_file names another endpoint, bucket or prefix than the one they were moved to"
        ),
        Some(_) => Ok(()),
    }
}

/// A new offloadable blob, uploaded while the target is S3: its content goes straight there. If S3 fails, it is
/// stored here instead, and a later pass moves it.
pub async fn upload(
    state: &AppState,
    objects: &Objects,
    user_id: UserId,
    id: BlobId,
    content: Bytes,
    now: i64,
) -> Result<(bool, BlobMeta), ApiError> {
    if let Some(meta) = state.db(move |c| store::blob_meta(c, &user_id, id)).await? {
        return Ok((false, meta));
    }
    let key = objects.key(&user_id, id);
    let held = state.moving.lock(key.clone()).await;
    let in_s3 = match objects.put(&key, content.clone()).await {
        Ok(()) => Some(objects.location().clone()),
        Err(e) => {
            tracing::warn!("blob {id} stays in the database for now: {e}");
            None
        }
    };
    let put_in_s3 = in_s3.is_some();
    let (created, meta) = state
        .db(move |c| store::put_blob(c, &user_id, id, &content, true, in_s3.as_ref(), now))
        .await?;
    if put_in_s3 && meta.stored == Stored::Local {
        // Another upload of the same blob got there first, into the database.
        drop_unowned(state, objects, &held, user_id, id).await;
    }
    Ok((created, meta))
}

/// Moves a blob to S3 if it is still in the database and offloadable. → whether it moved.
pub async fn to_s3(
    state: &AppState,
    objects: &Objects,
    user_id: UserId,
    id: BlobId,
) -> Result<bool, MoveError> {
    let key = objects.key(&user_id, id);
    let held = state.moving.lock(key.clone()).await;
    let Some(content) = state
        .db(move |c| store::offloadable_content(c, &user_id, id))
        .await?
    else {
        return Ok(false);
    };
    objects.put(&key, content.into()).await?;
    let location = objects.location().clone();
    let moved = state
        .db(move |c| store::mark_in_s3(c, &user_id, id, &location))
        .await?;
    if !moved {
        drop_unowned(state, objects, &held, user_id, id).await;
    }
    Ok(moved)
}

/// Brings a blob back from S3, checked against its ID; `unflag` also makes it not offloadable, in the same step.
/// → whether it moved; false if it wasn't in S3 (any more).
pub async fn to_local(
    state: &AppState,
    objects: &Objects,
    user_id: UserId,
    meta: BlobMeta,
    unflag: bool,
) -> Result<bool, MoveError> {
    let id = meta.id;
    let key = objects.key(&user_id, id);
    let held = state.moving.lock(key.clone()).await;
    let content = match objects.get_all(&key, meta.size).await {
        Ok(content) => content,
        Err(ObjectError::NotFound) if !in_s3(state, user_id, id).await? => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if BlobId::of(&content) != id {
        return Err(MoveError::Lost);
    }
    let moved = state
        .db(move |c| store::mark_local(c, &user_id, id, &content, unflag))
        .await?;
    if moved {
        drop_unowned(state, objects, &held, user_id, id).await;
    }
    Ok(moved)
}

/// The bytes of a blob in S3, as S3 sends them; None if it has come back to the database since `meta` was read.
pub async fn read(
    state: &AppState,
    objects: &Objects,
    user_id: UserId,
    meta: BlobMeta,
    range: ByteRange,
) -> Result<Option<reqwest::Response>, MoveError> {
    let range = match range {
        ByteRange::Partial { start, end } => Some((start, end)),
        ByteRange::Full | ByteRange::Unsatisfiable => None,
    };
    match objects
        .get(&objects.key(&user_id, meta.id), range, meta.size)
        .await
    {
        Ok(response) => Ok(Some(response)),
        Err(ObjectError::NotFound) if !in_s3(state, user_id, meta.id).await? => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn in_s3(state: &AppState, user_id: UserId, id: BlobId) -> Result<bool, ApiError> {
    let meta = state.db(move |c| store::blob_meta(c, &user_id, id)).await?;
    Ok(meta.is_some_and(|meta| meta.stored == Stored::S3))
}

/// After a blob is deleted: deletes its object, unless an upload has put the blob back meanwhile.
pub async fn forget(state: &AppState, objects: &Objects, user_id: UserId, id: BlobId) {
    let held = state.moving.lock(objects.key(&user_id, id)).await;
    drop_unowned(state, objects, &held, user_id, id).await;
}

/// Deletes the blob's object unless the database says it is in S3. The caller holds the key's lock, so nothing can
/// move it there in between. → whether it deleted it; if that fails, a later sweep does.
async fn drop_unowned(
    state: &AppState,
    objects: &Objects,
    held: &KeyGuard<'_>,
    user_id: UserId,
    id: BlobId,
) -> bool {
    let result = match in_s3(state, user_id, id).await {
        Ok(true) => return false,
        Ok(false) => objects.delete(&held.key).await.map_err(|e| e.to_string()),
        Err(e) => Err(e.message),
    };
    result
        .inspect_err(|e| tracing::warn!("left an unused object for the sweep: {e}"))
        .is_ok()
}

/// What a pass did, for the log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub to_s3: u64,
    pub to_local: u64,
    pub failed: u64,
    pub lost: u64,
    pub swept: u64,
    pub reclaimed_pages: u64,
}

/// Moves every blob that isn't where it belongs, deletes the objects no blob owns, and returns freed pages to the
/// file system. Never fails: what doesn't work now is tried again in the next pass.
pub async fn pass(state: &AppState) -> Pass {
    let mut done = Pass::default();
    if let Some(objects) = state.objects.clone() {
        relocate(state, &objects, &mut done).await;
        match sweep(state, &objects).await {
            Ok(swept) => done.swept = swept,
            Err(e) => tracing::warn!("sweeping S3 failed: {e:?}"),
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

async fn relocate(state: &AppState, objects: &Objects, done: &mut Pass) {
    let target = state.config.blob_target;
    let misplaced = match state.db(move |c| store::misplaced_blobs(c, target)).await {
        Ok(misplaced) => misplaced,
        Err(e) => {
            tracing::warn!("listing blobs to move failed: {}", e.message);
            return;
        }
    };
    for blob in misplaced {
        let moved = match blob.to {
            Stored::S3 => to_s3(state, objects, blob.user_id, blob.id).await,
            Stored::Local => {
                let user_id = blob.user_id;
                let id = blob.id;
                match state.db(move |c| store::blob_meta(c, &user_id, id)).await {
                    Ok(Some(meta)) => to_local(state, objects, user_id, meta, false).await,
                    Ok(None) => Ok(false),
                    Err(e) => Err(e.into()),
                }
            }
        };
        match (moved, blob.to) {
            (Ok(true), Stored::S3) => done.to_s3 += 1,
            (Ok(true), Stored::Local) => done.to_local += 1,
            (Ok(false), _) => {}
            (Err(MoveError::Lost), _) => {
                tracing::warn!("blob {} is lost: its object is gone or damaged", blob.id);
                done.lost += 1;
            }
            (Err(e), _) => {
                tracing::warn!("moving blob {} failed: {e:?}", blob.id);
                done.failed += 1;
            }
        }
    }
}

/// Deletes every object under the prefix that no blob in S3 owns: left by crashes, by deleted blobs and users, and
/// by older binaries. Keys that aren't ours are left alone.
async fn sweep(state: &AppState, objects: &Objects) -> Result<u64, MoveError> {
    let keys = objects.list().await?;
    let owned = state.db(|c| store::blobs_in_s3(c)).await?;
    let mut swept = 0;
    for (user_id, id) in keys
        .iter()
        .filter_map(|key| objects.parse_key(key))
        .filter(|blob| !owned.contains(blob))
    {
        // Checked again under the key's lock: a move may have taken it since the list.
        let held = state.moving.lock(objects.key(&user_id, id)).await;
        if drop_unowned(state, objects, &held, user_id, id).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blobs_in_s3_need_that_s3() {
        let here = S3Location {
            endpoint: "https://s3.example.com".into(),
            bucket: "music".into(),
            prefix: "music/".into(),
        };
        let other = S3Location {
            bucket: "other".into(),
            ..here.clone()
        };
        assert!(check_location(0, None, None).is_ok());
        assert!(
            check_location(0, Some(&here), Some(&other)).is_ok(),
            "nothing there yet"
        );
        assert!(check_location(3, Some(&here), Some(&here)).is_ok());
        assert!(check_location(3, Some(&here), None).is_err());
        assert!(check_location(3, Some(&here), Some(&other)).is_err());
        assert!(check_location(3, None, Some(&here)).is_err());
    }
}
