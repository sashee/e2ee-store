//! Making and dropping blobs' copies in the database and the storage backends (SPEC §7.4): on upload, when a flag
//! changes, when a read finds a copy gone, and in a pass at startup and every hour, which also sweeps the backends and
//! returns freed pages to the file system. Where a blob's copies belong is `placement`'s to say; copies into the
//! database need the room for them (SPEC §7.5).
//!
//! A copy is put where it goes before its row says it's there, and its row goes before its object does; a row only
//! changes if the blob is still as it was. So a crash or a race leaves at worst an object nobody owns, for the sweep.
//! Whatever writes or deletes an object, or forgets a copy, holds its key's lock, and deletes an object only if the
//! database, read under that lock, says no copy is there: so an object a copy is about to own is never deleted.
//! Nothing holds two keys' locks at once but an upload, which takes them in order.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

use axum::body::Bytes;

use crate::domain::BlobId;
use crate::http::{ApiError, AppState};
use crate::objects::ObjectError;
use crate::placement::{self, Location, Step};
use crate::remotes::Remote;
use crate::store::{self, BackendRecord, BlobMeta, NewCopies, Put, Storage, Usage, UserId};
use crate::{db, disk};

/// How often blobs' copies are brought in line, the backends swept, and freed pages returned.
pub const PASS_EVERY: Duration = Duration::from_secs(60 * 60);
/// Pages returned to the file system per step; each step holds the write lock only that long.
const RECLAIM_STEP: u32 = 1024;

#[derive(Debug)]
pub enum CopyError {
    /// No copy could be read: each is gone, or isn't the blob any more.
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

impl From<ApiError> for CopyError {
    fn from(e: ApiError) -> Self {
        Self::Db(e)
    }
}

impl From<ObjectError> for CopyError {
    fn from(e: ObjectError) -> Self {
        match e {
            ObjectError::NotFound | ObjectError::Damaged => Self::Lost,
            ObjectError::Unavailable(why) => Self::Unavailable(why),
        }
    }
}

impl From<CopyError> for ApiError {
    fn from(e: CopyError) -> Self {
        match e {
            CopyError::Lost => ApiError::blob_lost(),
            CopyError::Unavailable(why) => ApiError::storage_unavailable(why),
            CopyError::Full { needed, free } => ApiError::storage_full(needed, free),
            CopyError::Db(e) => e,
        }
    }
}

/// Refuses to serve if copies are in a backend the server can't reach them in: one that isn't configured, or one
/// whose name now stands for another type or location than the one they went to. Otherwise all of them would read as
/// lost, and nothing could drop them.
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
                "{blobs} blobs have a copy in backend {name:?}, which isn't configured: configure it, so they can be read and dropped; or if it is gone for good, `forget {name}` it"
            );
        };
        if !find(recorded, name).is_some_and(|there| same_place(&there, &here)) {
            anyhow::bail!(
                "{blobs} blobs have a copy in backend {name:?}, but its configuration names another type or location than the one they went to"
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
fn room(state: &AppState, total: u64, largest: u64) -> Result<(), CopyError> {
    let free = (state.free_space)(&state.config.database)
        .map_err(|e| CopyError::Unavailable(format!("the free space is unknown: {e}")))?;
    let reserve = state.config.min_free_space;
    if disk::fits(free, total, largest, reserve) {
        Ok(())
    } else {
        Err(CopyError::Full {
            needed: total.saturating_add(largest).saturating_add(reserve),
            free,
        })
    }
}

/// Whether one blob of `bytes` fits in the database.
pub fn room_for(state: &AppState, bytes: u64) -> Result<(), CopyError> {
    room(state, bytes, bytes)
}

/// What a backend's object is locked under: its key, in that backend.
fn lock_name(remote: &Remote, key: &str) -> String {
    format!("{}\n{key}", remote.name)
}

fn targets(state: &AppState) -> &[Location] {
    &state.config.blob_target
}

/// Whether offloadable uploads go to backends at all (`upload`), rather than into the database alone.
pub fn targets_a_backend(state: &AppState) -> bool {
    targets(state)
        .iter()
        .any(|target| matches!(target, Location::Backend(_)))
}

fn configured<'a>(state: &'a AppState, name: &str) -> Result<&'a Remote, CopyError> {
    state
        .remotes
        .get(name)
        .map(|remote| &**remote)
        .ok_or_else(|| CopyError::Unavailable(format!("backend {name:?} isn't configured")))
}

/// A new offloadable blob, or a lost one uploaded again, while backends are among the targets: it goes to all of them
/// at once, and into the database too if that is a target and has the room. It is stored once a backend has it; if
/// none took it, the database takes it, room permitting, target or not. The pass makes the copies that failed.
pub async fn upload(
    state: &AppState,
    user_id: UserId,
    id: BlobId,
    content: Bytes,
    now: i64,
) -> Result<(Put, BlobMeta), ApiError> {
    if let Some(meta) = state
        .db(move |c| store::blob_meta(c, &user_id, id))
        .await?
        .filter(|meta| !meta.copies.is_empty())
    {
        return Ok((Put::Existed, meta));
    }
    let remotes: Vec<Arc<Remote>> = targets(state)
        .iter()
        .filter_map(|target| match target {
            Location::Backend(name) => state.remotes.get(name).cloned(),
            Location::Local => None,
        })
        .collect();
    let mut lock_names: Vec<String> = remotes
        .iter()
        .map(|remote| lock_name(remote, &remote.key(&user_id, id)))
        .collect();
    // In order: the one place that holds more than one key's lock.
    lock_names.sort();
    let mut held = Vec::new();
    for name in lock_names {
        held.push(state.moving.lock(name).await);
    }
    // Spawned so they run in parallel; dropping the set, as a cancelled request does, aborts them.
    let mut puts = tokio::task::JoinSet::new();
    for remote in &remotes {
        let (remote, content) = (remote.clone(), content.clone());
        puts.spawn(async move {
            let put = remote.put(&remote.key(&user_id, id), content).await;
            (remote, put)
        });
    }
    let (taken, failed): (Vec<_>, Vec<_>) = puts
        .join_all()
        .await
        .into_iter()
        .partition(|(_, put)| put.is_ok());
    for (remote, put) in &failed {
        if let Err(e) = put {
            tracing::warn!(
                "blob {id}'s copy in {:?} waits for the pass: {e}",
                remote.name
            );
        }
    }
    let size = content.len() as u64;
    let here = if taken.is_empty() {
        let why = failed
            .first()
            .and_then(|(_, put)| put.as_ref().err())
            .map_or_else(|| "no backend took it".to_owned(), ToString::to_string);
        room_for(state, size).map_err(|_| ApiError::storage_unavailable(why))?;
        true
    } else if targets(state).contains(&Location::Local) {
        room_for(state, size)
            .inspect_err(|e| tracing::warn!("blob {id} waits for its copy in the database: {e:?}"))
            .is_ok()
    } else {
        false
    };
    let records: Vec<BackendRecord> = taken.iter().map(|(remote, _)| remote.record()).collect();
    let (put, meta) = state
        .db(move |c| {
            let copies = NewCopies {
                here,
                backends: &records,
            };
            store::put_blob(c, &user_id, id, &content, true, copies, now)
        })
        .await?;
    if put == Put::Existed {
        // Another upload of the same blob got there first: what it didn't put there is nobody's.
        for (remote, _) in &taken {
            let name = lock_name(remote, &remote.key(&user_id, id));
            if let Some(guard) = held.iter().find(|guard| guard.key == name) {
                drop_unowned(state, remote, guard, user_id, id).await;
            }
        }
    }
    Ok((put, meta))
}

/// Whether a blob uploaded again is lost: no copy in the database, and every copy in a backend gone or another size,
/// as asked for (one byte each); its rows are forgotten then, so the upload stores it anew (SPEC §7.1). A backend that
/// can't be asked counts as having it.
pub async fn forget_if_lost(
    state: &AppState,
    user_id: UserId,
    meta: &BlobMeta,
) -> Result<bool, ApiError> {
    if meta.here() {
        return Ok(false);
    }
    for name in placement::read_order(&meta.copies, targets(state)) {
        let Ok(remote) = configured(state, &name) else {
            return Ok(false);
        };
        match remote.size(&remote.key(&user_id, meta.id)).await {
            Ok(None) => {}
            Ok(Some(size)) if size != meta.size => {}
            Ok(Some(_)) | Err(_) => return Ok(false),
        }
    }
    let (id, copies) = (meta.id, meta.copies.clone());
    state
        .db(move |c| store::forget_lost(c, &user_id, id, &copies))
        .await
}

/// Why a copy is suspect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Its backend answered that there is no such object.
    Gone,
    /// It came back another size, or with bytes that aren't the blob's.
    Damaged,
}

/// What a suspect copy turned out to be, checked again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checked {
    Sound,
    Gone,
    Damaged,
}

/// Checks a copy suspected of `fault` once more: a gone one by asking for its size, a damaged one by fetching it whole
/// and hashing it.
async fn check(
    remote: &Remote,
    key: &str,
    id: BlobId,
    size: u64,
    fault: Fault,
) -> Result<Checked, ObjectError> {
    match fault {
        Fault::Gone => Ok(match remote.size(key).await? {
            None => Checked::Gone,
            Some(there) if there == size => Checked::Sound,
            Some(_) => Checked::Damaged,
        }),
        Fault::Damaged => match remote.get_all(key, size).await {
            Ok(content) if BlobId::of(&content) == id => Ok(Checked::Sound),
            Ok(_) | Err(ObjectError::Damaged) => Ok(Checked::Damaged),
            Err(ObjectError::NotFound) => Ok(Checked::Gone),
            Err(e) => Err(e),
        },
    }
}

/// A copy in `remote` that was found gone or damaged. Under its key's lock it is checked once more (`check`), as a
/// sound one may have been made there since. If it is still gone or damaged and the blob has another copy, its row
/// goes, a damaged one's object with it, so the pass makes it again. A blob's last copy stays: it reads as lost.
/// → whether it went.
pub async fn give_up(
    state: &AppState,
    remote: &Remote,
    user_id: UserId,
    id: BlobId,
    size: u64,
    fault: Fault,
) -> bool {
    let key = remote.key(&user_id, id);
    let held = state.moving.lock(lock_name(remote, &key)).await;
    let checked = match check(remote, &key, id, size, fault).await {
        Ok(Checked::Sound) => return false,
        Ok(checked) => checked,
        Err(e) => {
            tracing::warn!("checking blob {id}'s copy in {:?} failed: {e}", remote.name);
            return false;
        }
    };
    let name = remote.name.clone();
    match state
        .db(move |c| store::forget_copy(c, &user_id, id, &name))
        .await
    {
        Ok(true) => {
            tracing::warn!(
                "blob {id}'s copy in {:?} is {}; the pass makes another",
                remote.name,
                if checked == Checked::Gone {
                    "gone"
                } else {
                    "damaged"
                }
            );
            if checked == Checked::Damaged {
                drop_unowned(state, remote, &held, user_id, id).await;
            }
            true
        }
        Ok(false) => false,
        Err(e) => {
            tracing::warn!(
                "forgetting blob {id}'s copy in {:?} failed: {}",
                remote.name,
                e.message
            );
            false
        }
    }
}

/// Tries `attempt` on the blob's copies in backends, in read order, until one gives what it asks for: `attempt` gets
/// the backend and the copy's key. A copy found gone or damaged (`NotFound`, `Damaged`) is given up (`give_up`), and
/// the next one tried. With none left: Unavailable if a backend couldn't be reached; else, if the blob's copies have
/// changed since `meta` was read, as a pass may move a blob while it is read, or the blob is gone, None, for the caller
/// to look it up again; else Lost. Reads and copies alike go through here.
pub async fn from_backends<T>(
    state: &AppState,
    user_id: UserId,
    meta: &BlobMeta,
    attempt: impl AsyncFn(&Remote, &str) -> Result<T, ObjectError>,
) -> Result<Option<T>, CopyError> {
    let mut unavailable = None;
    for name in placement::read_order(&meta.copies, targets(state)) {
        let remote = match configured(state, &name) {
            Ok(remote) => remote,
            Err(e) => {
                unavailable = Some(e);
                continue;
            }
        };
        let fault = match attempt(remote, &remote.key(&user_id, meta.id)).await {
            Ok(got) => return Ok(Some(got)),
            Err(ObjectError::NotFound) => Fault::Gone,
            Err(ObjectError::Damaged) => Fault::Damaged,
            Err(e @ ObjectError::Unavailable(_)) => {
                unavailable = Some(e.into());
                continue;
            }
        };
        give_up(state, remote, user_id, meta.id, meta.size, fault).await;
    }
    if let Some(e) = unavailable {
        return Err(e);
    }
    let id = meta.id;
    let now = state.db(move |c| store::blob_meta(c, &user_id, id)).await?;
    if now.is_some_and(|now| now.copies == meta.copies) {
        Err(CopyError::Lost)
    } else {
        Ok(None)
    }
}

/// The blob's content, from a copy it has now: the database's, or else one in a backend, checked against the blob's
/// ID (`from_backends`). None if the blob is gone.
async fn fetch(state: &AppState, user_id: UserId, id: BlobId) -> Result<Option<Bytes>, CopyError> {
    for _ in 0..3 {
        let Some(meta) = state.db(move |c| store::blob_meta(c, &user_id, id)).await? else {
            return Ok(None);
        };
        // A copy here dropped since is still in a backend: a drop needs every copy the blob belongs in.
        if meta.here()
            && let Some(content) = state
                .db(move |c| store::local_content(c, &user_id, id))
                .await?
        {
            return Ok(Some(content.into()));
        }
        let size = meta.size;
        let whole = async move |remote: &Remote, key: &str| match remote.get_all(key, size).await {
            Ok(content) if BlobId::of(&content) == id => Ok(content),
            Ok(_) => Err(ObjectError::Damaged),
            Err(e) => Err(e),
        };
        if let Some(content) = from_backends(state, user_id, &meta, whole).await? {
            return Ok(Some(content));
        }
    }
    Err(CopyError::Unavailable(format!(
        "blob {id}'s copies kept changing"
    )))
}

/// Puts `content` in the database as the blob's copy there, room permitting, if it has none; `unflag` also makes it
/// not offloadable, in the same step. → whether it did.
async fn put_local(
    state: &AppState,
    user_id: UserId,
    id: BlobId,
    content: Bytes,
    unflag: bool,
) -> Result<bool, CopyError> {
    room_for(state, content.len() as u64)?;
    Ok(state
        .db(move |c| store::add_local(c, &user_id, id, &content, unflag))
        .await?)
}

/// Gives the blob a copy in the database, from a copy it has, room permitting; `unflag` also makes it not
/// offloadable, in the same step. → whether it did; false if it has one already, or is gone.
pub async fn to_local(
    state: &AppState,
    user_id: UserId,
    meta: &BlobMeta,
    unflag: bool,
) -> Result<bool, CopyError> {
    room_for(state, meta.size)?;
    let Some(content) = fetch(state, user_id, meta.id).await? else {
        return Ok(false);
    };
    put_local(state, user_id, meta.id, content, unflag).await
}

/// Puts `content` in backend `to` as the blob's copy there. → whether it is the blob's now; false if it had one
/// already, or is gone or no longer offloadable.
async fn put_copy(
    state: &AppState,
    to: &Remote,
    user_id: UserId,
    id: BlobId,
    content: Bytes,
) -> Result<bool, CopyError> {
    let key = to.key(&user_id, id);
    let held = state.moving.lock(lock_name(to, &key)).await;
    to.put(&key, content).await?;
    let record = to.record();
    let added = state
        .db(move |c| store::add_copy(c, &user_id, id, &record))
        .await?;
    if !added {
        drop_unowned(state, to, &held, user_id, id).await;
    }
    Ok(added)
}

/// Whether the blob's copies in the backends it belongs in are there, and its size: rows can outlive their objects
/// until a sweep notices, and a drop leaves the blob with only these. One that isn't is given up (`give_up`).
async fn confirmed(state: &AppState, user_id: UserId, meta: &BlobMeta) -> Result<bool, CopyError> {
    for place in placement::belongs(meta.offloadable, targets(state)) {
        let Location::Backend(name) = &place else {
            continue;
        };
        let remote = configured(state, name)?;
        let fault = match remote.size(&remote.key(&user_id, meta.id)).await? {
            Some(size) if size == meta.size => continue,
            Some(_) => Fault::Damaged,
            None => Fault::Gone,
        };
        give_up(state, remote, user_id, meta.id, meta.size, fault).await;
        return Ok(false);
    }
    Ok(true)
}

/// Drops the blob's copy in `from`, once the copies it keeps are confirmed there (`confirmed`) and if it may still go
/// (`store::drop_copy`); a backend's object after its row.
async fn drop_copy(
    state: &AppState,
    user_id: UserId,
    meta: &BlobMeta,
    from: &Location,
) -> Result<bool, CopyError> {
    if !confirmed(state, user_id, meta).await? {
        return Ok(false);
    }
    let (id, place, targets) = (meta.id, from.clone(), targets(state).to_vec());
    let drop_row =
        move |c: &mut rusqlite::Connection| store::drop_copy(c, &user_id, id, &place, &targets);
    match from {
        Location::Local => Ok(state.db(drop_row).await?),
        Location::Backend(name) => {
            let remote = configured(state, name)?;
            let held = state
                .moving
                .lock(lock_name(remote, &remote.key(&user_id, id)))
                .await;
            let dropped = state.db(drop_row).await?;
            if dropped {
                drop_unowned(state, remote, &held, user_id, id).await;
            }
            Ok(dropped)
        }
    }
}

/// What a blob's steps may do: copies into the database (`home`) only if they all fit (`reconcile`); drops only if
/// every target backend's list worked in the pass (`pass`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allowed {
    pub home: bool,
    pub drops: bool,
}

impl Allowed {
    pub const ALL: Allowed = Allowed {
        home: true,
        drops: true,
    };
}

/// Brings one blob's copies in line with where it belongs (`placement::plan`): the missing ones first, then, once
/// they are all there, the ones anywhere else. → what it did.
pub async fn settle(state: &AppState, user_id: UserId, meta: BlobMeta, allowed: Allowed) -> Pass {
    let first = run(state, user_id, &meta, allowed).await;
    let id = meta.id;
    let Ok(Some(meta)) = state.db(move |c| store::blob_meta(c, &user_id, id)).await else {
        return first;
    };
    // The drops the copies allow, now; but copies that failed aren't tried again until the next pass.
    let steps = placement::plan(meta.offloadable, &meta.copies, targets(state));
    if steps.iter().all(|step| matches!(step, Step::Drop(_))) {
        first.plus(run(state, user_id, &meta, allowed).await)
    } else {
        first
    }
}

/// The blob's plan: its missing copies (`make_copies`), or else its drops, one after the other.
async fn run(state: &AppState, user_id: UserId, meta: &BlobMeta, allowed: Allowed) -> Pass {
    let steps = placement::plan(meta.offloadable, &meta.copies, targets(state));
    let missing: Vec<Location> = steps
        .iter()
        .filter_map(|step| match step {
            Step::Copy(place) => Some(place.clone()),
            Step::Drop(_) => None,
        })
        .collect();
    if !missing.is_empty() {
        return make_copies(state, user_id, meta, &missing, allowed.home).await;
    }
    if !allowed.drops {
        return Pass::default();
    }
    let mut done = Pass::default();
    for step in &steps {
        if let Step::Drop(from) = step {
            done = done.plus(tally(
                step,
                drop_copy(state, user_id, meta, from).await,
                meta.id,
            ));
        }
    }
    done
}

/// Makes the blob's copies in `places` from one fetch of its content: the one in the database, if `home` and the
/// room allow, and the ones in backends at once.
async fn make_copies(
    state: &AppState,
    user_id: UserId,
    meta: &BlobMeta,
    places: &[Location],
    home: bool,
) -> Pass {
    let id = meta.id;
    let wants_local = places.contains(&Location::Local);
    let here = wants_local && home && room_for(state, meta.size).is_ok();
    let waiting = Pass {
        held_back: u64::from(wants_local && !here),
        ..Pass::default()
    };
    let backends: Vec<String> = places
        .iter()
        .filter_map(|place| match place {
            Location::Backend(name) => Some(name.clone()),
            Location::Local => None,
        })
        .collect();
    if !here && backends.is_empty() {
        return waiting;
    }
    let content = match fetch(state, user_id, id).await {
        Ok(Some(content)) => content,
        Ok(None) => return waiting,
        Err(e) => return waiting.plus(tally(&Step::Copy(places[0].clone()), Err(e), id)),
    };
    // Spawned so they run in parallel; each tallies its own step.
    let mut puts = tokio::task::JoinSet::new();
    for name in backends {
        let (state, content) = (state.clone(), content.clone());
        puts.spawn(async move {
            let put = match configured(&state, &name) {
                Ok(to) => put_copy(&state, to, user_id, id, content).await,
                Err(e) => Err(e),
            };
            tally(&Step::Copy(Location::Backend(name)), put, id)
        });
    }
    let local = if here {
        let put = put_local(state, user_id, id, content, false).await;
        tally(&Step::Copy(Location::Local), put, id)
    } else {
        Pass::default()
    };
    puts.join_all()
        .await
        .into_iter()
        .fold(waiting.plus(local), Pass::plus)
}

/// What one step did, for the pass's log.
fn tally(step: &Step, outcome: Result<bool, CopyError>, id: BlobId) -> Pass {
    let one = Pass::default();
    match (step, outcome) {
        (_, Ok(false)) => one,
        (Step::Copy(Location::Local), Ok(true)) => Pass { to_local: 1, ..one },
        (Step::Copy(_), Ok(true)) => Pass {
            to_backend: 1,
            ..one
        },
        (Step::Drop(_), Ok(true)) => Pass { dropped: 1, ..one },
        (_, Err(CopyError::Lost)) => {
            tracing::warn!("blob {id} is lost: every copy is gone or damaged");
            Pass { lost: 1, ..one }
        }
        (_, Err(CopyError::Full { .. })) => Pass {
            held_back: 1,
            ..one
        },
        (_, Err(e)) => {
            tracing::warn!("{step:?} of blob {id} failed: {e:?}");
            Pass { failed: 1, ..one }
        }
    }
}

async fn located_in(
    state: &AppState,
    user_id: UserId,
    id: BlobId,
    remote: &Remote,
) -> Result<bool, ApiError> {
    let meta = state.db(move |c| store::blob_meta(c, &user_id, id)).await?;
    let there = Location::Backend(remote.name.clone());
    Ok(meta.is_some_and(|meta| meta.copies.contains(&there)))
}

/// After a blob is deleted: deletes its object in `remote`, unless an upload has put the blob back meanwhile.
pub async fn forget(state: &AppState, remote: &Remote, user_id: UserId, id: BlobId) {
    let held = state
        .moving
        .lock(lock_name(remote, &remote.key(&user_id, id)))
        .await;
    drop_unowned(state, remote, &held, user_id, id).await;
}

/// Deletes the blob's object in `remote` unless the database says the blob has a copy there. The caller holds the
/// key's lock, so nothing can make it one in between. → whether it deleted it; if that fails, a later sweep does.
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

/// What a pass did, for the log: steps, objects and pages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Copies made in backends.
    pub to_backend: u64,
    /// Copies made in the database.
    pub to_local: u64,
    /// Copies dropped where blobs no longer belong.
    pub dropped: u64,
    /// Copies the database needs but hasn't the room for: they wait.
    pub held_back: u64,
    pub failed: u64,
    /// Blobs whose copies couldn't be made, as every copy they have is gone or damaged.
    pub lost: u64,
    /// Objects no copy owns, deleted.
    pub swept: u64,
    /// Copies found gone from their backend and forgotten, so the pass makes them again.
    pub vanished: u64,
    pub reclaimed_pages: u64,
}

impl Pass {
    fn plus(self, other: Pass) -> Pass {
        Pass {
            to_backend: self.to_backend + other.to_backend,
            to_local: self.to_local + other.to_local,
            dropped: self.dropped + other.dropped,
            held_back: self.held_back + other.held_back,
            failed: self.failed + other.failed,
            lost: self.lost + other.lost,
            swept: self.swept + other.swept,
            vanished: self.vanished + other.vanished,
            reclaimed_pages: self.reclaimed_pages + other.reclaimed_pages,
        }
    }
}

/// Sweeps every backend, brings every blob's copies in line, and returns freed pages to the file system. The sweep
/// goes first, so copies it finds gone are made again in the same pass. Never fails: what doesn't work now is tried
/// again in the next pass.
pub async fn pass(state: &AppState) -> Pass {
    let mut done = Pass::default();
    let mut unlisted = Vec::new();
    for remote in state.remotes.values() {
        match sweep(state, remote).await {
            Ok(swept) => done = done.plus(swept),
            Err(e) => {
                tracing::warn!("sweeping backend {:?} failed: {e:?}", remote.name);
                unlisted.push(Location::Backend(remote.name.clone()));
            }
        }
    }
    // A target whose list failed, its bucket gone perhaps, may not have the copies its rows say: nothing is dropped
    // on their word.
    let drops = !targets(state)
        .iter()
        .any(|target| unlisted.contains(target));
    done = done.plus(reconcile(state, drops).await);
    match reclaim(state).await {
        Ok(pages) => done.reclaimed_pages = pages,
        Err(e) => tracing::warn!("returning free pages failed: {}", e.message),
    }
    if done != Pass::default() {
        tracing::info!("offloading pass: {done:?}");
    }
    done
}

/// Every blob whose copies aren't where they belong, one after the other. Copies into the database are made for all
/// of them or none: some would fill the disk and still leave the rest out.
async fn reconcile(state: &AppState, drops: bool) -> Pass {
    let list = targets(state).to_vec();
    let unsettled = match state.db(move |c| store::unsettled_blobs(c, &list)).await {
        Ok(unsettled) => unsettled,
        Err(e) => {
            tracing::warn!("listing blobs to copy failed: {}", e.message);
            return Pass::default();
        }
    };
    let home: Vec<u64> = unsettled
        .iter()
        .filter(|(_, meta)| {
            placement::plan(meta.offloadable, &meta.copies, targets(state))
                .contains(&Step::Copy(Location::Local))
        })
        .map(|(_, meta)| meta.size)
        .collect();
    let (total, largest) = (home.iter().sum(), home.iter().copied().max().unwrap_or(0));
    let fits = home.is_empty()
        || room(state, total, largest)
            .inspect_err(|e| {
                tracing::warn!(
                    "{} blobs, {total} bytes, need a copy in the database but don't fit, so they wait: {e:?}",
                    home.len()
                )
            })
            .is_ok();
    let allowed = Allowed { home: fits, drops };
    let mut done = Pass::default();
    for (user_id, meta) in unsettled {
        done = done.plus(settle(state, user_id, meta, allowed).await);
    }
    done
}

/// Lists `remote`'s objects, deletes those no copy owns, and gives up the copies the database has there but the list
/// doesn't (`give_up`, which checks each once more). Keys that aren't ours are left alone. Nothing happens if the list
/// fails.
async fn sweep(state: &AppState, remote: &Remote) -> Result<Pass, CopyError> {
    let keys = remote.list().await?;
    let name = remote.name.clone();
    // Read after the list: a copy made in between is in here and not there, and `give_up` finds its object.
    let owned = state.db(move |c| store::blobs_in(c, &name)).await?;
    let listed: HashSet<(UserId, BlobId)> = keys
        .iter()
        .filter_map(|key| remote.parse_key(key))
        .collect();
    let mut done = Pass::default();
    for &(user_id, id) in listed.iter().filter(|blob| !owned.contains_key(blob)) {
        // Checked again under the key's lock: a copy may have been made since the list.
        let held = state
            .moving
            .lock(lock_name(remote, &remote.key(&user_id, id)))
            .await;
        if drop_unowned(state, remote, &held, user_id, id).await {
            done.swept += 1;
        }
    }
    for (&(user_id, id), &size) in owned.iter().filter(|(blob, _)| !listed.contains(blob)) {
        if give_up(state, remote, user_id, id, size, Fault::Gone).await {
            done.vanished += 1;
        }
    }
    Ok(done)
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

/// The copies in each place, how many copies the offloadable blobs have, and whether bringing every blob into the
/// database would fit: for `backend storage`.
pub fn storage_report(
    storage: &Storage,
    targets: &[Location],
    free: u64,
    min_free_space: u64,
    max_blob_size: u64,
) -> String {
    let rows: String = storage
        .places
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
    let by_copies = if storage.by_copies.is_empty() {
        "none".to_owned()
    } else {
        storage
            .by_copies
            .iter()
            .map(|(copies, blobs)| format!("{blobs} with {copies}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (lost, lost_bytes) = storage.lost;
    let (_, elsewhere) = storage.elsewhere;
    let largest = max_blob_size.min(elsewhere);
    let verdict = if disk::fits(free, elsewhere, largest, min_free_space) {
        "fits"
    } else {
        "doesn't fit"
    };
    let targets = targets
        .iter()
        .map(Location::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{:<20} {:>8} {:>12}\n{rows}\ntarget: {targets} (a copy in each, for offloadable blobs; the others are local)\noffloadable blobs by copies: {by_copies}\nlost, with no copy left: {lost} blobs, {}\nfree: {}, of which {} stays free\nbringing everything into the database: {} more; {verdict}\n",
        "where",
        "copies",
        "bytes",
        human(lost_bytes),
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
    fn the_report_says_where_the_copies_are_and_whether_everything_fits_back() {
        let storage = Storage {
            places: vec![
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
                Usage {
                    location: Location::Backend("b2".into()),
                    blobs: 100,
                    bytes: 4 << 30,
                },
            ],
            by_copies: vec![(1, 20), (2, 100)],
            elsewhere: (120, 5 << 30),
            lost: (1, 512),
        };
        let targets = [Location::named("aws"), Location::named("b2")];
        let report = storage_report(&storage, &targets, 7 << 30, 1 << 30, 16 << 20);
        let row = |words: &[&str]| {
            report
                .lines()
                .any(|line| line.split_whitespace().eq(words.iter().copied()))
        };
        assert!(row(&["local", "16", "257.2", "KiB"]), "{report}");
        assert!(row(&["aws", "120", "5.0", "GiB"]), "{report}");
        assert!(report.contains("target: aws, b2"), "{report}");
        assert!(
            report.contains("by copies: 20 with 1, 100 with 2"),
            "{report}"
        );
        assert!(
            report.contains("lost, with no copy left: 1 blobs, 512 B"),
            "{report}"
        );
        assert!(report.contains("5.0 GiB more; fits"), "{report}");
        let tight = storage_report(&storage, &targets, 6 << 30, 1 << 30, 16 << 20);
        assert!(tight.contains("doesn't fit"), "{tight}");
        assert_eq!(human(512), "512 B");
    }
}
