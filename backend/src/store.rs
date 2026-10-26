//! Persistence (SPEC §5, §7): plain functions over a connection. Callers pass `now`; nothing here reads
//! the clock. Outcomes the API distinguishes are returned as enums; `Err` is reserved for SQLite failures.

use std::collections::{BTreeSet, HashMap};

use rusqlite::{Connection, MAIN_DB, OptionalExtension, Row, TransactionBehavior, params};

use crate::domain::{BlobId, ByteRange, Precondition, is_live, precondition_holds};
use crate::placement;

pub type UserId = [u8; 16];

// ---------------------------------------------------------------- users

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub created_at: i64,
}

fn user_row(row: &Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        created_at: row.get(2)?,
    })
}

/// `false` when the username is taken.
pub fn insert_user(conn: &Connection, user: &User) -> rusqlite::Result<bool> {
    let inserted = conn.execute(
        "INSERT INTO users (id, username, created_at) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
        params![user.id, user.username, user.created_at],
    )?;
    Ok(inserted == 1)
}

pub fn user_by_id(conn: &Connection, id: &UserId) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        "SELECT id, username, created_at FROM users WHERE id = ?1",
        [id],
        user_row,
    )
    .optional()
}

pub fn user_by_username(conn: &Connection, username: &str) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        "SELECT id, username, created_at FROM users WHERE username = ?1",
        [username],
        user_row,
    )
    .optional()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSummary {
    pub user: User,
    /// `(rp_id, count)` per host.
    pub passkeys: Vec<(String, i64)>,
    pub stored_bytes: i64,
}

pub fn list_users(conn: &Connection) -> rusqlite::Result<Vec<UserSummary>> {
    let users = conn
        .prepare("SELECT id, username, created_at FROM users ORDER BY username")?
        .query_map([], user_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    users
        .into_iter()
        .map(|user| {
            let passkeys = conn
                .prepare("SELECT rp_id, count(*) FROM passkeys WHERE user_id = ?1 GROUP BY rp_id ORDER BY rp_id")?
                .query_map([user.id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let stored_bytes =
                conn.query_row("SELECT coalesce(sum(size), 0) FROM blobs WHERE user_id = ?1", [user.id], |r| r.get(0))?;
            Ok(UserSummary { user, passkeys, stored_bytes })
        })
        .collect()
}

/// Deletes the user and, by cascade, everything they own.
pub fn delete_user(conn: &Connection, id: &UserId) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM users WHERE id = ?1", [id])? == 1)
}

// ---------------------------------------------------------------- passkeys

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passkey {
    pub id: Vec<u8>,
    pub user_id: UserId,
    pub rp_id: String,
    pub name: String,
    pub static_state: Vec<u8>,
    pub dynamic_state: Vec<u8>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

const PASSKEY_COLUMNS: &str =
    "id, user_id, rp_id, name, static_state, dynamic_state, created_at, last_used_at";

fn passkey_row(row: &Row) -> rusqlite::Result<Passkey> {
    Ok(Passkey {
        id: row.get(0)?,
        user_id: row.get(1)?,
        rp_id: row.get(2)?,
        name: row.get(3)?,
        static_state: row.get(4)?,
        dynamic_state: row.get(5)?,
        created_at: row.get(6)?,
        last_used_at: row.get(7)?,
    })
}

/// `false` when the credential ID is already registered.
pub fn insert_passkey(conn: &Connection, p: &Passkey) -> rusqlite::Result<bool> {
    let inserted = conn.execute(
        &format!("INSERT INTO passkeys ({PASSKEY_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT DO NOTHING"),
        params![p.id, p.user_id, p.rp_id, p.name, p.static_state, p.dynamic_state, p.created_at, p.last_used_at],
    )?;
    Ok(inserted == 1)
}

pub fn passkey_by_id(conn: &Connection, id: &[u8]) -> rusqlite::Result<Option<Passkey>> {
    conn.query_row(
        &format!("SELECT {PASSKEY_COLUMNS} FROM passkeys WHERE id = ?1"),
        [id],
        passkey_row,
    )
    .optional()
}

pub fn passkeys_of(conn: &Connection, user_id: &UserId) -> rusqlite::Result<Vec<Passkey>> {
    conn.prepare(&format!(
        "SELECT {PASSKEY_COLUMNS} FROM passkeys WHERE user_id = ?1 ORDER BY created_at, id"
    ))?
    .query_map([user_id], passkey_row)?
    .collect()
}

/// Records a successful login; `dynamic_state` only when verification changed it.
pub fn record_passkey_use(
    conn: &Connection,
    id: &[u8],
    dynamic_state: Option<&[u8]>,
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE passkeys SET last_used_at = ?2, dynamic_state = coalesce(?3, dynamic_state) WHERE id = ?1",
        params![id, now, dynamic_state],
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyDeletion {
    Deleted,
    NotFound,
    LastPasskey,
}

/// Deletes one of the user's own passkeys, unless it is their last. Sessions created with it go too
/// (foreign key cascade). Counted and deleted under one write lock, so two deletions can't both pass.
pub fn delete_passkey(
    conn: &mut Connection,
    user_id: &UserId,
    id: &[u8],
) -> rusqlite::Result<PasskeyDeletion> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let owned: bool = tx.query_row(
        "SELECT count(*) FROM passkeys WHERE id = ?1 AND user_id = ?2",
        params![id, user_id],
        |r| r.get::<_, i64>(0).map(|n| n == 1),
    )?;
    let total: i64 = tx.query_row(
        "SELECT count(*) FROM passkeys WHERE user_id = ?1",
        [user_id],
        |r| r.get(0),
    )?;
    let outcome = match (owned, total) {
        (false, _) => PasskeyDeletion::NotFound,
        (true, 1) => PasskeyDeletion::LastPasskey,
        (true, _) => {
            tx.execute(
                "DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2",
                params![id, user_id],
            )?;
            PasskeyDeletion::Deleted
        }
    };
    tx.commit()?;
    Ok(outcome)
}

// ---------------------------------------------------------------- sessions

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub user_id: UserId,
    pub passkey_id: Option<Vec<u8>>,
    pub created_at: i64,
    pub expires_at: i64,
}

pub fn insert_session(
    conn: &Connection,
    token_hash: &[u8; 32],
    s: &Session,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, passkey_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![token_hash, s.user_id, s.passkey_id, s.created_at, s.expires_at],
    )?;
    Ok(())
}

pub fn live_session(
    conn: &Connection,
    token_hash: &[u8; 32],
    now: i64,
) -> rusqlite::Result<Option<Session>> {
    let session = conn
        .query_row(
            "SELECT user_id, passkey_id, created_at, expires_at FROM sessions WHERE token_hash = ?1",
            [token_hash],
            |r| Ok(Session { user_id: r.get(0)?, passkey_id: r.get(1)?, created_at: r.get(2)?, expires_at: r.get(3)? }),
        )
        .optional()?;
    Ok(session.filter(|s| is_live(now, s.expires_at)))
}

pub fn delete_session(conn: &Connection, token_hash: &[u8; 32]) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])?;
    Ok(())
}

// ---------------------------------------------------------------- setup tokens

pub fn insert_setup_token(
    conn: &Connection,
    token_hash: &[u8; 32],
    user_id: &UserId,
    created_at: i64,
    expires_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO setup_tokens (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash, user_id, created_at, expires_at],
    )?;
    Ok(())
}

/// Consumes a setup token: the row is deleted whether or not it was still live, so a token works once.
pub fn take_setup_token(
    conn: &Connection,
    token_hash: &[u8; 32],
    now: i64,
) -> rusqlite::Result<Option<UserId>> {
    let row: Option<(UserId, i64)> = conn
        .query_row(
            "DELETE FROM setup_tokens WHERE token_hash = ?1 RETURNING user_id, expires_at",
            [token_hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row
        .filter(|(_, expires_at)| is_live(now, *expires_at))
        .map(|(user_id, _)| user_id))
}

// ---------------------------------------------------------------- ceremonies

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ceremony {
    pub kind: String,
    pub user_id: Option<UserId>,
    pub state: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
}

pub fn insert_ceremony(
    conn: &Connection,
    challenge: &[u8; 16],
    c: &Ceremony,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO ceremonies (challenge, kind, user_id, state, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![challenge, c.kind, c.user_id, c.state, c.created_at, c.expires_at],
    )?;
    Ok(())
}

/// Takes a ceremony out before it is verified, so a challenge answers exactly one response.
pub fn take_ceremony(
    conn: &Connection,
    challenge: &[u8; 16],
    now: i64,
) -> rusqlite::Result<Option<Ceremony>> {
    let ceremony = conn
        .query_row(
            "DELETE FROM ceremonies WHERE challenge = ?1 RETURNING kind, user_id, state, created_at, expires_at",
            [challenge],
            |r| Ok(Ceremony { kind: r.get(0)?, user_id: r.get(1)?, state: r.get(2)?, created_at: r.get(3)?, expires_at: r.get(4)? }),
        )
        .optional()?;
    Ok(ceremony.filter(|c| is_live(now, c.expires_at)))
}

/// Deletes every expired session, setup token and ceremony. Returns how many rows went.
pub fn purge_expired(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    ["sessions", "setup_tokens", "ceremonies"]
        .iter()
        .map(|table| {
            conn.execute(
                &format!("DELETE FROM {table} WHERE expires_at <= ?1"),
                [now],
            )
        })
        .sum()
}

// ---------------------------------------------------------------- blobs

pub use crate::placement::Location;

/// What the database records of a backend copies went to, so a server pointed elsewhere under the same name doesn't
/// take them for lost (SPEC §7.4). `identity` is the type's own description of where it keeps blobs, as JSON, none of
/// it secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendRecord {
    pub name: String,
    pub kind: String,
    pub identity: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    pub id: BlobId,
    pub size: u64,
    pub created_at: i64,
    /// The client allows the server to keep the content outside the database (SPEC §7.1).
    pub offloadable: bool,
    /// Where it has copies (SPEC §7.4): the database first, then backends by name. None left: it is lost.
    pub copies: Vec<Location>,
}

impl BlobMeta {
    /// Whether the database has a copy.
    pub fn here(&self) -> bool {
        self.copies.contains(&Location::Local)
    }
}

/// The columns `blob_meta_row` reads, from `blobs`. `content IS NOT NULL` reads the row's header only, never the
/// content.
const BLOB_META: &str = "blobs.id, blobs.size, blobs.created_at, blobs.offloadable, blobs.content IS NOT NULL,
  (SELECT group_concat(backend, ',') FROM blob_copies c WHERE c.user_id = blobs.user_id AND c.blob_id = blobs.id)";

fn blob_meta_row(row: &Row) -> rusqlite::Result<BlobMeta> {
    let here: bool = row.get(4)?;
    // By name: `group_concat` keeps no order.
    let backends: BTreeSet<String> = row
        .get::<_, Option<String>>(5)?
        .map_or_else(BTreeSet::new, |list| {
            list.split(',').map(str::to_owned).collect()
        });
    Ok(BlobMeta {
        id: BlobId(row.get(0)?),
        size: row.get::<_, i64>(1)?.try_into().unwrap_or(0),
        created_at: row.get(2)?,
        offloadable: row.get(3)?,
        copies: here
            .then_some(Location::Local)
            .into_iter()
            .chain(backends.into_iter().map(Location::Backend))
            .collect(),
    })
}

fn sql_size(size: impl TryInto<i64>) -> i64 {
    size.try_into().unwrap_or(i64::MAX)
}

/// Where a new blob's copies are as its row is written: the database keeps the content if `here`, and `backends`
/// have it already.
#[derive(Clone, Copy, Debug)]
pub struct NewCopies<'a> {
    pub here: bool,
    pub backends: &'a [BackendRecord],
}

impl NewCopies<'_> {
    /// In the database alone.
    pub const HERE: NewCopies<'static> = NewCopies {
        here: true,
        backends: &[],
    };
}

/// What storing a blob did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    Created,
    /// It was lost, with no copy left: the new ones are its copies now.
    Restored,
    /// It has copies, and keeps them, and its flag.
    Existed,
}

/// Stores a blob, unless it exists with a copy: an existing one keeps its flag, and its copies if it has any. One with
/// none left, lost, gets the new ones (SPEC §7.1). → what it did, and the blob's metadata.
pub fn put_blob(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    content: &[u8],
    offloadable: bool,
    copies: NewCopies<'_>,
    now: i64,
) -> rusqlite::Result<(Put, BlobMeta)> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let here = copies.here.then_some(content);
    let put = match blob_meta(&tx, user_id, id)? {
        None => {
            tx.execute(
                "INSERT INTO blobs (user_id, id, size, created_at, offloadable, content)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    user_id,
                    id.0,
                    sql_size(content.len()),
                    now,
                    offloadable,
                    here
                ],
            )?;
            Put::Created
        }
        Some(meta) if meta.copies.is_empty() => {
            tx.execute(
                "UPDATE blobs SET content = ?3 WHERE user_id = ?1 AND id = ?2",
                params![user_id, id.0, here],
            )?;
            Put::Restored
        }
        Some(_) => Put::Existed,
    };
    if put != Put::Existed {
        for backend in copies.backends {
            tx.execute(
                "INSERT INTO blob_copies (user_id, blob_id, backend) VALUES (?1, ?2, ?3)",
                params![user_id, id.0, backend.name],
            )?;
            record_backend(&tx, backend)?;
        }
    }
    let meta = blob_meta(&tx, user_id, id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    tx.commit()?;
    Ok((put, meta))
}

pub fn blob_meta(
    conn: &Connection,
    user_id: &UserId,
    id: BlobId,
) -> rusqlite::Result<Option<BlobMeta>> {
    conn.query_row(
        &format!("SELECT {BLOB_META} FROM blobs WHERE user_id = ?1 AND id = ?2"),
        params![user_id, id.0],
        blob_meta_row,
    )
    .optional()
}

/// The blob's metadata, the range `pick` chooses for its size, and that range's bytes: empty when it's
/// unsatisfiable or the database has no copy. The bytes come through incremental BLOB I/O, so SQLite reads only the
/// pages up to the range's end and only the range is held in memory.
pub fn blob_content(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    pick: impl FnOnce(u64) -> ByteRange,
) -> rusqlite::Result<Option<(BlobMeta, ByteRange, Vec<u8>)>> {
    // One read transaction, so the rowid can't be deleted and reused between the lookup and the read.
    let tx = conn.transaction()?;
    let Some((meta, rowid)) = tx
        .query_row(
            &format!("SELECT {BLOB_META}, rowid FROM blobs WHERE user_id = ?1 AND id = ?2"),
            params![user_id, id.0],
            |r| Ok((blob_meta_row(r)?, r.get::<_, i64>(6)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let range = pick(meta.size);
    let content = match range {
        _ if !meta.here() => Vec::new(),
        ByteRange::Unsatisfiable => Vec::new(),
        ByteRange::Full => read_blob(&tx, rowid, 0, meta.size)?,
        ByteRange::Partial { start, end } => read_blob(&tx, rowid, start, end - start + 1)?,
    };
    Ok(Some((meta, range, content)))
}

fn read_blob(conn: &Connection, rowid: i64, start: u64, len: u64) -> rusqlite::Result<Vec<u8>> {
    let index = |n: u64| usize::try_from(n).map_err(|_| rusqlite::Error::BlobSizeError);
    let mut content = vec![0; index(len)?];
    conn.blob_open(MAIN_DB, c"blobs", c"content", rowid, true)?
        .read_at_exact(&mut content, index(start)?)?;
    Ok(content)
}

/// The database's copy of a blob, whole; None without one.
pub fn local_content(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
) -> rusqlite::Result<Option<Vec<u8>>> {
    Ok(blob_content(conn, user_id, id, |_| ByteRange::Full)?
        .filter(|(meta, _, _)| meta.here())
        .map(|(_, _, content)| content))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobDeletion {
    /// With the backends that had a copy: the caller's to delete there.
    Deleted(Vec<String>),
    NotFound,
    Referenced,
}

pub fn delete_blob(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
) -> rusqlite::Result<BlobDeletion> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = match blob_meta(&tx, user_id, id)? {
        None => BlobDeletion::NotFound,
        Some(_) if referenced(&tx, user_id, id)? => BlobDeletion::Referenced,
        Some(meta) => {
            tx.execute(
                "DELETE FROM blobs WHERE user_id = ?1 AND id = ?2",
                params![user_id, id.0],
            )?;
            BlobDeletion::Deleted(
                meta.copies
                    .iter()
                    .filter(|place| **place != Location::Local)
                    .map(|place| place.as_str().to_owned())
                    .collect(),
            )
        }
    };
    tx.commit()?;
    Ok(outcome)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlagWrite {
    Written(BlobMeta),
    NotFound,
    Referenced,
    /// Not offloadable can only be a blob with a copy in the database: this one needs one first.
    NotHere(BlobMeta),
}

fn referenced(conn: &Connection, user_id: &UserId, id: BlobId) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM refs WHERE user_id = ?1 AND blob_id = ?2)",
        params![user_id, id.0],
        |r| r.get(0),
    )
}

/// Sets whether the blob is offloadable. A blob a ref points to can't be, and one without a copy in the database
/// can't stop being (SPEC §7.1, §7.4).
pub fn set_offloadable(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    offloadable: bool,
) -> rusqlite::Result<FlagWrite> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = match blob_meta(&tx, user_id, id)? {
        None => FlagWrite::NotFound,
        Some(_) if offloadable && referenced(&tx, user_id, id)? => FlagWrite::Referenced,
        Some(meta) if !offloadable && !meta.here() => FlagWrite::NotHere(meta),
        Some(meta) => {
            tx.execute(
                "UPDATE blobs SET offloadable = ?3 WHERE user_id = ?1 AND id = ?2",
                params![user_id, id.0, offloadable],
            )?;
            FlagWrite::Written(BlobMeta {
                offloadable,
                ..meta
            })
        }
    };
    tx.commit()?;
    Ok(outcome)
}

/// Up to `limit + 1` blobs after `after`, by ID; the extra one tells the caller there is a next page.
pub fn list_blobs(
    conn: &Connection,
    user_id: &UserId,
    after: Option<BlobId>,
    limit: usize,
) -> rusqlite::Result<Vec<BlobMeta>> {
    let after: Vec<u8> = after.map(|a| a.0.to_vec()).unwrap_or_default();
    conn.prepare(&format!(
        "SELECT {BLOB_META} FROM blobs WHERE user_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3"
    ))?
    .query_map(params![user_id, after, limit as i64 + 1], blob_meta_row)?
    .collect()
}

// ---------------------------------------------------------------- copies (SPEC §7.4)

/// Every blob whose copies aren't where `targets` say they belong (`placement::plan`), with its owner.
pub fn unsettled_blobs(
    conn: &Connection,
    targets: &[Location],
) -> rusqlite::Result<Vec<(UserId, BlobMeta)>> {
    // Blobs that aren't offloadable, have a copy here and none elsewhere are where they belong: most of them, so
    // they are left out here rather than by the plan.
    let candidates = conn
        .prepare(&format!(
            "SELECT {BLOB_META}, blobs.user_id FROM blobs
             WHERE offloadable = 1 OR content IS NULL
                OR EXISTS (SELECT 1 FROM blob_copies c WHERE c.user_id = blobs.user_id AND c.blob_id = blobs.id)
             ORDER BY blobs.user_id, blobs.id"
        ))?
        .query_map([], |r| Ok((r.get(6)?, blob_meta_row(r)?)))?
        .collect::<rusqlite::Result<Vec<(UserId, BlobMeta)>>>()?;
    Ok(candidates
        .into_iter()
        .filter(|(_, meta)| !placement::plan(meta.offloadable, &meta.copies, targets).is_empty())
        .collect())
}

/// Records a copy of the blob in `backend`, which the caller has put there, if the blob still exists and is
/// offloadable. False otherwise, or if the copy was there already: then the object may be nobody's.
pub fn add_copy(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    backend: &BackendRecord,
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let added = tx.execute(
        "INSERT INTO blob_copies (user_id, blob_id, backend)
           SELECT user_id, id, ?3 FROM blobs WHERE user_id = ?1 AND id = ?2 AND offloadable = 1
         ON CONFLICT DO NOTHING",
        params![user_id, id.0, backend.name],
    )? == 1;
    if added {
        record_backend(&tx, backend)?;
    }
    tx.commit()?;
    Ok(added)
}

/// Gives the blob a copy in the database, if it has none; `unflag` also makes it not offloadable, in the same step.
/// False if it has one already, or is gone.
pub fn add_local(
    conn: &Connection,
    user_id: &UserId,
    id: BlobId,
    content: &[u8],
    unflag: bool,
) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE blobs SET content = ?3, offloadable = offloadable AND NOT ?4
         WHERE user_id = ?1 AND id = ?2 AND content IS NULL",
        params![user_id, id.0, content, unflag],
    )? == 1)
}

/// Drops the blob's copy in `place`, if `placement` still allows it with the copies the blob has now: never one it
/// belongs in, and only once it has a copy in all of those. → whether it did. A dropped backend copy's object is the
/// caller's to delete.
pub fn drop_copy(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    place: &Location,
    targets: &[Location],
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let allowed = blob_meta(&tx, user_id, id)?
        .is_some_and(|meta| placement::droppable(meta.offloadable, &meta.copies, targets, place));
    if allowed {
        match place {
            Location::Local => tx.execute(
                "UPDATE blobs SET content = NULL WHERE user_id = ?1 AND id = ?2",
                params![user_id, id.0],
            )?,
            Location::Backend(name) => tx.execute(
                "DELETE FROM blob_copies WHERE user_id = ?1 AND blob_id = ?2 AND backend = ?3",
                params![user_id, id.0, name],
            )?,
        };
    }
    tx.commit()?;
    Ok(allowed)
}

/// Forgets the blob's copy in backend `name`, found gone or damaged, if the blob has another copy: the pass then makes
/// it again. Its last copy stays, so it reads as lost. → whether it forgot it.
pub fn forget_copy(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    name: &str,
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let there = Location::Backend(name.to_owned());
    let forgotten = blob_meta(&tx, user_id, id)?
        .is_some_and(|meta| meta.copies.contains(&there) && meta.copies.len() > 1);
    if forgotten {
        tx.execute(
            "DELETE FROM blob_copies WHERE user_id = ?1 AND blob_id = ?2 AND backend = ?3",
            params![user_id, id.0, name],
        )?;
    }
    tx.commit()?;
    Ok(forgotten)
}

/// Forgets all of the blob's copies, found gone or damaged, if they are still `copies` and none is in the database: it
/// is lost, and an upload of it stores it anew (SPEC §7.1). → whether it did.
pub fn forget_lost(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    copies: &[Location],
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let lost =
        blob_meta(&tx, user_id, id)?.is_some_and(|meta| !meta.here() && meta.copies == copies);
    if lost {
        tx.execute(
            "DELETE FROM blob_copies WHERE user_id = ?1 AND blob_id = ?2",
            params![user_id, id.0],
        )?;
    }
    tx.commit()?;
    Ok(lost)
}

/// Every blob with a copy in backend `name`, with its size.
pub fn blobs_in(conn: &Connection, name: &str) -> rusqlite::Result<HashMap<(UserId, BlobId), u64>> {
    conn.prepare(
        "SELECT c.user_id, c.blob_id, blobs.size FROM blob_copies c
           JOIN blobs ON blobs.user_id = c.user_id AND blobs.id = c.blob_id
         WHERE c.backend = ?1",
    )?
    .query_map([name], |r| {
        let size = r.get::<_, i64>(2)?.try_into().unwrap_or(0);
        Ok(((r.get(0)?, BlobId(r.get(1)?)), size))
    })?
    .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forgetting {
    /// The rows of `copies` copies are gone, and the backend's record. `lost` had no other copy.
    Forgot {
        copies: u64,
        lost: Vec<(UserId, BlobId)>,
    },
    /// Nothing changed: these blobs have no copy anywhere else.
    WouldLose(Vec<(UserId, BlobId)>),
    /// No copy went there, and it isn't recorded: likely a typo.
    Unknown,
}

/// Forgets backend `name`, gone for good (SPEC §9): its copies' rows and its record. Unless `accept_loss`, nothing
/// changes if a blob's only copy is there.
pub fn forget_backend(
    conn: &mut Connection,
    name: &str,
    accept_loss: bool,
) -> rusqlite::Result<Forgetting> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let only_there = tx
        .prepare(
            "SELECT c.user_id, c.blob_id FROM blob_copies c
               JOIN blobs ON blobs.user_id = c.user_id AND blobs.id = c.blob_id
             WHERE c.backend = ?1 AND blobs.content IS NULL
               AND NOT EXISTS (SELECT 1 FROM blob_copies o
                               WHERE o.user_id = c.user_id AND o.blob_id = c.blob_id AND o.backend <> ?1)
             ORDER BY c.user_id, c.blob_id",
        )?
        .query_map([name], |r| Ok((r.get(0)?, BlobId(r.get(1)?))))?
        .collect::<rusqlite::Result<Vec<(UserId, BlobId)>>>()?;
    if !only_there.is_empty() && !accept_loss {
        return Ok(Forgetting::WouldLose(only_there));
    }
    let copies = tx.execute("DELETE FROM blob_copies WHERE backend = ?1", [name])?;
    let recorded = tx.execute("DELETE FROM backends WHERE name = ?1", [name])? == 1;
    if copies == 0 && !recorded {
        return Ok(Forgetting::Unknown);
    }
    tx.commit()?;
    Ok(Forgetting::Forgot {
        copies: copies as u64,
        lost: only_there,
    })
}

/// The copies in one place, and their bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    pub location: Location,
    pub blobs: u64,
    pub bytes: u64,
}

/// How many copies are where: the database first, then the backends with any, by name.
pub fn usage(conn: &Connection) -> rusqlite::Result<Vec<Usage>> {
    let mut usage: Vec<Usage> = conn
        .prepare(
            "SELECT 'local', count(*), coalesce(sum(size), 0) FROM blobs WHERE content IS NOT NULL
             UNION ALL
             SELECT c.backend, count(*), coalesce(sum(blobs.size), 0) FROM blob_copies c
               JOIN blobs ON blobs.user_id = c.user_id AND blobs.id = c.blob_id
             GROUP BY c.backend",
        )?
        .query_map([], |r| {
            Ok(Usage {
                location: Location::named(&r.get::<_, String>(0)?),
                blobs: r.get::<_, i64>(1)?.try_into().unwrap_or(0),
                bytes: r.get::<_, i64>(2)?.try_into().unwrap_or(0),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    usage.sort_by(|a, b| a.location.cmp(&b.location));
    Ok(usage)
}

/// What `backend storage` shows (SPEC §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Storage {
    /// The copies in each place.
    pub places: Vec<Usage>,
    /// Offloadable blobs with any copy, by how many they have, fewest first: (copies, blobs).
    pub by_copies: Vec<(u64, u64)>,
    /// The blobs with a copy, but none in the database, and their bytes: what bringing all of them in would take.
    pub elsewhere: (u64, u64),
    /// The blobs with no copy left, offloadable or not, and their bytes.
    pub lost: (u64, u64),
}

pub fn storage(conn: &Connection) -> rusqlite::Result<Storage> {
    let count = |n: i64| n.try_into().unwrap_or(0);
    let by_copies = conn
        .prepare(
            "SELECT n, count(*) FROM (
               SELECT (content IS NOT NULL)
                      + (SELECT count(*) FROM blob_copies c WHERE c.user_id = blobs.user_id AND c.blob_id = blobs.id)
                      AS n
               FROM blobs WHERE offloadable = 1)
             WHERE n > 0 GROUP BY n ORDER BY n",
        )?
        .query_map([], |r| Ok((count(r.get(0)?), count(r.get(1)?))))?
        .collect::<rusqlite::Result<_>>()?;
    let without_a_copy_here = |copies: &str| {
        conn.query_row(
            &format!(
                "SELECT count(*), coalesce(sum(size), 0) FROM blobs WHERE content IS NULL
                   AND {copies} (SELECT 1 FROM blob_copies c WHERE c.user_id = blobs.user_id AND c.blob_id = blobs.id)"
            ),
            [],
            |r| Ok((count(r.get(0)?), count(r.get(1)?))),
        )
    };
    Ok(Storage {
        places: usage(conn)?,
        by_copies,
        elsewhere: without_a_copy_here("EXISTS")?,
        lost: without_a_copy_here("NOT EXISTS")?,
    })
}

/// The backends copies have gone to, as the database recorded them.
pub fn recorded_backends(conn: &Connection) -> rusqlite::Result<Vec<BackendRecord>> {
    conn.prepare("SELECT name, type, identity FROM backends ORDER BY name")?
        .query_map([], |r| {
            Ok(BackendRecord {
                name: r.get(0)?,
                kind: r.get(1)?,
                identity: r.get(2)?,
            })
        })?
        .collect()
}

fn record_backend(conn: &Connection, backend: &BackendRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO backends (name, type, identity) VALUES (?1, ?2, ?3)
         ON CONFLICT (name) DO UPDATE SET type = excluded.type, identity = excluded.identity",
        params![backend.name, backend.kind, backend.identity],
    )?;
    Ok(())
}

// ---------------------------------------------------------------- refs

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefRow {
    pub name: String,
    pub blob: BlobId,
    pub updated_at: i64,
}

fn ref_row(row: &Row) -> rusqlite::Result<RefRow> {
    Ok(RefRow {
        name: row.get(0)?,
        blob: BlobId(row.get(1)?),
        updated_at: row.get(2)?,
    })
}

pub fn get_ref(
    conn: &Connection,
    user_id: &UserId,
    name: &str,
) -> rusqlite::Result<Option<RefRow>> {
    conn.query_row(
        "SELECT name, blob_id, updated_at FROM refs WHERE user_id = ?1 AND name = ?2",
        params![user_id, name],
        ref_row,
    )
    .optional()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefWrite {
    Created(RefRow),
    Updated(RefRow),
    PreconditionFailed(Option<BlobId>),
    BlobNotFound,
    BlobOffloadable,
}

/// Compare-and-swap on one ref, under a write lock (SPEC §7.2).
pub fn put_ref(
    conn: &mut Connection,
    user_id: &UserId,
    name: &str,
    blob: BlobId,
    precondition: Precondition,
    now: i64,
) -> rusqlite::Result<RefWrite> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_ref(&tx, user_id, name)?.map(|r| r.blob);
    let outcome = match blob_meta(&tx, user_id, blob)? {
        _ if !precondition_holds(precondition, current) => RefWrite::PreconditionFailed(current),
        None => RefWrite::BlobNotFound,
        // Not offloadable but without a copy here is only left behind by an older binary; the pass brings it home.
        Some(target) if target.offloadable || !target.here() => RefWrite::BlobOffloadable,
        Some(_) => {
            tx.execute(
                "INSERT INTO refs (user_id, name, blob_id, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (user_id, name) DO UPDATE SET blob_id = excluded.blob_id, updated_at = excluded.updated_at",
                params![user_id, name, blob.0, now],
            )?;
            let row = RefRow {
                name: name.to_owned(),
                blob,
                updated_at: now,
            };
            if current.is_some() {
                RefWrite::Updated(row)
            } else {
                RefWrite::Created(row)
            }
        }
    };
    tx.commit()?;
    Ok(outcome)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefDeletion {
    Deleted,
    NotFound,
    PreconditionFailed(Option<BlobId>),
}

pub fn delete_ref(
    conn: &mut Connection,
    user_id: &UserId,
    name: &str,
    precondition: Precondition,
) -> rusqlite::Result<RefDeletion> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_ref(&tx, user_id, name)?.map(|r| r.blob);
    let outcome = match (precondition, current) {
        (Precondition::None, None) => RefDeletion::NotFound,
        _ if !precondition_holds(precondition, current) => RefDeletion::PreconditionFailed(current),
        _ => {
            tx.execute(
                "DELETE FROM refs WHERE user_id = ?1 AND name = ?2",
                params![user_id, name],
            )?;
            RefDeletion::Deleted
        }
    };
    tx.commit()?;
    Ok(outcome)
}

/// Up to `limit + 1` refs starting with `prefix`, after `after`, by name.
pub fn list_refs(
    conn: &Connection,
    user_id: &UserId,
    prefix: &str,
    after: &str,
    limit: usize,
) -> rusqlite::Result<Vec<RefRow>> {
    conn.prepare(
        "SELECT name, blob_id, updated_at FROM refs
         WHERE user_id = ?1 AND substr(name, 1, length(?2)) = ?2 AND name > ?3
         ORDER BY name LIMIT ?4",
    )?
    .query_map(params![user_id, prefix, after, limit as i64 + 1], ref_row)?
    .collect()
}
