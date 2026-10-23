//! Persistence (SPEC §5, §7): plain functions over a connection. Callers pass `now`; nothing here reads
//! the clock. Outcomes the API distinguishes are returned as enums; `Err` is reserved for SQLite failures.

use std::collections::HashSet;

use rusqlite::{Connection, MAIN_DB, OptionalExtension, Row, TransactionBehavior, params};

use crate::config::Target;
use crate::domain::{BlobId, ByteRange, Precondition, is_live, precondition_holds};

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

/// Where a blob's content is (SPEC §7.4). A blob in S3 keeps its row, with empty `content`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored {
    Local,
    S3,
}

impl Stored {
    fn of(location: &str) -> Self {
        if location == "s3" {
            Self::S3
        } else {
            Self::Local
        }
    }
}

/// The S3 location blobs were moved to: none of it secret. The database keeps it so a server pointed at another
/// bucket doesn't take its blobs for lost (SPEC §7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Location {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    pub id: BlobId,
    pub size: u64,
    pub created_at: i64,
    /// The client allows the server to move the content out of the database (SPEC §7.1).
    pub offloadable: bool,
    pub stored: Stored,
}

const BLOB_META: &str = "id, size, created_at, offloadable, location";

fn blob_meta_row(row: &Row) -> rusqlite::Result<BlobMeta> {
    Ok(BlobMeta {
        id: BlobId(row.get(0)?),
        size: row.get::<_, i64>(1)?.try_into().unwrap_or(0),
        created_at: row.get(2)?,
        offloadable: row.get(3)?,
        stored: Stored::of(&row.get::<_, String>(4)?),
    })
}

fn sql_size(size: usize) -> i64 {
    i64::try_from(size).unwrap_or(i64::MAX)
}

/// Stores a blob unless it already exists; an existing one keeps its flag and its place. With `in_s3`, the content
/// is already there and only the row is written. Returns whether it was new, and its metadata.
pub fn put_blob(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    content: &[u8],
    offloadable: bool,
    in_s3: Option<&S3Location>,
    now: i64,
) -> rusqlite::Result<(bool, BlobMeta)> {
    let tx = conn.transaction()?;
    let (stored, location) = match in_s3 {
        Some(_) => (&[][..], "s3"),
        None => (content, "local"),
    };
    let inserted = tx.execute(
        "INSERT INTO blobs (user_id, id, size, content, created_at, offloadable, location)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT DO NOTHING",
        params![
            user_id,
            id.0,
            sql_size(content.len()),
            stored,
            now,
            offloadable,
            location
        ],
    )?;
    if inserted == 1
        && let Some(s3) = in_s3
    {
        record_s3_location(&tx, s3)?;
    }
    let meta = blob_meta(&tx, user_id, id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    tx.commit()?;
    Ok((inserted == 1, meta))
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
/// unsatisfiable or the blob is in S3. The bytes come through incremental BLOB I/O, so SQLite reads only the pages
/// up to the range's end and only the range is held in memory.
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
            |r| Ok((blob_meta_row(r)?, r.get::<_, i64>(5)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let range = pick(meta.size);
    let content = match (meta.stored, range) {
        (Stored::S3, _) | (_, ByteRange::Unsatisfiable) => Vec::new(),
        (Stored::Local, ByteRange::Full) => read_blob(&tx, rowid, 0, meta.size)?,
        (Stored::Local, ByteRange::Partial { start, end }) => {
            read_blob(&tx, rowid, start, end - start + 1)?
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobDeletion {
    /// Its content was where it says; one in S3 is the caller's to delete there.
    Deleted(Stored),
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
            BlobDeletion::Deleted(meta.stored)
        }
    };
    tx.commit()?;
    Ok(outcome)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagWrite {
    Written(BlobMeta),
    NotFound,
    Referenced,
    /// Not offloadable can only be a blob in the database: this one has to come back from S3 first.
    InS3,
}

fn referenced(conn: &Connection, user_id: &UserId, id: BlobId) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM refs WHERE user_id = ?1 AND blob_id = ?2)",
        params![user_id, id.0],
        |r| r.get(0),
    )
}

/// Sets whether the blob is offloadable. A blob a ref points to can't be, and one in S3 can't stop being
/// (SPEC §7.1, §7.4).
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
        Some(meta) if !offloadable && meta.stored == Stored::S3 => FlagWrite::InS3,
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

// ---------------------------------------------------------------- moving blobs (SPEC §7.4)

/// A blob that isn't where it belongs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Misplaced {
    pub user_id: UserId,
    pub id: BlobId,
    pub size: u64,
    pub to: Stored,
}

/// Every blob that isn't where it belongs: offloadable blobs in S3 if that is the target, everything else here.
pub fn misplaced_blobs(conn: &Connection, target: Target) -> rusqlite::Result<Vec<Misplaced>> {
    let to_s3 = target == Target::S3;
    conn.prepare(
        "SELECT user_id, id, size, location FROM blobs
         WHERE (?1 AND location = 'local' AND offloadable = 1) OR (location = 's3' AND (NOT ?1 OR offloadable = 0))
         ORDER BY user_id, id",
    )?
    .query_map(params![to_s3], |r| {
        Ok(Misplaced {
            user_id: r.get(0)?,
            id: BlobId(r.get(1)?),
            size: r.get::<_, i64>(2)?.try_into().unwrap_or(0),
            to: match Stored::of(&r.get::<_, String>(3)?) {
                Stored::Local => Stored::S3,
                Stored::S3 => Stored::Local,
            },
        })
    })?
    .collect()
}

/// The content of a blob that may go to S3: one in the database, and offloadable. None for any other.
pub fn offloadable_content(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
) -> rusqlite::Result<Option<Vec<u8>>> {
    match blob_content(conn, user_id, id, |_| ByteRange::Full)? {
        Some((meta, _, content)) if meta.offloadable && meta.stored == Stored::Local => {
            Ok(Some(content))
        }
        _ => Ok(None),
    }
}

/// Records that the blob's content is in S3 and drops it here, if the blob is still in the database and
/// offloadable; false otherwise, and then the object the caller put there is nobody's.
pub fn mark_in_s3(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    s3: &S3Location,
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let moved = tx.execute(
        "UPDATE blobs SET location = 's3', content = x'' WHERE user_id = ?1 AND id = ?2 AND location = 'local' AND offloadable = 1",
        params![user_id, id.0],
    )? == 1;
    if moved {
        record_s3_location(&tx, s3)?;
    }
    tx.commit()?;
    Ok(moved)
}

/// Puts a blob's content back in the database, if it is still in S3; `unflag` also makes it not offloadable, in the
/// same step. False if the blob isn't in S3 (any more).
pub fn mark_local(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
    content: &[u8],
    unflag: bool,
) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE blobs SET location = 'local', content = ?3, offloadable = offloadable AND NOT ?4
         WHERE user_id = ?1 AND id = ?2 AND location = 's3'",
        params![user_id, id.0, content, unflag],
    )? == 1)
}

/// Every blob whose content is in S3.
pub fn blobs_in_s3(conn: &Connection) -> rusqlite::Result<HashSet<(UserId, BlobId)>> {
    conn.prepare("SELECT user_id, id FROM blobs WHERE location = 's3'")?
        .query_map([], |r| Ok((r.get(0)?, BlobId(r.get(1)?))))?
        .collect()
}

/// How many blobs are in S3, and the location they were moved to.
pub fn s3_usage(conn: &Connection) -> rusqlite::Result<(u64, Option<S3Location>)> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM blobs WHERE location = 's3'",
        [],
        |r| r.get(0),
    )?;
    let location = conn
        .query_row(
            "SELECT endpoint, bucket, prefix FROM s3_location",
            [],
            |r| {
                Ok(S3Location {
                    endpoint: r.get(0)?,
                    bucket: r.get(1)?,
                    prefix: r.get(2)?,
                })
            },
        )
        .optional()?;
    Ok((count.try_into().unwrap_or(0), location))
}

fn record_s3_location(conn: &Connection, s3: &S3Location) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO s3_location (id, endpoint, bucket, prefix) VALUES (1, ?1, ?2, ?3)
         ON CONFLICT (id) DO UPDATE SET endpoint = excluded.endpoint, bucket = excluded.bucket, prefix = excluded.prefix",
        params![s3.endpoint, s3.bucket, s3.prefix],
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
        // Not offloadable but in S3 is only left behind by an older binary (SPEC §5.2); it comes back soon.
        Some(target) if target.offloadable || target.stored == Stored::S3 => {
            RefWrite::BlobOffloadable
        }
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
