//! Persistence (SPEC §5, §7): plain functions over a connection. Callers pass `now`; nothing here reads
//! the clock. Outcomes the API distinguishes are returned as enums; `Err` is reserved for SQLite failures.

use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};

use crate::domain::{BlobId, Precondition, is_live, precondition_holds};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    pub id: BlobId,
    pub size: u64,
    pub created_at: i64,
}

fn blob_meta_row(row: &Row) -> rusqlite::Result<BlobMeta> {
    Ok(BlobMeta {
        id: BlobId(row.get(0)?),
        size: row.get::<_, i64>(1)?.try_into().unwrap_or(0),
        created_at: row.get(2)?,
    })
}

/// Stores a blob unless it already exists. Returns whether it was new, and its metadata.
pub fn put_blob(
    conn: &Connection,
    user_id: &UserId,
    id: BlobId,
    content: &[u8],
    now: i64,
) -> rusqlite::Result<(bool, BlobMeta)> {
    let inserted = conn.execute(
        "INSERT INTO blobs (user_id, id, size, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
        params![user_id, id.0, i64::try_from(content.len()).unwrap_or(i64::MAX), content, now],
    )?;
    let meta = blob_meta(conn, user_id, id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    Ok((inserted == 1, meta))
}

pub fn blob_meta(
    conn: &Connection,
    user_id: &UserId,
    id: BlobId,
) -> rusqlite::Result<Option<BlobMeta>> {
    conn.query_row(
        "SELECT id, size, created_at FROM blobs WHERE user_id = ?1 AND id = ?2",
        params![user_id, id.0],
        blob_meta_row,
    )
    .optional()
}

pub fn blob_content(
    conn: &Connection,
    user_id: &UserId,
    id: BlobId,
) -> rusqlite::Result<Option<(BlobMeta, Vec<u8>)>> {
    conn.query_row(
        "SELECT id, size, created_at, content FROM blobs WHERE user_id = ?1 AND id = ?2",
        params![user_id, id.0],
        |r| Ok((blob_meta_row(r)?, r.get(3)?)),
    )
    .optional()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobDeletion {
    Deleted,
    NotFound,
    Referenced,
}

pub fn delete_blob(
    conn: &mut Connection,
    user_id: &UserId,
    id: BlobId,
) -> rusqlite::Result<BlobDeletion> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let referenced: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM refs WHERE user_id = ?1 AND blob_id = ?2)",
        params![user_id, id.0],
        |r| r.get(0),
    )?;
    let outcome = if referenced {
        BlobDeletion::Referenced
    } else if tx.execute(
        "DELETE FROM blobs WHERE user_id = ?1 AND id = ?2",
        params![user_id, id.0],
    )? == 1
    {
        BlobDeletion::Deleted
    } else {
        BlobDeletion::NotFound
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
    conn.prepare("SELECT id, size, created_at FROM blobs WHERE user_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3")?
        .query_map(params![user_id, after, limit as i64 + 1], blob_meta_row)?
        .collect()
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
    let outcome = if !precondition_holds(precondition, current) {
        RefWrite::PreconditionFailed(current)
    } else if blob_meta(&tx, user_id, blob)?.is_none() {
        RefWrite::BlobNotFound
    } else {
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
