//! Opening the database and migrating it (SPEC §5). Migrations are plain SQL, tracked with `user_version`.

use std::path::Path;

use rusqlite::Connection;

/// Index = version reached after applying it. Append only; never edit an applied migration.
const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE users (
  id          BLOB PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE passkeys (
  id             BLOB PRIMARY KEY,
  user_id        BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rp_id          TEXT NOT NULL,
  name           TEXT NOT NULL,
  static_state   BLOB NOT NULL,
  dynamic_state  BLOB NOT NULL,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER
) STRICT;
CREATE INDEX passkeys_by_user ON passkeys(user_id);

CREATE TABLE sessions (
  token_hash  BLOB PRIMARY KEY,
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  passkey_id  BLOB REFERENCES passkeys(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_by_expiry ON sessions(expires_at);
CREATE INDEX sessions_by_passkey ON sessions(passkey_id);

CREATE TABLE setup_tokens (
  token_hash  BLOB PRIMARY KEY,
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX setup_tokens_by_expiry ON setup_tokens(expires_at);

CREATE TABLE ceremonies (
  challenge   BLOB PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('login', 'register')),
  user_id     BLOB REFERENCES users(id) ON DELETE CASCADE,
  state       BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX ceremonies_by_expiry ON ceremonies(expires_at);

CREATE TABLE blobs (
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  id          BLOB NOT NULL,
  size        INTEGER NOT NULL,
  content     BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, id)
) STRICT;

CREATE TABLE refs (
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  blob_id     BLOB NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, name),
  -- NO ACTION (not RESTRICT): checked at the end of the statement, so deleting a user cascades cleanly.
  FOREIGN KEY (user_id, blob_id) REFERENCES blobs(user_id, id)
) STRICT;
CREATE INDEX refs_by_blob ON refs(user_id, blob_id);
"#];

/// A connection with the per-connection settings every caller needs. Foreign keys in particular are off
/// by default in SQLite and must be enabled on each connection.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;")?;
    Ok(conn)
}

/// Opens the database, switches it to WAL and applies pending migrations. Run once per process start.
pub fn open_and_migrate(path: &Path) -> anyhow::Result<Connection> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut conn = open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let version = usize::try_from(version).unwrap_or(0);
    if version > MIGRATIONS.len() {
        anyhow::bail!(
            "database schema version {version} is newer than this binary ({})",
            MIGRATIONS.len()
        );
    }
    for (index, sql) in MIGRATIONS.iter().enumerate().skip(version) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", i64::try_from(index + 1)?)?;
        tx.commit()?;
    }
    Ok(conn)
}
