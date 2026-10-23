//! Opening the database and migrating it (SPEC §5.2). Migrations are plain SQL; `user_version` holds the
//! schema version as `major.minor`.

use std::path::Path;

use anyhow::Context as _;
use rusqlite::Connection;

/// Bound on both parts of a version: `encode` keeps the minor in the low three decimal digits.
const COMPONENT_LIMIT: i64 = 1000;

/// A schema version (SPEC §5.2). A minor version only adds what an older binary of the same major can ignore (see
/// `MIGRATIONS`), so that binary still starts and works against the database. A new major is one it can't work
/// against, and it refuses to start. Running an older binary is routine: the host's nightly upgrade replaces a
/// generation switched to by hand with the one the pipeline last delivered.
///
/// Ordered by major, then minor: 1.9 < 1.10 < 2.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: i64,
    pub minor: i64,
}

impl Version {
    pub const fn new(major: i64, minor: i64) -> Self {
        assert!(
            major >= 0 && major < COMPONENT_LIMIT,
            "major version must be 0..1000"
        );
        assert!(
            minor >= 0 && minor < COMPONENT_LIMIT,
            "minor version must be 0..1000"
        );
        Self { major, minor }
    }

    /// What goes in `user_version`: `major * 1000 + minor`, but `N.0` as the bare `N`. Databases from before
    /// versions had a minor hold the bare `N` already, so they are left as they are.
    pub const fn encode(self) -> i64 {
        if self.minor == 0 {
            self.major
        } else {
            self.major * COMPONENT_LIMIT + self.minor
        }
    }

    /// The version a stored `user_version` stands for. Total: the value on disk isn't under our control.
    pub const fn decode(raw: i64) -> Self {
        if raw < COMPONENT_LIMIT {
            Self {
                major: raw,
                minor: 0,
            }
        } else {
            Self {
                major: raw / COMPONENT_LIMIT,
                minor: raw % COMPONENT_LIMIT,
            }
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The schema this binary writes.
pub const SCHEMA_VERSION: Version = Version::new(1, 1);

/// A new major stops every older binary from starting, so it needs a plan, not just an edit: deliver a binary that
/// no longer depends on what the major changes first, through the pipeline, then the major. Changing this line is
/// that decision.
const _: () = assert!(
    SCHEMA_VERSION.major == 1,
    "a major bump stops every older binary from starting; see SPEC §5.2"
);

struct Migration {
    version: Version,
    sql: &'static str,
}

/// In ascending order, the last one at `SCHEMA_VERSION`. Append only; never edit an applied migration.
///
/// A minor migration may only:
/// - `CREATE TABLE` or `CREATE INDEX`;
/// - `ALTER TABLE … ADD COLUMN` that is nullable or has a default, so an older binary's `INSERT`, which doesn't
///   name the column, still works;
/// - rebuild a table to change only how it is stored, keeping every column and refusing exactly the rows it
///   refused before.
///
/// Everything else is a major: dropping or renaming a table or column, changing a column's type, a constraint an
/// older binary's writes could break, or a new meaning for existing data. The test is whether the previous binary
/// would still behave correctly against the database.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: Version::new(1, 0),
        sql: r#"
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
"#,
    },
    // Blobs the client lets the server move out of the database (SPEC §7.1). An older binary uploads blobs that
    // aren't offloadable, and doesn't refuse refs to offloadable ones: nothing is offloaded yet, so that's harmless.
    Migration {
        version: Version::new(1, 1),
        sql: "ALTER TABLE blobs ADD COLUMN offloadable INTEGER NOT NULL DEFAULT 0 CHECK (offloadable IN (0, 1));",
    },
];

/// A connection with the per-connection settings every caller needs. Foreign keys in particular are off
/// by default in SQLite and must be enabled on each connection.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;")?;
    Ok(conn)
}

/// Opens the database, switches it to WAL and migrates it. Run once per process start.
pub fn open_and_migrate(path: &Path) -> anyhow::Result<Connection> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut conn = open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&mut conn)?;
    Ok(conn)
}

/// Brings an older schema to `SCHEMA_VERSION` in one transaction. A newer minor is left as it is, with a warning; a
/// newer major is refused. A database already at `SCHEMA_VERSION` isn't written to.
fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let current = Version::decode(conn.pragma_query_value(None, "user_version", |r| r.get(0))?);
    if current.major > SCHEMA_VERSION.major {
        anyhow::bail!(
            "database schema version {current} is newer than this binary's ({SCHEMA_VERSION}) by a major version"
        );
    }
    if current > SCHEMA_VERSION {
        tracing::warn!(
            "database schema version {current} is newer than this binary's ({SCHEMA_VERSION}); continuing, since a minor version only adds"
        );
        return Ok(());
    }
    if current == SCHEMA_VERSION {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
        tx.execute_batch(migration.sql)
            .with_context(|| format!("migrating the database to {}", migration.version))?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION.encode())?;
    tx.commit()?;
    tracing::info!("database schema migrated from {current} to {SCHEMA_VERSION}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(conn: &Connection) -> i64 {
        conn.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn versions_are_stored_as_one_integer() {
        assert_eq!(
            Version::new(1, 0).encode(),
            1,
            "as before versions had a minor"
        );
        assert_eq!(Version::new(1, 1).encode(), 1001);
        assert_eq!(Version::new(12, 345).encode(), 12_345);
        for version in [
            Version::new(0, 0),
            Version::new(1, 0),
            Version::new(1, 1),
            Version::new(999, 999),
        ] {
            assert_eq!(Version::decode(version.encode()), version);
        }
        assert_eq!(Version::decode(1000), Version::new(1, 0));
        assert!(Version::new(1, 9) < Version::new(1, 10));
        assert!(Version::new(1, 10) < Version::new(2, 0));
    }

    #[test]
    fn migrations_are_in_order_and_end_at_the_schema_version() {
        assert!(
            MIGRATIONS
                .windows(2)
                .all(|pair| pair[0].version < pair[1].version)
        );
        assert_eq!(MIGRATIONS.last().unwrap().version, SCHEMA_VERSION);
    }

    #[test]
    fn a_new_database_is_migrated_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data/backend.sqlite3");
        open_and_migrate(&path).unwrap();
        let conn = open_and_migrate(&path).unwrap();
        assert_eq!(stored(&conn), SCHEMA_VERSION.encode());
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "wal");
        let foreign_keys: i64 = conn
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
    }

    /// The database on the host is at 1, written before versions had a minor.
    #[test]
    fn a_1_0_database_gets_offloadable_blobs_and_still_takes_a_1_0_binarys_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backend.sqlite3");
        let conn = open(&path).unwrap();
        conn.execute_batch(MIGRATIONS[0].sql).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        let insert = "INSERT INTO blobs (user_id, id, size, content, created_at) VALUES (x'01', ?1, 1, x'00', 0)";
        conn.execute_batch(
            "INSERT INTO users (id, username, created_at) VALUES (x'01', 'alice', 0)",
        )
        .unwrap();
        conn.execute(insert, [b"before".to_vec()]).unwrap();
        drop(conn);

        let conn = open_and_migrate(&path).unwrap();
        assert_eq!(stored(&conn), 1001);
        conn.execute(insert, [b"after".to_vec()]).unwrap();
        let flags: Vec<i64> = conn
            .prepare("SELECT offloadable FROM blobs ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(flags, [0, 0]);
    }

    #[test]
    fn a_newer_minor_is_used_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backend.sqlite3");
        let conn = open_and_migrate(&path).unwrap();
        let newer = Version::new(SCHEMA_VERSION.major, SCHEMA_VERSION.minor + 1).encode();
        conn.pragma_update(None, "user_version", newer).unwrap();
        let conn = open_and_migrate(&path).unwrap();
        assert_eq!(
            stored(&conn),
            newer,
            "not written down to this binary's version"
        );
    }

    #[test]
    fn a_newer_major_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backend.sqlite3");
        let conn = open_and_migrate(&path).unwrap();
        let newer = Version::new(SCHEMA_VERSION.major + 1, 0).encode();
        conn.pragma_update(None, "user_version", newer).unwrap();
        let error = open_and_migrate(&path).unwrap_err().to_string();
        assert!(error.contains("by a major version"), "{error}");
        assert_eq!(stored(&conn), newer);
    }
}
