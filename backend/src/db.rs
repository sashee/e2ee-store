//! Opening the database and migrating it (SPEC §5.2). Migrations are plain SQL; `user_version` holds the
//! schema version as `major.minor`.

use std::path::Path;

use anyhow::Context as _;
use rusqlite::{Connection, TransactionBehavior};

use crate::disk;

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
pub const SCHEMA_VERSION: Version = Version::new(1, 3);

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
    /// Copies a table, so it needs room for a second copy while it runs.
    rebuilds: bool,
}

/// In ascending order, the last one at `SCHEMA_VERSION`. Append only; never edit an applied migration.
///
/// A minor migration may only:
/// - `CREATE TABLE` or `CREATE INDEX`;
/// - `ALTER TABLE … ADD COLUMN` that is nullable or has a default, so an older binary's `INSERT`, which doesn't
///   name the column, still works;
/// - rebuild a table to change only how it is stored, keeping every column and refusing exactly the rows it
///   refused before; or to relax a constraint only a newer configuration's data needs relaxed (1.3).
///
/// Everything else is a major: dropping or renaming a table or column, changing a column's type, a constraint an
/// older binary's writes could break, or a new meaning for existing data. The test is whether the previous binary
/// would still behave correctly against the database. One exception: data that only a newer binary's configuration
/// creates may make an older binary fail loudly, never quietly wrong (1.2's blobs in S3).
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
        rebuilds: false,
    },
    // Blobs the client lets the server move out of the database (SPEC §7.1). An older binary uploads blobs that
    // aren't offloadable, and doesn't refuse refs to offloadable ones: nothing is offloaded yet, so that's harmless.
    Migration {
        version: Version::new(1, 1),
        sql: "ALTER TABLE blobs ADD COLUMN offloadable INTEGER NOT NULL DEFAULT 0 CHECK (offloadable IN (0, 1));",
        rebuilds: false,
    },
    // Offloadable blobs in S3 (SPEC §7.4): where each blob's content is, and which bucket they went to. Only a
    // server configured for S3 moves blobs there. An older binary answers 500 for those, as it reads past their
    // empty content, and leaves their objects behind when it deletes them, for the sweep.
    Migration {
        version: Version::new(1, 2),
        sql: r#"
ALTER TABLE blobs ADD COLUMN location TEXT NOT NULL DEFAULT 'local' CHECK (location IN ('local', 's3'));
CREATE INDEX blobs_by_location ON blobs(location, offloadable);

CREATE TABLE s3_location (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  endpoint  TEXT NOT NULL,
  bucket    TEXT NOT NULL,
  prefix    TEXT NOT NULL
) STRICT;
"#,
        rebuilds: false,
    },
    // Named backends (SPEC §7.4): `location` holds "local" or a backend's name, so `blobs` loses its CHECK of
    // ('local', 's3'), which only a rebuild can drop. The same columns, with `content` last: SQLite reaches a column
    // stored after a large blob by stepping through the blob's overflow pages, and 1.1 and 1.2 had added
    // `offloadable` and `location` there, which every lookup and every pass read. An older binary names every column,
    // so it can't tell. It does take a blob in a backend of another name for one in the database, and answers 500
    // for it, reading past its empty content: data only a newer configuration makes.
    //
    // The new table is renamed to `blobs`, never the old one away: renaming `blobs` would take `refs`' foreign key
    // with it. `migrate` turns foreign keys off around this, as dropping `blobs` would otherwise trip it.
    //
    // `backends` records each backend blobs went to; S3's location from 1.2 becomes the backend "s3", which blobs in
    // S3 already name. `s3_location` stays: 1.2 binaries read it at startup.
    Migration {
        version: Version::new(1, 3),
        sql: r#"
CREATE TABLE blobs_new (
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  id          BLOB NOT NULL,
  size        INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  offloadable INTEGER NOT NULL DEFAULT 0 CHECK (offloadable IN (0, 1)),
  location    TEXT NOT NULL DEFAULT 'local' CHECK (location <> ''),
  content     BLOB NOT NULL,
  PRIMARY KEY (user_id, id)
) STRICT;
INSERT INTO blobs_new (user_id, id, size, content, created_at, offloadable, location)
  SELECT user_id, id, size, content, created_at, offloadable, location FROM blobs;
DROP TABLE blobs;
ALTER TABLE blobs_new RENAME TO blobs;
CREATE INDEX blobs_by_location ON blobs(location, offloadable);

CREATE TABLE backends (
  name      TEXT PRIMARY KEY,
  type      TEXT NOT NULL,
  identity  TEXT NOT NULL
) STRICT;
INSERT INTO backends (name, type, identity)
  SELECT 's3', 's3', json_object('bucket', bucket, 'endpoint', endpoint, 'prefix', prefix) FROM s3_location;
"#,
        rebuilds: true,
    },
];

/// How long a statement waits for another connection's lock.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A connection with the per-connection settings every caller needs. Foreign keys in particular are off
/// by default in SQLite and must be enabled on each connection.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;")?;
    Ok(conn)
}

/// Opens the database, switches it to WAL and migrates it. Run once per process start.
pub fn open_and_migrate(path: &Path) -> anyhow::Result<Connection> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut conn = open(path)?;
    use_wal(&conn)?;
    // Off around the migration, as a rebuild drops a table others point to; outside its transaction, as SQLite
    // ignores the pragma inside one. `foreign_key_check` stands in for it.
    conn.pragma_update(None, "foreign_keys", false)?;
    let migrated = migrate(&mut conn, path);
    conn.pragma_update(None, "foreign_keys", true)?;
    migrated?;
    Ok(conn)
}

/// Switches the database to WAL. A new one starts in rollback-journal mode, and there two processes switching at
/// once could each wait for the other: SQLite answers "busy" right away instead of waiting out the busy timeout. So
/// this tries again, for as long as that timeout.
fn use_wal(conn: &Connection) -> rusqlite::Result<()> {
    let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
    loop {
        match conn.pragma_update(None, "journal_mode", "WAL") {
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            done => return done,
        }
    }
}

/// Brings an older schema to `SCHEMA_VERSION` in one transaction. A newer minor is left as it is, with a warning; a
/// newer major is refused. A database already at `SCHEMA_VERSION` isn't written to.
fn migrate(conn: &mut Connection, path: &Path) -> anyhow::Result<()> {
    // The write lock before the version: a server and an admin command starting together then migrate once.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = Version::decode(tx.pragma_query_value(None, "user_version", |r| r.get(0))?);
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
    let pending: Vec<&Migration> = MIGRATIONS.iter().filter(|m| m.version > current).collect();
    if pending.iter().any(|m| m.rebuilds) {
        room_to_rebuild(path)?;
    }
    for migration in pending {
        tx.execute_batch(migration.sql)
            .with_context(|| format!("migrating the database to {}", migration.version))?;
    }
    let dangling: i64 = tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
        r.get(0)
    })?;
    if dangling > 0 {
        anyhow::bail!("migrating would leave {dangling} rows pointing at rows that don't exist");
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION.encode())?;
    tx.commit()?;
    tracing::info!("database schema migrated from {current} to {SCHEMA_VERSION}");
    Ok(())
}

/// A rebuild holds a second copy of the table while it runs, first in the WAL, then in the database: about twice the
/// database's size, free. Refused before it starts rather than failing with a full disk.
fn room_to_rebuild(path: &Path) -> anyhow::Result<()> {
    let size = std::fs::metadata(path).map_or(0, |m| m.len());
    let free = disk::system_free_space()(path)?;
    if free < size.saturating_mul(2) {
        anyhow::bail!(
            "migrating the database copies it: it needs {} bytes free, and {free} are",
            size.saturating_mul(2)
        );
    }
    Ok(())
}

/// Makes freed pages returnable to the file system (SPEC §7.4): a database from before needs one full `VACUUM` for
/// that, run here, before serving. Not in a migration: `VACUUM` can't run in a transaction, and no binary depends on
/// it.
pub fn enable_incremental_vacuum(conn: &Connection) -> rusqlite::Result<bool> {
    let mode: i64 = conn.pragma_query_value(None, "auto_vacuum", |r| r.get(0))?;
    if mode == INCREMENTAL {
        return Ok(false);
    }
    conn.pragma_update(None, "auto_vacuum", INCREMENTAL)?;
    conn.execute_batch("VACUUM")?;
    Ok(true)
}

const INCREMENTAL: i64 = 2;

/// Returns up to `pages` free pages to the file system; → how many are still free.
pub fn reclaim(conn: &Connection, pages: u32) -> rusqlite::Result<u64> {
    conn.execute_batch(&format!("PRAGMA incremental_vacuum({pages})"))?;
    free_pages(conn)
}

pub fn free_pages(conn: &Connection) -> rusqlite::Result<u64> {
    let free: i64 = conn.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
    Ok(free.try_into().unwrap_or(0))
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

    /// The database on the host was at 1, written before versions had a minor.
    #[test]
    fn a_1_0_database_is_migrated_and_still_takes_a_1_0_binarys_writes() {
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
        assert_eq!(stored(&conn), 1003);
        conn.execute(insert, [b"after".to_vec()]).unwrap();
        let rows: Vec<(i64, String)> = conn
            .prepare("SELECT offloadable, location FROM blobs ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, [(0, "local".into()), (0, "local".into())]);
    }

    /// A database at 1.2, written the way a 1.2 binary does, with blobs here and in S3 and refs to them.
    fn at_1_2(path: &Path) -> Connection {
        let conn = open(path).unwrap();
        for migration in &MIGRATIONS[..3] {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 1002).unwrap();
        conn.execute_batch(
            "INSERT INTO users (id, username, created_at) VALUES (x'01', 'alice', 0);
             INSERT INTO blobs (user_id, id, size, content, created_at, offloadable, location)
               VALUES (x'01', x'aa', 3, x'616263', 1, 0, 'local'),
                      (x'01', x'bb', 5, x'', 2, 1, 's3');
             INSERT INTO refs (user_id, name, blob_id, updated_at) VALUES (x'01', 'vault', x'aa', 3);
             INSERT INTO s3_location (id, endpoint, bucket, prefix) VALUES (1, 'https://s3.example.com', 'music', 'music/');",
        )
        .unwrap();
        conn
    }

    #[test]
    fn the_1_3_rebuild_keeps_every_row_and_what_points_to_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backend.sqlite3");
        drop(at_1_2(&path));
        let conn = open_and_migrate(&path).unwrap();
        assert_eq!(stored(&conn), 1003);

        type Blob = (Vec<u8>, i64, Vec<u8>, i64, bool, String);
        let rows: Vec<Blob> = conn
            .prepare("SELECT id, size, content, created_at, offloadable, location FROM blobs ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                (vec![0xaa], 3, b"abc".to_vec(), 1, false, "local".into()),
                (vec![0xbb], 5, vec![], 2, true, "s3".into())
            ]
        );
        let backends: Vec<(String, String, String)> = conn
            .prepare("SELECT name, type, identity FROM backends")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            backends,
            [(
                "s3".into(),
                "s3".into(),
                r#"{"bucket":"music","endpoint":"https://s3.example.com","prefix":"music/"}"#
                    .into()
            )]
        );

        // `refs` still points at `blobs`, and the foreign key is enforced again.
        let foreign_keys: i64 = conn
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        let refs_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'refs'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            refs_sql.contains("REFERENCES blobs(user_id, id)"),
            "{refs_sql}"
        );
        assert!(
            conn.execute("INSERT INTO refs (user_id, name, blob_id, updated_at) VALUES (x'01', 'x', x'cc', 4)", [])
                .is_err(),
            "a ref to a blob that doesn't exist"
        );
        assert!(
            conn.execute("DELETE FROM blobs WHERE id = x'aa'", [])
                .is_err(),
            "a referenced blob"
        );
        let columns: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('blobs')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            columns,
            [
                "user_id",
                "id",
                "size",
                "created_at",
                "offloadable",
                "location",
                "content"
            ],
            "content last, so reading the others never steps through a blob"
        );
        let index: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'blobs_by_location'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(index, 1);

        // Any backend's name now, but not none; and a 1.2 binary's reads and writes still work.
        conn.execute_batch("UPDATE blobs SET location = 'backblaze' WHERE id = x'bb'")
            .unwrap();
        assert!(
            conn.execute_batch("UPDATE blobs SET location = '' WHERE id = x'bb'")
                .is_err()
        );
        let read: (i64, String, i64) = conn
            .query_row(
                "SELECT size, location, rowid FROM blobs WHERE user_id = x'01' AND id = x'aa'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((read.0, read.1.as_str()), (3, "local"));
        conn.execute_batch(
            "INSERT INTO blobs (user_id, id, size, content, created_at, offloadable, location)
               VALUES (x'01', x'dd', 1, x'00', 5, 0, 'local')",
        )
        .unwrap();
    }

    /// Several processes starting at once, on a new, a 1.0 and a 1.2 database: one migrates, the others find it
    /// done. Switching a database to WAL is where they collide (`use_wal`).
    #[test]
    fn many_starts_at_once_migrate_once() {
        for round in 0..60 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("backend.sqlite3");
            let blobs = match round % 3 {
                0 => 0,
                1 => {
                    let conn = open(&path).unwrap();
                    conn.execute_batch(MIGRATIONS[0].sql).unwrap();
                    conn.pragma_update(None, "user_version", 1).unwrap();
                    0
                }
                _ => {
                    drop(at_1_2(&path));
                    2
                }
            };
            let starts: Vec<_> = (0..16)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || open_and_migrate(&path).map(|_| ()))
                })
                .collect();
            for start in starts {
                start
                    .join()
                    .unwrap()
                    .unwrap_or_else(|e| panic!("round {round}: {e:#}"));
            }
            let conn = open(&path).unwrap();
            assert_eq!(stored(&conn), 1003);
            let count: i64 = conn
                .query_row("SELECT count(*) FROM blobs", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, blobs);
        }
    }

    #[test]
    fn freed_pages_go_back_to_the_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backend.sqlite3");
        let conn = open_and_migrate(&path).unwrap();
        assert!(enable_incremental_vacuum(&conn).unwrap(), "once");
        assert!(!enable_incremental_vacuum(&conn).unwrap());
        let pages = |conn: &Connection| -> i64 {
            conn.pragma_query_value(None, "page_count", |r| r.get(0))
                .unwrap()
        };
        conn.execute_batch("CREATE TABLE t (x BLOB); INSERT INTO t VALUES (zeroblob(1000000));")
            .unwrap();
        let full = pages(&conn);
        conn.execute_batch("UPDATE t SET x = x''").unwrap();
        assert!(reclaim(&conn, 100).unwrap() > 0, "a step at a time");
        while reclaim(&conn, 100).unwrap() > 0 {}
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        assert!(pages(&conn) < full / 5, "{} of {full} pages", pages(&conn));
        assert!(std::fs::metadata(&path).unwrap().len() < 200_000);
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
