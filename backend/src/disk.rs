//! Free space on the database's file system (SPEC §7.5): what writes into the database may use.

use std::path::Path;
use std::sync::Arc;

/// The bytes free for an unprivileged writer on the file system holding `path`. A function so tests can fill the disk.
pub type FreeSpace = Arc<dyn Fn(&Path) -> std::io::Result<u64> + Send + Sync>;

pub fn system_free_space() -> FreeSpace {
    Arc::new(|path| {
        let stat = rustix::fs::statvfs(path)?;
        Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
    })
}

/// Whether writing `total` bytes into the database leaves `reserve` free. Every write passes through the WAL before it
/// reaches the database, so while one is in flight its bytes are there twice: room for the `largest` of them too.
pub fn fits(free: u64, total: u64, largest: u64, reserve: u64) -> bool {
    free >= total.saturating_add(largest).saturating_add(reserve)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_need_their_size_twice_while_in_flight_and_the_reserve_stays() {
        assert!(fits(1000, 300, 100, 600));
        assert!(!fits(999, 300, 100, 600));
        assert!(fits(1000, 0, 0, 1000));
        assert!(!fits(10, u64::MAX, 1, 0), "no overflow");
    }

    #[test]
    fn the_system_reports_the_temporary_directorys_file_system() {
        let dir = tempfile::tempdir().unwrap();
        assert!(system_free_space()(dir.path()).unwrap() > 0);
        assert!(system_free_space()(&dir.path().join("missing")).is_err());
    }
}
