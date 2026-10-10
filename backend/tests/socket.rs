//! Binding the Unix socket (SPEC §3.1).
//!
//! Apart from the tests that spawn the binary (server.rs): a child spawned by another test thread holds copies of
//! this process's file descriptors until it execs, which would keep a "stale" socket listening for a moment.

use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};

use backend::server::bind;

#[tokio::test]
async fn the_socket_is_created_for_its_group_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/backend.sock");
    let _listener = bind(&path).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o660);
}

#[tokio::test]
async fn a_stale_socket_is_replaced_but_a_live_one_or_another_file_is_not() {
    let dir = tempfile::tempdir().unwrap();

    let stale = dir.path().join("stale.sock");
    drop(UnixListener::bind(&stale).unwrap());
    assert!(
        stale.exists(),
        "nothing listens, but the file is still there"
    );
    let _replaced = bind(&stale).unwrap();

    let live = dir.path().join("live.sock");
    let _other_server = UnixListener::bind(&live).unwrap();
    let error = bind(&live).unwrap_err().to_string();
    assert!(error.contains("in use"), "{error}");
    assert!(
        UnixStream::connect(&live).is_ok(),
        "the other server still has its socket"
    );

    let file = dir.path().join("file.sock");
    std::fs::write(&file, "data").unwrap();
    let error = bind(&file).unwrap_err().to_string();
    assert!(error.contains("not a socket"), "{error}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "data");
}
