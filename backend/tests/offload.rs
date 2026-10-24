//! Offloadable blobs in S3 (SPEC §7.4), against the stand-in S3 (common/s3.rs): uploads, reads, flag changes, the
//! pass at startup and every hour, the sweep, and the checks before serving.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use backend::config::{Backend, Config, Kind};
use backend::domain::{BlobId, ByteRange, format_uuid};
use backend::objects::Timeouts;
use backend::offload::{self, Pass};
use backend::remotes::Remote;
use backend::store::{self, Location, UserId};
use backend::{db, server};
use common::s3::{FakeS3, PREFIX};
use common::*;
use serde_json::json;

fn user_id(h: &Harness) -> UserId {
    store::user_by_username(&h.conn(), "alice")
        .unwrap()
        .unwrap()
        .id
}

fn key(h: &Harness, content: &[u8]) -> String {
    format!(
        "{PREFIX}{}/{}",
        format_uuid(&user_id(h)),
        BlobId::of(content)
    )
}

/// Where the database says the blob is, and how many bytes of content it holds itself.
fn stored(h: &Harness, content: &[u8]) -> (String, i64) {
    h.conn()
        .query_row(
            "SELECT location, length(content) FROM blobs WHERE id = ?1",
            [BlobId::of(content).0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

fn in_s3() -> (String, i64) {
    ("s3".into(), 0)
}

fn here(content: &[u8]) -> (String, i64) {
    ("local".into(), content.len() as i64)
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

async fn get(h: &Harness, cookie: &str, content: &[u8], range: Option<&str>) -> Reply {
    h.send(Call {
        cookie: Some(cookie),
        headers: range.map(|r| ("range", r.to_owned())).into_iter().collect(),
        ..h.call(
            Method::GET,
            PHONE,
            format!("/api/v1/blobs/{}", BlobId::of(content)),
        )
    })
    .await
}

fn s3_gets(s3: &FakeS3) -> usize {
    s3.requests()
        .iter()
        .filter(|r| r.starts_with("GET "))
        .count()
}

#[tokio::test]
async fn offloadable_uploads_go_to_s3_and_are_read_from_there() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(300, 1);
    let created = put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.json()["offloadable"], true);
    assert_eq!(created.json()["size"], 300);
    assert_eq!(s3.object(&key(&h, &track)), Some(track.clone()));
    assert_eq!(stored(&h, &track), in_s3());

    let whole = get(&h, &cookie, &track, None).await;
    assert_eq!(whole.status, StatusCode::OK);
    assert_eq!(whole.body, track);
    assert_eq!(whole.header("content-length"), Some("300"));
    let part = get(&h, &cookie, &track, Some("bytes=10-19")).await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.body, track[10..20]);
    assert_eq!(part.header("content-range"), Some("bytes 10-19/300"));
    assert_eq!(
        s3.requests().last().unwrap(),
        &format!("GET {} bytes=10-19", key(&h, &track))
    );

    let fetched = s3_gets(&s3);
    let outside = get(&h, &cookie, &track, Some("bytes=300-")).await;
    assert_eq!(outside.status, StatusCode::RANGE_NOT_SATISFIABLE);
    let head = h
        .send(Call {
            cookie: Some(&cookie),
            ..h.call(
                Method::HEAD,
                PHONE,
                format!("/api/v1/blobs/{}", BlobId::of(&track)),
            )
        })
        .await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.header("content-length"), Some("300"));
    assert_eq!(s3_gets(&s3), fetched, "neither asks S3");

    let again = put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(
        s3.requests()
            .iter()
            .filter(|r| r.starts_with("PUT "))
            .count(),
        1,
        "not uploaded again"
    );

    let notes = b"notes";
    put_blob(&h, &cookie, notes).await;
    assert_eq!(stored(&h, notes), here(notes), "only offloadable blobs go");
    assert_eq!(s3.keys().len(), 1);
}

#[tokio::test]
async fn with_the_local_target_nothing_goes_to_s3() {
    let (h, s3) = Harness::with_s3("local").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(100, 2);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    put_blob(&h, &cookie, b"x").await;
    let flagged = patch_blob(
        &h,
        &cookie,
        &BlobId::of(b"x"),
        json!({ "offloadable": true }),
    )
    .await;
    assert_eq!(flagged.json()["offloadable"], true);
    assert_eq!(stored(&h, &track), here(&track));
    assert_eq!(stored(&h, b"x"), here(b"x"));
    assert_eq!(offload::pass(&h.state).await, Pass::default());
    assert!(
        s3.requests().iter().all(|r| r.starts_with("LIST")),
        "{:?}",
        s3.requests()
    );
}

#[tokio::test]
async fn when_s3_is_down_uploads_stay_here_and_a_pass_moves_them() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(200, 3);
    s3.set_down(true);
    let created = put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    assert_eq!(
        created.status,
        StatusCode::CREATED,
        "S3 doesn't fail the upload"
    );
    assert_eq!(stored(&h, &track), here(&track));
    assert_eq!(get(&h, &cookie, &track, None).await.body, track);
    let failed = offload::pass(&h.state).await;
    assert_eq!(failed.failed, 1);

    s3.set_down(false);
    let moved = offload::pass(&h.state).await;
    assert_eq!(moved.to_backend, 1);
    assert_eq!(stored(&h, &track), in_s3());
    assert_eq!(s3.object(&key(&h, &track)), Some(track.clone()));
    assert_eq!(get(&h, &cookie, &track, None).await.body, track);
    assert_eq!(offload::pass(&h.state).await.to_backend, 0, "once");
}

#[tokio::test]
async fn changing_the_flag_moves_the_blob() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(150, 4);
    let id = BlobId::of(&track);
    put_blob(&h, &cookie, &track).await;
    assert_eq!(stored(&h, &track), here(&track));

    let flagged = patch_blob(&h, &cookie, &id, json!({ "offloadable": true })).await;
    assert_eq!(flagged.status, StatusCode::OK);
    assert_eq!(stored(&h, &track), in_s3(), "moved before the answer");

    let unflagged = patch_blob(&h, &cookie, &id, json!({ "offloadable": false })).await;
    assert_eq!(unflagged.status, StatusCode::OK);
    assert_eq!(unflagged.json()["offloadable"], false);
    assert_eq!(stored(&h, &track), here(&track), "back before the answer");
    assert_eq!(s3.keys(), Vec::<String>::new(), "and its object deleted");
    assert_eq!(get(&h, &cookie, &track, None).await.body, track);

    // S3 is down: flagging still works, the blob stays here for now; unflagging one in S3 can't.
    s3.set_down(true);
    let flagged = patch_blob(&h, &cookie, &id, json!({ "offloadable": true })).await;
    assert_eq!(flagged.status, StatusCode::OK);
    assert_eq!(stored(&h, &track), here(&track));
    s3.set_down(false);
    offload::pass(&h.state).await;
    assert_eq!(stored(&h, &track), in_s3());
    s3.set_down(true);
    let refused = patch_blob(&h, &cookie, &id, json!({ "offloadable": false })).await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.json()["error"], "storage_unavailable");
    assert_eq!(stored(&h, &track), in_s3());
    let listed = h.get(PHONE, "/api/v1/blobs", &cookie).await.json();
    assert_eq!(
        listed["blobs"][0]["offloadable"], true,
        "the flag didn't change"
    );
}

#[tokio::test]
async fn lost_damaged_and_unreachable_objects() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(120, 5);
    let id = BlobId::of(&track);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;

    s3.set_down(true);
    let down = get(&h, &cookie, &track, None).await;
    assert_eq!(down.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(down.json()["error"], "storage_unavailable");
    s3.set_down(false);

    // Damaged: the same length, other bytes. Reads pass it on (the client checks); moving it back doesn't.
    let mut damaged = track.clone();
    damaged[0] ^= 1;
    s3.put(&key(&h, &track), &damaged);
    assert_eq!(get(&h, &cookie, &track, None).await.body, damaged);
    let refused = patch_blob(&h, &cookie, &id, json!({ "offloadable": false })).await;
    assert_eq!(refused.status, StatusCode::GONE);
    assert_eq!(refused.json()["error"], "blob_lost");

    s3.remove(&key(&h, &track));
    let lost = get(&h, &cookie, &track, None).await;
    assert_eq!(lost.status, StatusCode::GONE);
    assert_eq!(lost.json()["error"], "blob_lost");
    assert_eq!(
        get(&h, &cookie, &track, Some("bytes=0-9")).await.status,
        StatusCode::GONE
    );
    let h = h.retarget("local");
    assert_eq!(offload::pass(&h.state).await.lost, 1);
    assert_eq!(stored(&h, &track), in_s3(), "stays, for the client to see");

    // A lost blob can still be deleted.
    let deleted = h
        .delete(PHONE, &format!("/api/v1/blobs/{id}"), &cookie)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_target_decides_where_blobs_are_at_each_pass() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let tracks = [bytes(100, 6), bytes(200, 7)];
    for track in &tracks {
        put_blob_with(&h, &cookie, track, offloadable("true")).await;
    }
    put_blob(&h, &cookie, b"root").await;
    assert_eq!(s3.keys().len(), 2);

    let h = h.retarget("local");
    let back = offload::pass(&h.state).await;
    assert_eq!((back.to_local, back.to_backend), (2, 0));
    assert!(s3.keys().is_empty());
    for track in &tracks {
        assert_eq!(stored(&h, track), here(track));
        assert_eq!(get(&h, &cookie, track, None).await.body, *track);
    }

    let h = h.retarget("s3");
    let out = offload::pass(&h.state).await;
    assert_eq!((out.to_local, out.to_backend), (0, 2));
    assert_eq!(stored(&h, b"root"), here(b"root"));
    assert_eq!(s3.keys().len(), 2);
}

#[tokio::test]
async fn the_sweep_deletes_only_objects_no_blob_owns() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(100, 8);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    let gone = bytes(100, 9);
    put_blob_with(&h, &cookie, &gone, offloadable("true")).await;
    let deleted = h
        .delete(
            PHONE,
            &format!("/api/v1/blobs/{}", BlobId::of(&gone)),
            &cookie,
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        s3.object(&key(&h, &gone)),
        None,
        "deleting a blob deletes its object"
    );

    let orphan = key(&h, b"never stored");
    for other in [orphan.as_str(), "other/thing", "test/readme.txt"] {
        s3.put(other, b"x");
    }
    s3.page_size.store(1, std::sync::atomic::Ordering::SeqCst);
    let pass = offload::pass(&h.state).await;
    assert_eq!(pass.swept, 1);
    assert_eq!(
        s3.keys(),
        vec![
            "other/thing".to_owned(),
            key(&h, &track),
            "test/readme.txt".to_owned()
        ],
        "what isn't ours stays"
    );
    assert!(
        s3.requests()
            .iter()
            .filter(|r| r.starts_with("LIST"))
            .count()
            >= 3,
        "in pages"
    );
}

#[tokio::test]
async fn refs_never_point_to_blobs_in_s3() {
    let (h, _s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let root = bytes(100, 10);
    let id = BlobId::of(&root);
    put_blob(&h, &cookie, &root).await;
    put_ref(&h, &cookie, "vault", &id, None).await;
    let refused = patch_blob(&h, &cookie, &id, json!({ "offloadable": true })).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(stored(&h, &root), here(&root));

    // An older binary can unflag a blob in S3 without bringing it back; the ref waits for the next pass.
    let other = bytes(100, 11);
    put_blob_with(&h, &cookie, &other, offloadable("true")).await;
    h.conn()
        .execute(
            "UPDATE blobs SET offloadable = 0 WHERE id = ?1",
            [BlobId::of(&other).0],
        )
        .unwrap();
    let early = put_ref(&h, &cookie, "vault", &BlobId::of(&other), None).await;
    assert_eq!(early.json()["error"], "blob_offloadable");
    assert_eq!(offload::pass(&h.state).await.to_local, 1);
    assert_eq!(
        put_ref(&h, &cookie, "vault", &BlobId::of(&other), None)
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_read_that_races_a_move_back_reads_the_database() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(100, 12);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    let user = user_id(&h);
    let remote = h.state.remotes["s3"].clone();
    let before = store::blob_meta(&h.conn(), &user, BlobId::of(&track))
        .unwrap()
        .unwrap();
    assert_eq!(before.location, Location::Backend("s3".into()));
    assert!(
        offload::to_local(&h.state, &remote, user, &before, false)
            .await
            .unwrap()
    );
    assert!(s3.keys().is_empty());
    let read = offload::read(&h.state, &remote, user, &before, ByteRange::Full).await;
    assert!(matches!(read, Ok(None)), "{read:?}");
    assert_eq!(get(&h, &cookie, &track, None).await.body, track);
}

#[tokio::test]
async fn moving_blobs_out_returns_their_space() {
    let (h, _s3) = Harness::with_backends("local", &["s3"], |c| c.max_blob_size = 4 << 20).await;
    db::enable_incremental_vacuum(&h.conn()).unwrap();
    let cookie = h.signed_up("alice", PHONE).await;
    let tracks = [bytes(1 << 20, 13), bytes(1 << 20, 14)];
    for track in &tracks {
        put_blob_with(&h, &cookie, track, offloadable("true")).await;
    }
    let pages = |h: &Harness| -> i64 {
        let conn = h.conn();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        conn.pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap()
    };
    let full = pages(&h);
    let h = h.retarget("s3");
    let pass = offload::pass(&h.state).await;
    assert_eq!(pass.to_backend, 2);
    assert!(pass.reclaimed_pages > 400, "{pass:?}");
    assert!(pages(&h) < full / 4, "{} of {full} pages", pages(&h));
}

/// The configuration `serve` would start with: the harness's database, and backends of these names whose files hold
/// these texts.
fn config(h: &Harness, backends: &[(&str, &str)]) -> Config {
    let backends = backends
        .iter()
        .map(|(name, text)| {
            let file = h.dir.path().join(format!("{name}.toml"));
            std::fs::write(&file, text).unwrap();
            (
                (*name).to_owned(),
                Backend {
                    kind: Kind::S3,
                    file,
                },
            )
        })
        .collect();
    Config {
        blob_target: target_of("local"),
        backends,
        ..(*h.state.config).clone()
    }
}

#[tokio::test]
async fn serving_needs_the_backends_its_blobs_are_in() {
    let (h, s3) = Harness::with_s3("s3").await;
    let file = s3.file();
    let other = FakeS3::start().await.file();
    assert!(
        server::prepare(&config(&h, &[])).unwrap().is_empty(),
        "nothing in a backend yet"
    );
    let cookie = h.signed_up("alice", PHONE).await;
    put_blob_with(&h, &cookie, &bytes(100, 15), offloadable("true")).await;

    let remotes = server::prepare(&config(&h, &[("s3", &file), ("b2", &other)])).unwrap();
    assert_eq!(remotes.keys().collect::<Vec<_>>(), ["b2", "s3"]);
    let mode: i64 = h
        .conn()
        .pragma_query_value(None, "auto_vacuum", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, 2, "incremental from now on");
    let gone = server::prepare(&config(&h, &[("b2", &other)])).unwrap_err();
    assert!(
        format!("{gone:#}").contains("1 blobs are in backend \"s3\", which isn't configured"),
        "{gone:#}"
    );
    for moved in [
        file.replace("bucket = \"bucket\"", "bucket = \"other\""),
        file.replace("prefix = \"test/\"", "prefix = \"other/\""),
        file.replace("127.0.0.1", "localhost"),
        other.clone(),
    ] {
        let error = server::prepare(&config(&h, &[("s3", &moved)])).unwrap_err();
        assert!(
            format!("{error:#}").contains("another type or location"),
            "{error:#}"
        );
    }
    let broken = server::prepare(&config(&h, &[("s3", "endpoint = 1")])).unwrap_err();
    assert!(
        format!("{broken:#}").contains("backend \"s3\"'s file"),
        "{broken:#}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moves_and_passes_at_once_never_lose_an_object() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let user = user_id(&h);
    let remote = h.state.remotes["s3"].clone();
    for seed in 0..20 {
        let track = bytes(100, seed);
        let id = BlobId::of(&track);
        put_blob(&h, &cookie, &track).await;
        h.conn()
            .execute("UPDATE blobs SET offloadable = 1 WHERE id = ?1", [id.0])
            .unwrap();
        let meta = store::blob_meta(&h.conn(), &user, id).unwrap().unwrap();
        let (a, b, _) = tokio::join!(
            offload::to_backend(&h.state, &remote, user, &meta),
            offload::to_backend(&h.state, &remote, user, &meta),
            offload::pass(&h.state),
        );
        assert_eq!(stored(&h, &track), in_s3(), "seed {seed}");
        assert!(!(a.unwrap() && b.unwrap()), "moved once");
        assert_eq!(
            s3.object(&key(&h, &track)),
            Some(track.clone()),
            "seed {seed}"
        );

        let meta = store::blob_meta(&h.conn(), &user, id).unwrap().unwrap();
        let (back, _) = tokio::join!(
            offload::to_local(&h.state, &remote, user, &meta, true),
            offload::pass(&h.state),
        );
        back.unwrap();
        assert_eq!(stored(&h, &track), here(&track), "seed {seed}");
        assert_eq!(get(&h, &cookie, &track, None).await.body, track);
    }
    assert!(s3.keys().is_empty());
}

/// A blob deleted and uploaded again before its object is deleted keeps the object.
#[tokio::test]
async fn an_object_a_blob_owns_is_never_deleted() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(100, 99);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    let remote = h.state.remotes["s3"].clone();
    offload::forget(&h.state, &remote, user_id(&h), BlobId::of(&track)).await;
    assert_eq!(s3.object(&key(&h, &track)), Some(track.clone()));
    assert_eq!(get(&h, &cookie, &track, None).await.body, track);
}

/// The credential file for an S3 at `endpoint`, with timeouts short enough for a test.
fn elsewhere(s3: &FakeS3, endpoint: &str) -> Remote {
    let timeouts = Timeouts {
        connect: Duration::from_millis(300),
        read: Duration::from_millis(300),
    };
    let file = s3.file().replace(&s3.endpoint, endpoint);
    Remote::with_timeouts("s3", Kind::S3, &file, timeouts).unwrap()
}

/// Fails instead of hanging.
async fn bounded<T>(call: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("an S3 that doesn't answer makes the request hang")
}

/// What a real outage looks like, rather than an S3 answering 503: nothing listening, or a connection that never
/// answers. Both are unavailable, and quickly: nothing waits longer than the timeouts.
#[tokio::test]
async fn an_unreachable_or_stalled_s3_is_unavailable_and_nothing_hangs() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(100, 20);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;

    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let refused = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent = format!("http://{}", stalled.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((connection, _)) = stalled.accept().await {
            held.push(connection);
        }
    });

    let mut h = h;
    for (seed, endpoint) in [(21, refused), (22, silent)] {
        h = h.with_remote(elsewhere(&s3, &endpoint));
        let read = bounded(get(&h, &cookie, &track, None)).await;
        assert_eq!(read.status, StatusCode::SERVICE_UNAVAILABLE, "{endpoint}");
        assert_eq!(read.json()["error"], "storage_unavailable");
        let unflag = bounded(patch_blob(
            &h,
            &cookie,
            &BlobId::of(&track),
            json!({ "offloadable": false }),
        ))
        .await;
        assert_eq!(unflag.status, StatusCode::SERVICE_UNAVAILABLE);
        let other = bytes(100, seed);
        let upload = bounded(put_blob_with(&h, &cookie, &other, offloadable("true"))).await;
        assert_eq!(
            upload.status,
            StatusCode::CREATED,
            "uploads don't wait for S3"
        );
        assert_eq!(stored(&h, &other), here(&other));
        let pass = bounded(offload::pass(&h.state)).await;
        assert!(pass.failed >= 1, "{pass:?}");
    }
    assert_eq!(stored(&h, &track), in_s3(), "nothing changed");
}

#[tokio::test]
async fn every_range_form_reads_through_s3() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(300, 23);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    for (asked, start, end) in [
        ("bytes=-10", 290, 299),
        ("bytes=290-", 290, 299),
        ("bytes=0-0", 0, 0),
        ("bytes=250-1000", 250, 299),
    ] {
        let part = get(&h, &cookie, &track, Some(asked)).await;
        assert_eq!(part.status, StatusCode::PARTIAL_CONTENT, "{asked}");
        assert_eq!(part.body, track[start..=end], "{asked}");
        let range = format!("bytes {start}-{end}/300");
        assert_eq!(
            part.header("content-range"),
            Some(range.as_str()),
            "{asked}"
        );
        let sent = format!("GET {} bytes={start}-{end}", key(&h, &track));
        assert_eq!(
            s3.requests().last(),
            Some(&sent),
            "S3 is asked for exactly those bytes"
        );
    }
}

/// `user delete` works on the database alone: the user's objects are left for the next sweep.
#[tokio::test]
async fn a_deleted_users_objects_go_in_the_next_sweep() {
    let (h, s3) = Harness::with_s3("s3").await;
    let alice = h.signed_up("alice", PHONE).await;
    let bob = h.signed_up("bob", PHONE).await;
    let theirs = bytes(100, 24);
    let his = bytes(100, 25);
    put_blob_with(&h, &alice, &theirs, offloadable("true")).await;
    put_blob_with(&h, &bob, &his, offloadable("true")).await;
    let alice_key = key(&h, &theirs);
    store::delete_user(&h.conn(), &user_id(&h)).unwrap();
    assert!(s3.object(&alice_key).is_some(), "the CLI doesn't reach S3");

    assert_eq!(offload::pass(&h.state).await.swept, 1);
    assert_eq!(s3.object(&alice_key), None);
    assert_eq!(s3.keys().len(), 1);
    assert_eq!(get(&h, &bob, &his, None).await.body, his);
}

/// Errors go in the log: none of them may name the location or carry a signed URL, which lets anyone holding it make
/// that request for a while.
#[tokio::test]
async fn s3_errors_say_what_failed_but_not_where() {
    let (h, s3) = Harness::with_s3("s3").await;
    h.signed_up("alice", PHONE).await;
    let key = key(&h, b"x");
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let refused = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let unreachable = elsewhere(&s3, &refused);
    s3.set_down(true);
    let remote = h.state.remotes["s3"].clone();
    let errors = [
        unreachable.get_all(&key, 1).await.unwrap_err(),
        unreachable
            .put(&key, b"x".to_vec().into())
            .await
            .unwrap_err(),
        unreachable.list().await.unwrap_err(),
        remote.get_all(&key, 1).await.unwrap_err(),
        remote.delete(&key).await.unwrap_err(),
    ];
    let errors = errors.map(|e| e.to_string());
    assert!(errors[0].contains("Connection refused"), "{}", errors[0]);
    for error in errors {
        for secret in [
            refused.as_str(),
            &s3.endpoint,
            &key,
            "X-Amz",
            "bucket",
            PREFIX,
            "id",
        ] {
            assert!(!error.contains(secret), "{secret:?} in {error:?}");
        }
    }
    assert!(
        remote
            .list()
            .await
            .unwrap_err()
            .to_string()
            .contains("503 Service Unavailable SlowDown")
    );
}

const RESERVE: u64 = 1 << 30;

/// The free space the server sees: the reserve and `spare` bytes more.
fn spare(h: &Harness, spare: u64) {
    h.free
        .store(RESERVE + spare, std::sync::atomic::Ordering::SeqCst);
}

fn at(h: &Harness, content: &[u8]) -> (String, i64) {
    stored(h, content)
}

#[tokio::test]
async fn blobs_move_between_backends_without_the_database() {
    let (h, fakes) = Harness::with_backends("aws", &["aws", "b2"], |_| {}).await;
    let (aws, b2) = (&fakes["aws"], &fakes["b2"]);
    let cookie = h.signed_up("alice", PHONE).await;
    let tracks = [bytes(100, 30), bytes(200, 31)];
    for track in &tracks {
        put_blob_with(&h, &cookie, track, offloadable("true")).await;
    }
    put_blob(&h, &cookie, b"root").await;
    assert_eq!(aws.keys().len(), 2);

    let h = h.retarget("b2");
    spare(&h, 0);
    let pass = offload::pass(&h.state).await;
    assert_eq!(
        (pass.across, pass.to_local, pass.held_back),
        (2, 0, 0),
        "no room needed here"
    );
    assert_eq!(
        pass.swept, 0,
        "the move deleted what it moved, not the sweep"
    );
    assert!(aws.keys().is_empty(), "gone from where they were");
    for track in &tracks {
        assert_eq!(at(&h, track), ("b2".into(), 0));
        assert_eq!(b2.object(&key(&h, track)), Some(track.clone()));
        assert_eq!(get(&h, &cookie, track, None).await.body, *track);
    }
    assert_eq!(at(&h, b"root"), here(b"root"));
    let recorded = store::recorded_backends(&h.conn()).unwrap();
    assert_eq!(
        recorded.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(),
        ["aws", "b2"]
    );

    // A blob damaged on the way out stays where it was, as lost.
    let h = h.retarget("aws");
    spare(&h, 1 << 20);
    let mut damaged = tracks[0].clone();
    damaged[0] ^= 1;
    b2.put(&key(&h, &tracks[0]), &damaged);
    let back = offload::pass(&h.state).await;
    assert_eq!((back.across, back.lost), (1, 1));
    assert_eq!(at(&h, &tracks[0]), ("b2".into(), 0));
    assert_eq!(at(&h, &tracks[1]), ("aws".into(), 0));
}

#[tokio::test]
async fn blobs_come_home_all_together_or_not_at_all() {
    let (h, s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let tracks = [bytes(100, 32), bytes(100, 33), bytes(100, 34)];
    for track in &tracks {
        put_blob_with(&h, &cookie, track, offloadable("true")).await;
    }
    let h = h.retarget("local");
    // 300 bytes, and the largest once more while it is in flight: 400 bytes over the reserve.
    spare(&h, 399);
    let held = offload::pass(&h.state).await;
    assert_eq!((held.to_local, held.held_back), (0, 3));
    assert_eq!(s3.keys().len(), 3, "none came, not some");
    assert_eq!(
        get(&h, &cookie, &tracks[0], None).await.body,
        tracks[0],
        "still readable there"
    );
    spare(&h, 400);
    let home = offload::pass(&h.state).await;
    assert_eq!((home.to_local, home.held_back), (3, 0));
    assert!(s3.keys().is_empty());
}

#[tokio::test]
async fn a_blob_is_unflagged_only_if_it_fits_here() {
    let (h, _s3) = Harness::with_s3("s3").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let track = bytes(100, 35);
    put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    spare(&h, 199);
    let full = patch_blob(
        &h,
        &cookie,
        &BlobId::of(&track),
        json!({ "offloadable": false }),
    )
    .await;
    assert_eq!(full.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(full.json()["error"], "storage_full");
    assert_eq!(
        at(&h, &track),
        in_s3(),
        "the flag didn't change, nor where it is"
    );
    spare(&h, 200);
    let fits = patch_blob(
        &h,
        &cookie,
        &BlobId::of(&track),
        json!({ "offloadable": false }),
    )
    .await;
    assert_eq!(fits.status, StatusCode::OK);
    assert_eq!(at(&h, &track), here(&track));
}

#[tokio::test]
async fn uploads_into_the_database_keep_the_reserve_free() {
    let (h, s3) = Harness::with_s3("local").await;
    let cookie = h.signed_up("alice", PHONE).await;
    let notes = bytes(100, 36);
    spare(&h, 199);
    let full = put_blob(&h, &cookie, &notes).await;
    assert_eq!(full.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(full.json()["error"], "storage_full");
    spare(&h, 200);
    assert_eq!(
        put_blob(&h, &cookie, &notes).await.status,
        StatusCode::CREATED
    );
    spare(&h, 0);
    assert_eq!(
        put_blob(&h, &cookie, &notes).await.status,
        StatusCode::OK,
        "uploading what is already here writes nothing"
    );

    // Into a backend, the database needs no room; unless the backend fails and it would have to take the blob.
    let h = h.retarget("s3");
    let track = bytes(100, 37);
    let out = put_blob_with(&h, &cookie, &track, offloadable("true")).await;
    assert_eq!(out.status, StatusCode::CREATED);
    assert_eq!(at(&h, &track), in_s3());
    s3.set_down(true);
    let nowhere = put_blob_with(&h, &cookie, &bytes(100, 38), offloadable("true")).await;
    assert_eq!(nowhere.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(nowhere.json()["error"], "storage_unavailable");
}
