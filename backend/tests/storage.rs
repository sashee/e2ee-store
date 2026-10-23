//! Blobs, refs and static files through the HTTP API.

mod common;

use axum::http::{Method, StatusCode};
use backend::domain::BlobId;
use common::*;
use serde_json::json;

async fn put_blob(h: &Harness, cookie: &str, content: &[u8]) -> common::Reply {
    put_blob_with(h, cookie, content, vec![]).await
}

async fn put_blob_with<'a>(
    h: &Harness,
    cookie: &'a str,
    content: &[u8],
    headers: Vec<(&'a str, String)>,
) -> common::Reply {
    let id = BlobId::of(content);
    h.send(common::Call {
        cookie: Some(cookie),
        body: content.to_vec(),
        content_type: Some("application/octet-stream"),
        headers,
        ..h.call(Method::PUT, PHONE, format!("/api/v1/blobs/{id}"))
    })
    .await
}

async fn patch_blob(
    h: &Harness,
    cookie: &str,
    id: &BlobId,
    flags: serde_json::Value,
) -> common::Reply {
    h.send(common::Call {
        cookie: Some(cookie),
        body: flags.to_string().into_bytes(),
        content_type: Some("application/json"),
        ..h.call(Method::PATCH, PHONE, format!("/api/v1/blobs/{id}"))
    })
    .await
}

fn offloadable(value: &str) -> Vec<(&'static str, String)> {
    vec![("blob-offloadable", value.to_owned())]
}

async fn put_ref(
    h: &Harness,
    cookie: &str,
    name: &str,
    blob: &BlobId,
    precondition: Option<(&str, String)>,
) -> common::Reply {
    h.send(common::Call {
        cookie: Some(cookie),
        body: json!({ "blob": blob.to_string() }).to_string().into_bytes(),
        content_type: Some("application/json"),
        headers: precondition.into_iter().collect(),
        ..h.call(Method::PUT, PHONE, format!("/api/v1/refs/{name}"))
    })
    .await
}

fn tag(id: &BlobId) -> String {
    format!("\"{id}\"")
}

#[tokio::test]
async fn blobs_round_trip_with_ranges() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let content = b"0123456789";
    let id = BlobId::of(content);

    let created = put_blob(&h, &cookie, content).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(
        created.json(),
        json!({ "id": id.to_string(), "size": 10, "created_at": "2026-10-09T20:57:00.000Z", "offloadable": false })
    );
    h.advance(1000);
    let again = put_blob(&h, &cookie, content).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(
        again.json()["created_at"],
        "2026-10-09T20:57:00.000Z",
        "created_at is unchanged"
    );

    let full = h.get(PHONE, &format!("/api/v1/blobs/{id}"), &cookie).await;
    assert_eq!(full.status, StatusCode::OK);
    assert_eq!(full.body, content);
    assert_eq!(
        full.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(full.header("etag"), Some(tag(&id).as_str()));
    assert_eq!(
        full.header("content-security-policy"),
        Some("default-src 'none'; sandbox")
    );
    assert_eq!(full.header("content-disposition"), Some("attachment"));
    assert_eq!(full.header("cache-control"), Some("no-store"));

    let range = |r: &'static str| common::Call {
        cookie: Some(&cookie),
        headers: vec![("range", r.into())],
        ..h.call(Method::GET, PHONE, format!("/api/v1/blobs/{id}"))
    };
    let partial = h.send(range("bytes=2-4")).await;
    assert_eq!(partial.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(partial.body, b"234");
    assert_eq!(partial.header("content-range"), Some("bytes 2-4/10"));
    assert_eq!(h.send(range("bytes=-3")).await.body, b"789");
    let unsatisfiable = h.send(range("bytes=10-")).await;
    assert_eq!(unsatisfiable.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(unsatisfiable.header("content-range"), Some("bytes */10"));
    assert_eq!(h.send(range("bytes=0-1,4-5")).await.status, StatusCode::OK);

    let head = h
        .send(common::Call {
            cookie: Some(&cookie),
            ..h.call(Method::HEAD, PHONE, format!("/api/v1/blobs/{id}"))
        })
        .await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.header("content-length"), Some("10"));
    assert!(head.body.is_empty());
}

#[tokio::test]
async fn ranges_span_overflow_pages() {
    let h = Harness::with(|config| config.max_blob_size = 1 << 20);
    let cookie = h.signed_up("alice", PHONE).await;
    let content: Vec<u8> = (0..1 << 20).map(|i: u32| (i % 251) as u8).collect();
    let id = BlobId::of(&content);
    assert_eq!(
        put_blob(&h, &cookie, &content).await.status,
        StatusCode::CREATED
    );

    let range = |r: String| common::Call {
        cookie: Some(&cookie),
        headers: vec![("range", r)],
        ..h.call(Method::GET, PHONE, format!("/api/v1/blobs/{id}"))
    };
    for (start, end) in [(0, 99), (4000, 70_000), ((1 << 20) - 5000, (1 << 20) - 1)] {
        let partial = h.send(range(format!("bytes={start}-{end}"))).await;
        assert_eq!(partial.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(partial.body, content[start..=end]);
    }
    assert_eq!(
        h.get(PHONE, &format!("/api/v1/blobs/{id}"), &cookie)
            .await
            .body,
        content
    );

    let empty = BlobId::of(b"");
    put_blob(&h, &cookie, b"").await;
    let full = h
        .get(PHONE, &format!("/api/v1/blobs/{empty}"), &cookie)
        .await;
    assert_eq!(full.status, StatusCode::OK);
    assert!(full.body.is_empty());
}

#[tokio::test]
async fn uploads_are_checked() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let wrong_hash = h
        .send(common::Call {
            cookie: Some(&cookie),
            body: b"abc".to_vec(),
            content_type: Some("application/octet-stream"),
            ..h.call(
                Method::PUT,
                PHONE,
                format!("/api/v1/blobs/{}", BlobId::of(b"xyz")),
            )
        })
        .await;
    assert_eq!(wrong_hash.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong_hash.json()["error"], "hash_mismatch");

    let wrong_type = h
        .send(common::Call {
            cookie: Some(&cookie),
            body: b"abc".to_vec(),
            content_type: Some("text/plain"),
            ..h.call(
                Method::PUT,
                PHONE,
                format!("/api/v1/blobs/{}", BlobId::of(b"abc")),
            )
        })
        .await;
    assert_eq!(wrong_type.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let big = vec![1u8; 1025];
    let too_large = put_blob(&h, &cookie, &big).await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(too_large.json()["error"], "blob_too_large");
    assert_eq!(
        put_blob(&h, &cookie, &big[..1024]).await.status,
        StatusCode::CREATED
    );

    let bad_id = h.get(PHONE, "/api/v1/blobs/ABC", &cookie).await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn blobs_are_listed_in_pages() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let mut ids: Vec<String> = Vec::new();
    for i in 0..5u8 {
        put_blob(&h, &cookie, &[i]).await;
        ids.push(BlobId::of(&[i]).to_string());
    }
    ids.sort();
    let first = h.get(PHONE, "/api/v1/blobs?limit=2", &cookie).await.json();
    assert_eq!(
        first["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ids[..2]
    );
    assert_eq!(first["blobs"][0]["size"], 1);
    assert_eq!(first["next"], ids[1]);
    let last = h
        .get(
            PHONE,
            &format!("/api/v1/blobs?limit=2&after={}", ids[3]),
            &cookie,
        )
        .await
        .json();
    assert_eq!(last["blobs"].as_array().unwrap().len(), 1);
    assert_eq!(last["next"], serde_json::Value::Null);
}

#[tokio::test]
async fn blobs_are_flagged_offloadable_on_upload_or_later() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let a = BlobId::of(b"a");
    let b = BlobId::of(b"b");

    let flagged = put_blob_with(&h, &cookie, b"a", offloadable("true")).await;
    assert_eq!(flagged.status, StatusCode::CREATED);
    assert_eq!(flagged.json()["offloadable"], true);
    let again = put_blob_with(&h, &cookie, b"a", offloadable("false")).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(
        again.json()["offloadable"],
        true,
        "an upload doesn't change an existing blob's flag"
    );
    assert_eq!(
        put_blob(&h, &cookie, b"b").await.json()["offloadable"],
        false
    );

    let unflagged = patch_blob(&h, &cookie, &a, json!({ "offloadable": false })).await;
    assert_eq!(unflagged.status, StatusCode::OK);
    assert_eq!(
        unflagged.json(),
        json!({ "id": a.to_string(), "size": 1, "created_at": "2026-10-09T20:57:00.000Z", "offloadable": false })
    );
    for _ in 0..2 {
        let flag = patch_blob(&h, &cookie, &b, json!({ "offloadable": true })).await;
        assert_eq!(flag.status, StatusCode::OK);
        assert_eq!(flag.json()["offloadable"], true);
    }
    let listed = h.get(PHONE, "/api/v1/blobs", &cookie).await.json();
    let flags: std::collections::HashMap<String, bool> = listed["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|blob| {
            (
                blob["id"].as_str().unwrap().to_owned(),
                blob["offloadable"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        flags,
        [(a.to_string(), false), (b.to_string(), true)].into()
    );

    // Offloadable blobs are read like any other.
    assert_eq!(
        h.get(PHONE, &format!("/api/v1/blobs/{b}"), &cookie)
            .await
            .body,
        b"b"
    );

    let missing = patch_blob(
        &h,
        &cookie,
        &BlobId::of(b"c"),
        json!({ "offloadable": true }),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let bob = h.signed_up("bob", PHONE).await;
    assert_eq!(
        patch_blob(&h, &bob, &a, json!({ "offloadable": true }))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn offloadable_flags_are_checked() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let a = BlobId::of(b"a");
    for value in ["yes", "True", "1", ""] {
        let reply = put_blob_with(&h, &cookie, b"a", offloadable(value)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{value:?}");
    }
    put_blob(&h, &cookie, b"a").await;
    for body in [
        json!({}),
        json!({ "offloadable": "true" }),
        json!({ "offloadable": null }),
    ] {
        let reply = patch_blob(&h, &cookie, &a, body.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
    let wrong_type = h
        .send(common::Call {
            cookie: Some(&cookie),
            body: b"offloadable=true".to_vec(),
            content_type: Some("application/x-www-form-urlencoded"),
            ..h.call(Method::PATCH, PHONE, format!("/api/v1/blobs/{a}"))
        })
        .await;
    assert_eq!(wrong_type.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let other_origin = h
        .send(common::Call {
            cookie: Some(&cookie),
            body: json!({ "offloadable": true }).to_string().into_bytes(),
            content_type: Some("application/json"),
            origin: Some("http://evil.localhost:24038".to_owned()),
            ..h.call(Method::PATCH, PHONE, format!("/api/v1/blobs/{a}"))
        })
        .await;
    assert_eq!(other_origin.status, StatusCode::FORBIDDEN);
    assert_eq!(
        h.get(PHONE, "/api/v1/blobs", &cookie).await.json()["blobs"][0]["offloadable"],
        false,
        "nothing changed"
    );
}

#[tokio::test]
async fn refs_never_point_to_offloadable_blobs() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let a = BlobId::of(b"a");
    let b = BlobId::of(b"b");
    put_blob_with(&h, &cookie, b"a", offloadable("true")).await;
    put_blob(&h, &cookie, b"b").await;

    let refused = put_ref(&h, &cookie, "root", &a, None).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.json()["error"], "blob_offloadable");
    assert_eq!(
        h.get(PHONE, "/api/v1/refs/root", &cookie).await.status,
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        put_ref(&h, &cookie, "root", &b, None).await.status,
        StatusCode::CREATED
    );
    let flag = patch_blob(&h, &cookie, &b, json!({ "offloadable": true })).await;
    assert_eq!(flag.status, StatusCode::CONFLICT);
    assert_eq!(flag.json()["error"], "blob_offloadable");
    assert_eq!(
        patch_blob(&h, &cookie, &b, json!({ "offloadable": false }))
            .await
            .status,
        StatusCode::OK,
        "unflagging is always allowed"
    );

    // Once the ref points elsewhere, the blob can be flagged.
    patch_blob(&h, &cookie, &a, json!({ "offloadable": false })).await;
    assert_eq!(
        put_ref(&h, &cookie, "root", &a, None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        patch_blob(&h, &cookie, &b, json!({ "offloadable": true }))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn refs_compare_and_swap() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let (a, b) = (BlobId::of(b"a"), BlobId::of(b"b"));
    put_blob(&h, &cookie, b"a").await;
    put_blob(&h, &cookie, b"b").await;

    let created = put_ref(
        &h,
        &cookie,
        "vault",
        &a,
        Some(("if-none-match", "*".into())),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.json()["blob"], a.to_string());
    let exists = put_ref(
        &h,
        &cookie,
        "vault",
        &b,
        Some(("if-none-match", "*".into())),
    )
    .await;
    assert_eq!(exists.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(exists.json()["current"], a.to_string());

    let stale = put_ref(&h, &cookie, "vault", &b, Some(("if-match", tag(&b)))).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(stale.json()["current"], a.to_string());
    let swapped = put_ref(&h, &cookie, "vault", &b, Some(("if-match", tag(&a)))).await;
    assert_eq!(swapped.status, StatusCode::OK);

    let read = h.get(PHONE, "/api/v1/refs/vault", &cookie).await;
    assert_eq!(read.json()["blob"], b.to_string());
    assert_eq!(read.header("etag"), Some(tag(&b).as_str()));

    let missing_blob = put_ref(&h, &cookie, "vault", &BlobId::of(b"zzz"), None).await;
    assert_eq!(missing_blob.status, StatusCode::CONFLICT);
    assert_eq!(missing_blob.json()["error"], "blob_not_found");

    let must_exist = put_ref(&h, &cookie, "other", &a, Some(("if-match", "*".into()))).await;
    assert_eq!(must_exist.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(must_exist.json()["current"], serde_json::Value::Null);

    let both = h
        .send(common::Call {
            cookie: Some(&cookie),
            body: json!({ "blob": a.to_string() }).to_string().into_bytes(),
            content_type: Some("application/json"),
            headers: vec![("if-match", "*".into()), ("if-none-match", "*".into())],
            ..h.call(Method::PUT, PHONE, "/api/v1/refs/vault")
        })
        .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn referenced_blobs_stay_and_refs_delete_with_expect() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let a = BlobId::of(b"a");
    put_blob(&h, &cookie, b"a").await;
    put_ref(&h, &cookie, "keys/x", &a, None).await;

    let referenced = h
        .delete(PHONE, &format!("/api/v1/blobs/{a}"), &cookie)
        .await;
    assert_eq!(referenced.status, StatusCode::CONFLICT);
    assert_eq!(referenced.json()["error"], "blob_referenced");

    let delete_ref = |precondition: Option<(&'static str, String)>| common::Call {
        cookie: Some(&cookie),
        headers: precondition.into_iter().collect(),
        ..h.call(Method::DELETE, PHONE, "/api/v1/refs/keys/x")
    };
    let wrong = h
        .send(delete_ref(Some(("if-match", tag(&BlobId::of(b"b"))))))
        .await;
    assert_eq!(wrong.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        h.send(delete_ref(Some(("if-none-match", "*".into()))))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        h.send(delete_ref(Some(("if-match", tag(&a))))).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.send(delete_ref(None)).await.status, StatusCode::NOT_FOUND);
    let gone = h.send(delete_ref(Some(("if-match", tag(&a))))).await;
    assert_eq!(gone.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(gone.json()["current"], serde_json::Value::Null);

    assert_eq!(
        h.delete(PHONE, &format!("/api/v1/blobs/{a}"), &cookie)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.delete(PHONE, &format!("/api/v1/blobs/{a}"), &cookie)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn refs_are_listed_by_prefix() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let a = BlobId::of(b"a");
    put_blob(&h, &cookie, b"a").await;
    for name in ["vault", "keys/a", "keys/b", "keysx"] {
        put_ref(&h, &cookie, name, &a, None).await;
    }
    let keys = h
        .get(PHONE, "/api/v1/refs?prefix=keys/", &cookie)
        .await
        .json();
    let names: Vec<_> = keys["refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["keys/a", "keys/b"]);
    let page = h
        .get(PHONE, "/api/v1/refs?limit=1&after=keys/a", &cookie)
        .await
        .json();
    assert_eq!(page["refs"][0]["name"], "keys/b");
    assert_eq!(page["next"], "keys/b");
    let bad = h.get(PHONE, "/api/v1/refs/a/../b", &cookie).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn users_see_only_their_own_storage() {
    let h = Harness::new();
    let alice = h.signed_up("alice", PHONE).await;
    let bob = h.signed_up("bob", PHONE).await;
    let a = BlobId::of(b"secret");
    put_blob(&h, &alice, b"secret").await;
    put_ref(&h, &alice, "vault", &a, None).await;
    assert_eq!(
        h.get(PHONE, &format!("/api/v1/blobs/{a}"), &bob)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.get(PHONE, "/api/v1/refs/vault", &bob).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.get(PHONE, "/api/v1/blobs", &bob).await.json()["blobs"],
        json!([])
    );
    // Bob can't point a ref at Alice's blob.
    assert_eq!(
        put_ref(&h, &bob, "vault", &a, None).await.json()["error"],
        "blob_not_found"
    );
    assert_eq!(
        h.get(PHONE, "/api/v1/blobs", "not-a-session").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn concurrent_writers_get_exactly_one_winner() {
    let h = std::sync::Arc::new(Harness::new());
    let cookie = h.signed_up("alice", PHONE).await;
    let base = BlobId::of(b"base");
    put_blob(&h, &cookie, b"base").await;
    put_ref(&h, &cookie, "vault", &base, None).await;
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let (h, cookie) = (h.clone(), cookie.clone());
        tasks.push(tokio::spawn(async move {
            put_blob(&h, &cookie, &[i]).await;
            put_ref(
                &h,
                &cookie,
                "vault",
                &BlobId::of(&[i]),
                Some(("if-match", tag(&base))),
            )
            .await
            .status
        }));
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.unwrap());
    }
    assert_eq!(
        statuses.iter().filter(|s| **s == StatusCode::OK).count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::PRECONDITION_FAILED)
            .count(),
        7,
        "{statuses:?}"
    );
}

#[tokio::test]
async fn static_files_are_served_with_security_headers() {
    let h = Harness::new();
    let index = h.send(h.call(Method::GET, LAPTOP, "/")).await;
    assert_eq!(index.status, StatusCode::OK);
    assert_eq!(
        index.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(
        index
            .header("content-security-policy")
            .unwrap()
            .contains("default-src 'self'")
    );
    assert_eq!(index.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(index.header("cache-control"), Some("no-cache"));
    let script = h.send(h.call(Method::GET, LAPTOP, "/js/main.js")).await;
    assert_eq!(
        script.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    for missing in ["/nope.html", "/js", "/../backend.sqlite3", "/.hidden"] {
        assert_eq!(
            h.send(h.call(Method::GET, LAPTOP, missing)).await.status,
            StatusCode::NOT_FOUND,
            "{missing}"
        );
    }
    let api_missing = h.get(LAPTOP, "/api/v1/nothing", "x").await;
    assert_eq!(api_missing.status, StatusCode::NOT_FOUND);
    assert_eq!(api_missing.json()["error"], "not_found");
}

#[tokio::test]
async fn a_ref_deletes_with_if_match_star_only_if_it_exists() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let delete = || common::Call {
        cookie: Some(&cookie),
        headers: vec![("if-match", "*".into())],
        ..h.call(Method::DELETE, PHONE, "/api/v1/refs/vault")
    };
    let missing = h.send(delete()).await;
    assert_eq!(missing.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(missing.json()["current"], serde_json::Value::Null);
    put_blob(&h, &cookie, b"a").await;
    put_ref(&h, &cookie, "vault", &BlobId::of(b"a"), None).await;
    assert_eq!(h.send(delete()).await.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn blobs_larger_than_the_frameworks_default_limit_are_accepted() {
    // 16 MiB is the default; axum's own body limit for extractors that buffer is 2 MiB.
    let h = Harness::with(|config| config.max_blob_size = 16 << 20);
    let cookie = h.signed_up("alice", PHONE).await;
    let content: Vec<u8> = (0..3 << 20).map(|i: u32| (i % 251) as u8).collect();
    assert_eq!(
        put_blob(&h, &cookie, &content).await.status,
        StatusCode::CREATED
    );
    let read = h
        .get(
            PHONE,
            &format!("/api/v1/blobs/{}", BlobId::of(&content)),
            &cookie,
        )
        .await;
    assert_eq!(read.body, content);
}

#[tokio::test]
async fn deleting_a_user_deletes_everything_they_own_and_nothing_else() {
    let h = Harness::new();
    let alice = h.signed_up("alice", PHONE).await;
    h.register(PHONE, &alice, &Authenticator::new(1), "Phone")
        .await;
    put_blob(&h, &alice, b"a").await;
    put_ref(&h, &alice, "vault", &BlobId::of(b"a"), None).await;
    // A pending registration and an unused setup token.
    h.post_json(
        PHONE,
        "/api/v1/me/passkeys/register/start",
        Some(&alice),
        json!({}),
    )
    .await;
    h.setup_token_for("alice");
    let bob = h.signed_up("bob", PHONE).await;
    put_blob(&h, &bob, b"bob's").await;

    let conn = h.conn();
    let summaries: Vec<_> = backend::store::list_users(&conn)
        .unwrap()
        .into_iter()
        .map(|s| (s.user.username, s.passkeys, s.stored_bytes))
        .collect();
    assert_eq!(
        summaries,
        [
            ("alice".into(), vec![("6c4b9e.localhost".into(), 1)], 1),
            ("bob".into(), vec![], 5)
        ]
    );

    let user = backend::store::user_by_username(&conn, "alice")
        .unwrap()
        .unwrap();
    assert!(backend::store::delete_user(&conn, &user.id).unwrap());
    for table in [
        "passkeys",
        "sessions",
        "setup_tokens",
        "ceremonies",
        "blobs",
        "refs",
    ] {
        let left: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE user_id = ?1"),
                [user.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 0, "{table}");
    }
    assert_eq!(
        h.get(PHONE, "/api/v1/me", &alice).await.status,
        StatusCode::UNAUTHORIZED
    );
    let bobs = h.get(PHONE, "/api/v1/blobs", &bob).await.json();
    assert_eq!(bobs["blobs"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn the_frameworks_own_errors_are_json_too() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    for uri in ["/api/v1/blobs?limit=-1", "/api/v1/refs?limit=lots"] {
        let reply = h.get(PHONE, uri, &cookie).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(reply.json()["error"], "bad_request", "{uri}");
        assert_eq!(reply.header("cache-control"), Some("no-store"));
    }
    let wrong_method = h
        .send(common::Call {
            cookie: Some(&cookie),
            ..h.call(Method::POST, PHONE, "/api/v1/blobs")
        })
        .await;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong_method.json()["error"], "method_not_allowed");
    assert!(wrong_method.header("allow").unwrap().contains("GET"));
}
