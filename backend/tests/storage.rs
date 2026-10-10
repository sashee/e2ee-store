//! Blobs, refs and static files through the HTTP API.

mod common;

use axum::http::{Method, StatusCode};
use backend::domain::BlobId;
use common::*;
use serde_json::json;

async fn put_blob(h: &Harness, cookie: &str, content: &[u8]) -> common::Reply {
    let id = BlobId::of(content);
    h.send(common::Call {
        cookie: Some(cookie),
        body: content.to_vec(),
        content_type: Some("application/octet-stream"),
        ..h.call(Method::PUT, PHONE, format!("/api/v1/blobs/{id}"))
    })
    .await
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
        json!({ "id": id.to_string(), "size": 10, "created_at": "2026-10-09T20:57:00.000Z" })
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
