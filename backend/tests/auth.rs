//! Users, passkeys, sessions, setup tokens and the host/origin checks, through the HTTP API.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

const HOUR: i64 = 3600 * 1000;
const MINUTE: i64 = 60 * 1000;

#[tokio::test]
async fn a_setup_token_gives_a_session_once() {
    let h = Harness::new();
    let token = h.create_user("alice");
    let first = h
        .post_json(
            PHONE,
            "/api/v1/auth/setup-token",
            None,
            json!({ "token": token }),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json()["user"]["username"], "alice");
    let set_cookie = first.header("set-cookie").unwrap();
    assert!(
        set_cookie.contains("HttpOnly")
            && set_cookie.contains("SameSite=Strict")
            && set_cookie.contains("Max-Age=14400")
    );
    assert!(
        !set_cookie.contains("Secure"),
        "no Secure on a loopback host: {set_cookie}"
    );

    let me = h.get(PHONE, "/api/v1/me", &first.cookie()).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["username"], "alice");

    let again = h
        .post_json(
            PHONE,
            "/api/v1/auth/setup-token",
            None,
            json!({ "token": token }),
        )
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert_eq!(again.json()["error"], "invalid_token");
}

#[tokio::test]
async fn setup_tokens_expire_after_15_minutes() {
    let h = Harness::new();
    let token = h.create_user("alice");
    h.advance(15 * MINUTE);
    let reply = h
        .post_json(
            PHONE,
            "/api/v1/auth/setup-token",
            None,
            json!({ "token": token }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "invalid_token");
    let garbage = h
        .post_json(
            PHONE,
            "/api/v1/auth/setup-token",
            None,
            json!({ "token": "nope" }),
        )
        .await;
    assert_eq!(garbage.json()["error"], "invalid_token");
}

#[tokio::test]
async fn sessions_expire_after_4_hours_and_logout_ends_them() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    h.advance(4 * HOUR - 1);
    assert_eq!(
        h.get(PHONE, "/api/v1/me", &cookie).await.status,
        StatusCode::OK
    );
    h.advance(1);
    let expired = h.get(PHONE, "/api/v1/me", &cookie).await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert_eq!(expired.json()["error"], "unauthenticated");

    let cookie = h
        .post_json(
            PHONE,
            "/api/v1/auth/setup-token",
            None,
            json!({ "token": h.setup_token_for("alice") }),
        )
        .await
        .cookie();
    let logout = h
        .post_json(PHONE, "/api/v1/auth/logout", Some(&cookie), json!({}))
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    assert!(logout.header("set-cookie").unwrap().contains("Max-Age=0"));
    assert_eq!(
        h.get(PHONE, "/api/v1/me", &cookie).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_passkey_registers_and_logs_in_despite_unrequested_prf() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let phone = Authenticator::new(1);
    assert!(
        phone.prf,
        "the authenticator sends prf and hmac-secret the server never requested"
    );

    let registered = h.register(PHONE, &cookie, &phone, "Phone").await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&registered.body)
    );
    let passkey = &registered.json()["passkey"];
    assert_eq!(passkey["rp_id"], "6c4b9e.localhost");
    assert_eq!(passkey["name"], "Phone");
    assert_eq!(passkey["id"], phone.id());

    let login = h
        .login(PHONE, &phone, &h.user_handle("alice"), Some(&cookie))
        .await;
    assert_eq!(
        login.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&login.body)
    );
    assert_eq!(login.json()["user"]["username"], "alice");
    let new_cookie = login.cookie();
    assert_eq!(
        h.get(PHONE, "/api/v1/me", &cookie).await.status,
        StatusCode::UNAUTHORIZED,
        "the old session is replaced"
    );

    let list = h
        .get(PHONE, "/api/v1/me/passkeys", &new_cookie)
        .await
        .json();
    assert_eq!(list["passkeys"][0]["current"], true);
    assert!(list["passkeys"][0]["last_used_at"].is_string());
}

#[tokio::test]
async fn a_passkey_without_prf_works_too() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", LAPTOP).await;
    let key = Authenticator {
        prf: false,
        ..Authenticator::new(2)
    };
    assert_eq!(
        h.register(LAPTOP, &cookie, &key, "Key").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        h.login(LAPTOP, &key, &h.user_handle("alice"), None)
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_passkey_works_only_on_its_own_host() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let phone = Authenticator::new(1);
    h.register(PHONE, &cookie, &phone, "Phone").await;

    // The authenticator signs for the laptop's RP ID, but the passkey was registered for the phone's.
    let elsewhere = h.login(LAPTOP, &phone, &h.user_handle("alice"), None).await;
    assert_eq!(elsewhere.status, StatusCode::UNAUTHORIZED);
    assert_eq!(elsewhere.json()["error"], "authentication_failed");
}

#[tokio::test]
async fn a_ceremony_answers_once_and_only_on_its_host_and_port() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let phone = Authenticator::new(1);
    h.register(PHONE, &cookie, &phone, "Phone").await;
    let handle = h.user_handle("alice");

    let start = h
        .post_json(PHONE, "/api/v1/auth/login/start", None, json!({}))
        .await
        .json();
    let credential = phone.sign(
        &start["options"],
        &origin_of(PHONE),
        "6c4b9e.localhost",
        &handle,
    );
    // Finished from another port: the client data names the phone's origin, which doesn't match.
    let other_port = h
        .post_json(
            "6c4b9e.localhost:9999",
            "/api/v1/auth/login/finish",
            None,
            json!({ "credential": credential }),
        )
        .await;
    assert_eq!(other_port.status, StatusCode::UNAUTHORIZED);
    // And the ceremony is gone, even though that attempt failed.
    let retry = h
        .post_json(
            PHONE,
            "/api/v1/auth/login/finish",
            None,
            json!({ "credential": credential }),
        )
        .await;
    assert_eq!(retry.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unknown_credential_or_impostor_is_refused() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    h.register(PHONE, &cookie, &Authenticator::new(1), "Phone")
        .await;
    let stranger = Authenticator::new(9);
    assert_eq!(
        h.login(PHONE, &stranger, &h.user_handle("alice"), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let impostor = Authenticator {
        credential_id: Authenticator::new(1).credential_id,
        ..Authenticator::new(9)
    };
    assert_eq!(
        h.login(PHONE, &impostor, &h.user_handle("alice"), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn step_up_is_required_after_5_minutes() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    h.advance(5 * MINUTE);
    for uri in [
        "/api/v1/me/passkeys/register/start",
        "/api/v1/me/setup-tokens",
    ] {
        let reply = h.post_json(PHONE, uri, Some(&cookie), json!({})).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(reply.json()["error"], "reauth_required");
    }
    // Reading still works.
    assert_eq!(
        h.get(PHONE, "/api/v1/me/passkeys", &cookie).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn users_create_setup_tokens_for_themselves() {
    let h = Harness::new();
    let setup_cookie = h.signed_up("alice", PHONE).await;
    let phone = Authenticator::new(1);
    h.register(PHONE, &setup_cookie, &phone, "Phone").await;
    let cookie = h
        .login(PHONE, &phone, &h.user_handle("alice"), None)
        .await
        .cookie();
    let reply = h
        .post_json(PHONE, "/api/v1/me/setup-tokens", Some(&cookie), json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let body = reply.json();
    let token = body["token"].as_str().unwrap();
    assert_eq!(
        body["links"],
        json!([format!("https://{PUBLIC}/#setup={token}")])
    );

    // Used on the public host: the cookie is Secure there.
    let exchanged = h
        .post_json(
            PUBLIC,
            "/api/v1/auth/setup-token",
            None,
            json!({ "token": token }),
        )
        .await;
    assert_eq!(exchanged.status, StatusCode::OK);
    assert!(
        exchanged
            .header("set-cookie")
            .unwrap()
            .ends_with("; Secure")
    );
}

#[tokio::test]
async fn deleting_passkeys_keeps_the_last_one_and_revokes_its_sessions() {
    let h = Harness::new();
    let setup_cookie = h.signed_up("alice", PHONE).await;
    let (a, b) = (Authenticator::new(1), Authenticator::new(2));
    h.register(PHONE, &setup_cookie, &a, "A").await;
    h.register(PHONE, &setup_cookie, &b, "B").await;
    let handle = h.user_handle("alice");
    let a_cookie = h.login(PHONE, &a, &handle, None).await.cookie();
    let b_cookie = h.login(PHONE, &b, &handle, None).await.cookie();

    let deleted = h
        .delete(PHONE, &format!("/api/v1/me/passkeys/{}", a.id()), &b_cookie)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.get(PHONE, "/api/v1/me", &a_cookie).await.status,
        StatusCode::UNAUTHORIZED,
        "sessions from A are gone"
    );
    assert_eq!(
        h.get(PHONE, "/api/v1/me", &b_cookie).await.status,
        StatusCode::OK
    );

    let last = h
        .delete(PHONE, &format!("/api/v1/me/passkeys/{}", b.id()), &b_cookie)
        .await;
    assert_eq!(last.status, StatusCode::CONFLICT);
    assert_eq!(last.json()["error"], "last_passkey");
    let missing = h
        .delete(PHONE, &format!("/api/v1/me/passkeys/{}", a.id()), &b_cookie)
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn registering_the_same_authenticator_twice_is_refused() {
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let phone = Authenticator::new(1);
    h.register(PHONE, &cookie, &phone, "Phone").await;
    let start = h
        .post_json(
            PHONE,
            "/api/v1/me/passkeys/register/start",
            Some(&cookie),
            json!({}),
        )
        .await
        .json();
    assert_eq!(start["options"]["excludeCredentials"][0]["id"], phone.id());
    let again = h.register(PHONE, &cookie, &phone, "Again").await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.json()["error"], "passkey_exists");
}

#[tokio::test]
async fn hosts_and_origins_are_checked() {
    let h = Harness::new();
    for host in [
        "127.0.0.1:8080",
        "evil.example.com",
        "localhost.example.com",
    ] {
        let reply = h.send(h.call(Method::GET, host, "/healthz")).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{host}");
        assert_eq!(reply.json()["error"], "unknown_host");
    }
    let token = h.create_user("alice");
    let body = json!({ "token": token }).to_string().into_bytes();
    let call = |origin: Option<String>| common::Call {
        origin,
        body: body.clone(),
        content_type: Some("application/json"),
        ..h.call(Method::POST, LAPTOP, "/api/v1/auth/setup-token")
    };
    for origin in [
        None,
        Some("http://localhost:3000".into()),
        Some("https://localhost:8080".into()),
        Some("null".into()),
    ] {
        let reply = h.send(call(origin.clone())).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert_eq!(reply.json()["error"], "forbidden");
    }
    // None of those consumed the token.
    assert_eq!(
        h.send(call(Some("http://localhost:8080".into())))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn json_endpoints_need_json() {
    let h = Harness::new();
    let token = h.create_user("alice");
    let reply = h
        .send(common::Call {
            body: json!({ "token": token }).to_string().into_bytes(),
            content_type: Some("text/plain"),
            ..h.call(Method::POST, LAPTOP, "/api/v1/auth/setup-token")
        })
        .await;
    assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let big = h
        .post_json(
            LAPTOP,
            "/api/v1/auth/setup-token",
            None,
            json!({ "token": "x".repeat(70_000) }),
        )
        .await;
    assert_eq!(big.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn expired_rows_are_purged() {
    let h = Harness::new();
    let _ = h.signed_up("alice", PHONE).await;
    h.create_user("bob");
    h.post_json(PHONE, "/api/v1/auth/login/start", None, json!({}))
        .await;
    h.advance(5 * HOUR);
    let purged = backend::store::purge_expired(&h.conn(), h.now()).unwrap();
    assert_eq!(purged, 3, "a session, bob's setup token and a ceremony");
}

#[tokio::test]
async fn only_passkey_sessions_create_setup_tokens() {
    // A session from a setup token could otherwise mint the next setup token, and so on, forever.
    let h = Harness::new();
    let cookie = h.signed_up("alice", PHONE).await;
    let reply = h
        .post_json(PHONE, "/api/v1/me/setup-tokens", Some(&cookie), json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json()["error"], "passkey_session_required");
}
