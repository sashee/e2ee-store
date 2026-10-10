//! `/auth/*`: passkey login, setup-token exchange and logout (SPEC §8.2).

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::guard::presented_session;
use super::{ApiError, AppState, json_body, session_cookie};
use crate::accounts::CEREMONY_TTL_MS;
use crate::domain::{Site, duration_ms, format_timestamp, format_uuid};
use crate::passkey::{self, Assertion, StoredCredential};
use crate::secret::{new_token, token_hash};
use crate::store::{self, Ceremony, Session, User, UserId};

pub fn user_json(user: &User) -> Value {
    json!({ "id": format_uuid(&user.id), "username": user.username, "created_at": format_timestamp(user.created_at) })
}

/// Stores a started ceremony. It expires after 5 minutes, or earlier if the library says so.
pub async fn store_ceremony(
    state: &AppState,
    kind: &'static str,
    user_id: Option<UserId>,
    started: passkey::Started,
) -> Result<Value, ApiError> {
    let now = state.now();
    let ceremony = Ceremony {
        kind: kind.to_owned(),
        user_id,
        state: started.state,
        created_at: now,
        expires_at: (now + CEREMONY_TTL_MS).min(started.expires_at),
    };
    let challenge = started.challenge;
    state
        .db(move |c| store::insert_ceremony(c, &challenge, &ceremony))
        .await?;
    Ok(json!({ "options": started.options }))
}

pub async fn login_start(
    State(state): State<AppState>,
    site: Site,
) -> Result<Json<Value>, ApiError> {
    let started = passkey::start_login(&site).map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(store_ceremony(&state, "login", None, started).await?))
}

#[derive(Deserialize)]
struct LoginFinish {
    credential: Value,
}

pub async fn login_finish(
    State(state): State<AppState>,
    site: Site,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let LoginFinish { credential } = json_body(&headers, body).await?;
    let assertion = Assertion::parse(&credential).map_err(ApiError::authentication_failed)?;
    let challenge = assertion
        .challenge()
        .map_err(ApiError::authentication_failed)?;
    let credential_id = assertion.credential_id();
    let now = state.now();

    // The ceremony is taken out before anything is checked, so a challenge answers exactly one response.
    let (ceremony, passkey) = state
        .db(move |c| {
            Ok((
                store::take_ceremony(c, &challenge, now)?,
                store::passkey_by_id(c, &credential_id)?,
            ))
        })
        .await?;
    let ceremony = ceremony
        .filter(|c| c.kind == "login")
        .ok_or_else(|| ApiError::authentication_failed("no such login ceremony"))?;
    let passkey = passkey.ok_or_else(|| ApiError::authentication_failed("unknown credential"))?;
    if passkey.rp_id != site.rp_id {
        return Err(ApiError::authentication_failed(format!(
            "passkey belongs to {}, not {}",
            passkey.rp_id, site.rp_id
        )));
    }
    let stored = StoredCredential {
        id: &passkey.id,
        user_id: passkey.user_id,
        static_state: &passkey.static_state,
        dynamic_state: &passkey.dynamic_state,
    };
    let changed = passkey::finish_login(&ceremony.state, &site, &assertion, &stored)
        .map_err(ApiError::authentication_failed)?;

    let previous = presented_session(&headers);
    let passkey_id = passkey.id.clone();
    let user_id = passkey.user_id;
    let (cookie, user) = start_session(
        &state,
        &site,
        user_id,
        Some(passkey_id.clone()),
        previous,
        move |c| store::record_passkey_use(c, &passkey_id, changed.as_deref(), now),
    )
    .await?;
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "user": user_json(&user) })),
    )
        .into_response())
}

#[derive(Deserialize)]
struct SetupTokenExchange {
    token: String,
}

pub async fn exchange_setup_token(
    State(state): State<AppState>,
    site: Site,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let SetupTokenExchange { token } = json_body(&headers, body).await?;
    let invalid = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "This setup token is unknown, expired or already used",
        )
    };
    let hash = token_hash(&token).ok_or_else(invalid)?;
    let now = state.now();
    let user_id = state
        .db(move |c| store::take_setup_token(c, &hash, now))
        .await?
        .ok_or_else(invalid)?;
    let (cookie, user) = start_session(
        &state,
        &site,
        user_id,
        None,
        presented_session(&headers),
        |_| Ok(()),
    )
    .await?;
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "user": user_json(&user) })),
    )
        .into_response())
}

/// Creates a session (replacing `previous`, if any) after running `also` in the same database call.
async fn start_session(
    state: &AppState,
    site: &Site,
    user_id: UserId,
    passkey_id: Option<Vec<u8>>,
    previous: Option<[u8; 32]>,
    also: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<()> + Send + 'static,
) -> Result<(String, User), ApiError> {
    let now = state.now();
    let ttl = state.config.session_ttl;
    let (token, hash) = new_token();
    let session = Session {
        user_id,
        passkey_id,
        created_at: now,
        expires_at: now + duration_ms(ttl),
    };
    let user = state
        .db(move |c| {
            let tx = c.transaction()?;
            also(&tx)?;
            if let Some(previous) = previous {
                store::delete_session(&tx, &previous)?;
            }
            store::insert_session(&tx, &hash, &session)?;
            let user = store::user_by_id(&tx, &user_id)?;
            tx.commit()?;
            Ok(user)
        })
        .await?
        .ok_or_else(|| ApiError::internal("session for a missing user"))?;
    Ok((session_cookie(&token, ttl.as_secs(), site.secure), user))
}

pub async fn logout(
    State(state): State<AppState>,
    site: Site,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(hash) = presented_session(&headers) {
        state.db(move |c| store::delete_session(c, &hash)).await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session_cookie("", 0, site.secure))],
    )
        .into_response())
}
