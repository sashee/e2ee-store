//! `/me/*`: the current user, self-service setup tokens and passkey management (SPEC §8.3).

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::auth::{store_ceremony, user_json};
use super::guard::Authed;
use super::{ApiError, AppState, json_body};
use crate::accounts::{issue_setup_token, setup_links};
use crate::domain::{Site, format_timestamp, valid_passkey_name};
use crate::passkey;
use crate::secret::{b64url, from_b64url};
use crate::store::{self, Passkey, PasskeyDeletion};

async fn current_user(state: &AppState, authed: &Authed) -> Result<store::User, ApiError> {
    let user_id = authed.session.user_id;
    state
        .db(move |c| store::user_by_id(c, &user_id))
        .await?
        .ok_or_else(ApiError::unauthenticated)
}

pub async fn me(State(state): State<AppState>, authed: Authed) -> Result<Json<Value>, ApiError> {
    Ok(Json(user_json(&current_user(&state, &authed).await?)))
}

pub async fn create_setup_token(
    State(state): State<AppState>,
    authed: Authed,
) -> Result<Response, ApiError> {
    authed.require_fresh(&state)?;
    // Only a session created with a passkey: a setup-token session creating setup tokens could renew itself
    // forever, invisibly, and survive the deletion of every passkey (SPEC §6.6).
    if authed.session.passkey_id.is_none() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "passkey_session_required",
            "Log in with a passkey to do this",
        ));
    }
    let user_id = authed.session.user_id;
    let now = state.now();
    let (token, expires_at) = state
        .db(move |c| issue_setup_token(c, &user_id, now))
        .await?;
    let links = setup_links(&state.config.public_hosts, &token);
    let body =
        json!({ "token": token, "expires_at": format_timestamp(expires_at), "links": links });
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

fn passkey_json(p: &Passkey, current: Option<&[u8]>) -> Value {
    json!({
        "id": b64url(&p.id),
        "name": p.name,
        "rp_id": p.rp_id,
        "created_at": format_timestamp(p.created_at),
        "last_used_at": p.last_used_at.map(format_timestamp),
        "current": current == Some(p.id.as_slice()),
    })
}

pub async fn list_passkeys(
    State(state): State<AppState>,
    authed: Authed,
) -> Result<Json<Value>, ApiError> {
    let user_id = authed.session.user_id;
    let passkeys = state.db(move |c| store::passkeys_of(c, &user_id)).await?;
    let current = authed.session.passkey_id.as_deref();
    Ok(Json(
        json!({ "passkeys": passkeys.iter().map(|p| passkey_json(p, current)).collect::<Vec<_>>() }),
    ))
}

pub async fn register_start(
    State(state): State<AppState>,
    site: Site,
    authed: Authed,
) -> Result<Json<Value>, ApiError> {
    authed.require_fresh(&state)?;
    let user = current_user(&state, &authed).await?;
    let user_id = user.id;
    let existing: Vec<Vec<u8>> = state
        .db(move |c| store::passkeys_of(c, &user_id))
        .await?
        .into_iter()
        .filter(|p| p.rp_id == site.rp_id)
        .map(|p| p.id)
        .collect();
    let started = passkey::start_registration(&site, user.id, &user.username, &existing)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(
        store_ceremony(&state, "register", Some(user.id), started).await?,
    ))
}

#[derive(Deserialize)]
struct RegisterFinish {
    name: String,
    credential: Value,
}

pub async fn register_finish(
    State(state): State<AppState>,
    site: Site,
    authed: Authed,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let RegisterFinish { name, credential } = json_body(&headers, body).await?;
    let name = name.trim().to_owned();
    if !valid_passkey_name(&name) {
        return Err(ApiError::bad_request(
            "The passkey name must be 1–64 characters",
        ));
    }
    let failed = |e: passkey::PasskeyError| {
        tracing::info!("passkey registration refused: {e}");
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "registration_failed",
            "The passkey could not be verified",
        )
    };
    let (challenge, registration) = passkey::parse_registration(&credential).map_err(failed)?;
    let user_id = authed.session.user_id;
    let now = state.now();
    let ceremony = state
        .db(move |c| store::take_ceremony(c, &challenge, now))
        .await?
        .filter(|c| c.kind == "register" && c.user_id == Some(user_id))
        .ok_or_else(|| {
            failed(passkey::PasskeyError::Refused(
                "no such registration ceremony for this user".into(),
            ))
        })?;
    let registered = passkey::finish_registration(&ceremony.state, &site, user_id, &registration)
        .map_err(failed)?;

    let passkey = Passkey {
        id: registered.credential_id,
        user_id,
        rp_id: site.rp_id.clone(),
        name,
        static_state: registered.static_state,
        dynamic_state: registered.dynamic_state,
        created_at: now,
        last_used_at: None,
    };
    let row = passkey.clone();
    if !state.db(move |c| store::insert_passkey(c, &row)).await? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "passkey_exists",
            "This passkey is already registered",
        ));
    }
    let current = authed.session.passkey_id.as_deref();
    Ok((
        StatusCode::CREATED,
        Json(json!({ "passkey": passkey_json(&passkey, current) })),
    )
        .into_response())
}

pub async fn delete_passkey(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    authed.require_fresh(&state)?;
    let id = from_b64url(&id).ok_or_else(ApiError::not_found)?;
    let user_id = authed.session.user_id;
    match state
        .db(move |c| store::delete_passkey(c, &user_id, &id))
        .await?
    {
        PasskeyDeletion::Deleted => Ok(StatusCode::NO_CONTENT.into_response()),
        PasskeyDeletion::NotFound => Err(ApiError::not_found()),
        PasskeyDeletion::LastPasskey => Err(ApiError::new(
            StatusCode::CONFLICT,
            "last_passkey",
            "Your last passkey can't be deleted",
        )),
    }
}
