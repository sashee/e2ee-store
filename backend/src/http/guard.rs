//! Request guards: the host allowlist and origin check (SPEC §6.1), and the session (SPEC §6.4).

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::{ApiError, AppState};
use crate::domain::{Site, classify_host, is_fresh};
use crate::secret::token_hash;
use crate::store::{self, Session};

pub const SESSION_COOKIE: &str = "session";

/// Runs before everything else: the `Host` must be allowed, and requests that can change something must
/// carry this site's own `Origin`. The `Site` is handed on as a request extension.
pub async fn host_and_origin(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let Some(site) = classify_host(host, &state.config.public_hosts) else {
        return ApiError::new(
            StatusCode::BAD_REQUEST,
            "unknown_host",
            "This host is not served here",
        )
        .into_response();
    };
    let safe = matches!(*request.method(), Method::GET | Method::HEAD);
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|o| o.to_str().ok());
    if !safe && origin != Some(site.origin().as_str()) {
        return ApiError::new(StatusCode::FORBIDDEN, "forbidden", "Origin check failed")
            .into_response();
    }
    request.extensions_mut().insert(site);
    next.run(request).await
}

impl FromRequestParts<AppState> for Site {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Site>()
            .cloned()
            .ok_or_else(|| ApiError::internal("no Site on the request"))
    }
}

/// The value of one cookie in a `Cookie` header.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// `Set-Cookie` for a session; `max_age_secs = 0` clears it.
pub fn session_cookie(token: &str, max_age_secs: u64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}{secure}"
    )
}

/// The session cookie's token hash, if the request carries a well-formed one.
pub fn presented_session(headers: &axum::http::HeaderMap) -> Option<[u8; 32]> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|h| cookie_value(h, SESSION_COOKIE))
        .and_then(token_hash)
}

/// A request with a valid session.
pub struct Authed {
    pub session: Session,
}

impl Authed {
    /// Step-up (SPEC §6.5): the session must have been created within the reauth window.
    pub fn require_fresh(&self, state: &AppState) -> Result<(), ApiError> {
        if is_fresh(
            state.now(),
            self.session.created_at,
            state.config.reauth_window,
        ) {
            Ok(())
        } else {
            Err(ApiError::reauth_required())
        }
    }
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token_hash = presented_session(&parts.headers).ok_or_else(ApiError::unauthenticated)?;
        let now = state.now();
        let session = state
            .db(move |c| store::live_session(c, &token_hash, now))
            .await?;
        session
            .map(|session| Authed { session })
            .ok_or_else(ApiError::unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies() {
        assert_eq!(
            cookie_value("a=1; session=abc; b=2", "session"),
            Some("abc")
        );
        assert_eq!(cookie_value("xsession=abc", "session"), None);
        assert_eq!(
            session_cookie("t", 14400, false),
            "session=t; Path=/; HttpOnly; SameSite=Strict; Max-Age=14400"
        );
        assert!(session_cookie("t", 1, true).ends_with("; Secure"));
    }
}
