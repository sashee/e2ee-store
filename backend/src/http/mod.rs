//! The HTTP API (SPEC §8): routes, shared state and request helpers.

mod auth;
pub mod error;
mod guard;
mod me;
mod static_files;
mod storage;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use http_body_util::LengthLimitError;
use rusqlite::Connection;
use serde::de::DeserializeOwned;

use crate::config::Config;
use crate::db;
pub use error::ApiError;
pub use guard::{cookie_value, session_cookie};

/// JSON request bodies are limited to 64 KiB.
pub const JSON_LIMIT: u64 = 64 * 1024;

/// Milliseconds since the Unix epoch. A function so tests can move time.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    })
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub clock: Clock,
}

impl AppState {
    pub fn new(config: Config, clock: Clock) -> Self {
        Self {
            config: Arc::new(config),
            clock,
        }
    }

    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Runs `f` on its own connection, off the async runtime.
    pub async fn db<T, F>(&self, f: F) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let path = self.config.database.clone();
        tokio::task::spawn_blocking(move || db::open(&path).and_then(|mut conn| f(&mut conn)))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)
    }
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/setup-token", post(auth::exchange_setup_token))
        .route("/auth/logout", post(auth::logout))
        .route("/me", get(me::me))
        .route("/me/setup-tokens", post(me::create_setup_token))
        .route("/me/passkeys", get(me::list_passkeys))
        .route("/me/passkeys/register/start", post(me::register_start))
        .route("/me/passkeys/register/finish", post(me::register_finish))
        .route(
            "/me/passkeys/{id}",
            axum::routing::delete(me::delete_passkey),
        )
        .route("/blobs", get(storage::list_blobs))
        .route(
            "/blobs/{id}",
            get(storage::get_blob)
                .put(storage::put_blob)
                .delete(storage::delete_blob),
        )
        .route("/refs", get(storage::list_refs))
        .route(
            "/refs/{*name}",
            get(storage::get_ref)
                .put(storage::put_ref)
                .delete(storage::delete_ref),
        )
        .fallback(|| async { ApiError::not_found() })
        .layer(middleware::from_fn(api_headers));

    Router::new()
        .nest("/api/v1", api)
        .route("/healthz", get(|| async { "ok" }))
        .fallback(static_files::serve)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            guard::host_and_origin,
        ))
        .layer(middleware::from_fn(log_request))
        .with_state(state)
}

/// One line per request: method, path, host, status and how long it took, body upload included.
/// Never the query, headers or bodies, which can carry tokens.
async fn log_request(request: Request, next: Next) -> Response {
    let started = std::time::Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let response = next.run(request).await;
    tracing::info!(
        "{method} {path} host={host} status={} {}ms",
        response.status().as_u16(),
        started.elapsed().as_millis()
    );
    response
}

/// Every API response: never cached, never sniffed.
async fn api_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Reads a body of at most `limit` bytes, answering 413 above it.
pub async fn read_body(body: Body, limit: u64) -> Result<Bytes, ApiError> {
    axum::body::to_bytes(body, usize::try_from(limit).unwrap_or(usize::MAX))
        .await
        .map_err(|e| {
            let too_large =
                std::error::Error::source(&e).is_some_and(|s| s.is::<LengthLimitError>());
            if too_large {
                ApiError::too_large(limit)
            } else {
                ApiError::bad_request("Could not read the body")
            }
        })
}

fn content_type_is(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(expected))
}

/// A JSON body: `application/json` (415 otherwise), at most 64 KiB, and parseable as `T`.
pub async fn json_body<T: DeserializeOwned>(
    headers: &HeaderMap,
    body: Body,
) -> Result<T, ApiError> {
    if !content_type_is(headers, "application/json") {
        return Err(unsupported_media_type("application/json"));
    }
    let bytes = read_body(body, JSON_LIMIT).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad_request(format!("Invalid JSON body: {e}")))
}

pub fn unsupported_media_type(expected: &str) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
        format!("Expected Content-Type: {expected}"),
    )
}
