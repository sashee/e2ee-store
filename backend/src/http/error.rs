//! API errors: `{"error": "<code>", "message": "<human readable>"}` plus optional extra fields (SPEC §8).

use std::fmt::Display;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub extra: Map<String, Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            extra: Map::new(),
        }
    }

    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_owned(), value);
        self
    }

    /// Logged in full, reported without detail.
    pub fn internal(e: impl Display) -> Self {
        tracing::error!("internal error: {e}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal error",
        )
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "Not found")
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "No valid session",
        )
    }

    pub fn authentication_failed(detail: impl Display) -> Self {
        tracing::info!("passkey login refused: {detail}");
        Self::new(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "Passkey login failed",
        )
    }

    pub fn reauth_required() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "reauth_required",
            "Log in again to do this",
        )
    }

    /// An offloadable blob whose content S3 has lost (SPEC §7.4).
    pub fn blob_lost() -> Self {
        Self::new(StatusCode::GONE, "blob_lost", "The blob's content is lost")
    }

    /// S3 can't be reached; logged in full, reported without detail.
    pub fn storage_unavailable(detail: impl Display) -> Self {
        tracing::warn!("S3 is unavailable: {detail}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "The storage is unavailable; try again later",
        )
    }

    /// The database's file system would drop below `min_free_space` (SPEC §7.5); logged in full.
    pub fn storage_full(needed: u64, free: u64) -> Self {
        tracing::warn!("the disk is too full: {needed} bytes needed free, {free} are");
        Self::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "storage_full",
            "The server's disk is too full for this",
        )
    }

    pub fn too_large(limit: u64) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "blob_too_large",
            format!("The body is larger than {limit} bytes"),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = self.extra;
        body.insert("error".into(), Value::from(self.code));
        body.insert("message".into(), Value::from(self.message));
        (self.status, Json(Value::Object(body))).into_response()
    }
}
