//! Frontend files from `static_dir` (SPEC §8.6). `/` serves `index.html`; there is no fallback to it and
//! no directory listing. Paths are built only from validated segments, so nothing outside the directory
//! can be named.

use std::path::PathBuf;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::AppState;

/// `None` unless every segment is a plain file or directory name: no empty, dot-leading or odd segments.
pub fn file_path(url_path: &str) -> Option<PathBuf> {
    let path = url_path.strip_prefix('/')?;
    let path = if path.is_empty() { "index.html" } else { path };
    let segments: Vec<&str> = path.split('/').collect();
    let valid = segments.iter().all(|s| {
        !s.is_empty()
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    });
    valid.then(|| segments.iter().collect())
}

pub fn content_type(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
    {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

pub async fn serve(State(state): State<AppState>, request: Request) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some(relative) = file_path(request.uri().path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = state.config.static_dir.join(&relative);
    let content = match tokio::fs::metadata(&path).await {
        Ok(meta) if meta.is_file() => tokio::fs::read(&path).await.ok(),
        _ => None,
    };
    let Some(content) = content else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = content.into_response();
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(&path)),
    );
    if let Ok(csp) = HeaderValue::from_str(&state.config.static_csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, csp);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_paths_map_to_files() {
        assert_eq!(file_path("/"), Some(PathBuf::from("index.html")));
        assert_eq!(file_path("/js/main.js"), Some(PathBuf::from("js/main.js")));
        for refused in [
            "/../etc/passwd",
            "/a/../b",
            "/.git/config",
            "//a",
            "/a/",
            "/a%2fb",
            "relative",
            "/a b",
        ] {
            assert_eq!(file_path(refused), None, "{refused}");
        }
    }
}
