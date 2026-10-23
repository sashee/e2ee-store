//! A stand-in for S3 on 127.0.0.1, path-style, with what the backend uses: PUT (checking Content-MD5), GET with
//! ranges, DELETE and ListObjectsV2 in pages. Signatures aren't checked; the VM test runs against MinIO for that.
//! The objects are plain state the tests read and change, e.g. to lose one or to take S3 down.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use md5::{Digest as _, Md5};

pub const BUCKET: &str = "bucket";
pub const PREFIX: &str = "test/";

#[derive(Clone, Default)]
pub struct FakeS3 {
    pub objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    /// Every request: "PUT <key>", "GET <key> <range>", "DELETE <key>", "LIST <prefix>".
    pub requests: Arc<Mutex<Vec<String>>>,
    /// Everything answers 503.
    pub down: Arc<AtomicBool>,
    /// Keys per list page.
    pub page_size: Arc<AtomicUsize>,
    pub endpoint: String,
}

impl FakeS3 {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s3 = Self {
            endpoint: format!("http://{}", listener.local_addr().unwrap()),
            page_size: Arc::new(AtomicUsize::new(1000)),
            ..Self::default()
        };
        let app = Router::new().fallback(handle).with_state(s3.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        s3
    }

    /// The credential file for it.
    pub fn file(&self) -> String {
        format!(
            "endpoint = \"{}\"\nregion = \"test-1\"\nbucket = \"{BUCKET}\"\nprefix = \"{PREFIX}\"\naccess_key_id = \"id\"\nsecret_access_key = \"secret\"\n",
            self.endpoint
        )
    }

    pub fn keys(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }

    pub fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(key).cloned()
    }

    pub fn put(&self, key: &str, content: &[u8]) {
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_owned(), content.to_vec());
    }

    pub fn remove(&self, key: &str) {
        self.objects.lock().unwrap().remove(key);
    }

    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn log(&self, line: String) {
        self.requests.lock().unwrap().push(line);
    }
}

fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code></Error>"),
    )
        .into_response()
}

async fn handle(
    State(s3): State<FakeS3>,
    method: Method,
    uri: Uri,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if s3.down.load(Ordering::SeqCst) {
        return error(StatusCode::SERVICE_UNAVAILABLE, "SlowDown");
    }
    let Some(key) = uri.path().strip_prefix(&format!("/{BUCKET}/")) else {
        return error(StatusCode::NOT_FOUND, "NoSuchBucket");
    };
    match (method, key) {
        (Method::GET, "") if query.get("list-type").map(String::as_str) == Some("2") => {
            list(&s3, &query)
        }
        (Method::PUT, key) => {
            s3.log(format!("PUT {key}"));
            let md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(&body));
            if headers.get("content-md5").and_then(|v| v.to_str().ok()) != Some(md5.as_str()) {
                return error(StatusCode::BAD_REQUEST, "BadDigest");
            }
            s3.put(key, &body);
            (StatusCode::OK, [(header::ETAG, "\"etag\"")]).into_response()
        }
        (Method::GET, key) => {
            let range = headers
                .get(header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            s3.log(format!("GET {key} {}", range.as_deref().unwrap_or("all")));
            let Some(content) = s3.object(key) else {
                return error(StatusCode::NOT_FOUND, "NoSuchKey");
            };
            let total = content.len();
            match range.and_then(|r| {
                let (start, end) = r.strip_prefix("bytes=")?.split_once('-')?;
                Some((start.parse::<usize>().ok()?, end.parse::<usize>().ok()?))
            }) {
                Some((start, end)) if start <= end && end < total => (
                    StatusCode::PARTIAL_CONTENT,
                    [(
                        header::CONTENT_RANGE,
                        format!("bytes {start}-{end}/{total}"),
                    )],
                    content[start..=end].to_vec(),
                )
                    .into_response(),
                Some(_) => error(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange"),
                None => (StatusCode::OK, content).into_response(),
            }
        }
        (Method::DELETE, key) => {
            s3.log(format!("DELETE {key}"));
            s3.remove(key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

/// ListObjectsV2: the keys under `prefix` after `continuation-token`, a page at a time.
fn list(s3: &FakeS3, query: &BTreeMap<String, String>) -> Response {
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    s3.log(format!("LIST {prefix}"));
    let after = query.get("continuation-token").cloned().unwrap_or_default();
    let page_size = s3.page_size.load(Ordering::SeqCst);
    let objects = s3.objects.lock().unwrap();
    let matching: Vec<(&String, &Vec<u8>)> = objects
        .iter()
        .filter(|(key, _)| key.starts_with(&prefix) && **key > after)
        .collect();
    let page = &matching[..matching.len().min(page_size)];
    let contents: String = page
        .iter()
        .map(|(key, content)| {
            format!(
                "<Contents><Key>{key}</Key><LastModified>2026-10-23T00:00:00.000Z</LastModified><ETag>\"etag\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                content.len()
            )
        })
        .collect();
    let next = match page.last() {
        Some((key, _)) if matching.len() > page.len() => {
            format!("<NextContinuationToken>{key}</NextContinuationToken>")
        }
        _ => String::new(),
    };
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{BUCKET}</Name><Prefix>{prefix}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{page_size}</MaxKeys><IsTruncated>{}</IsTruncated>{contents}{next}</ListBucketResult>",
        page.len(),
        !next.is_empty()
    );
    (StatusCode::OK, body).into_response()
}
