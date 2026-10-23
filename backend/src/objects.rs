//! The S3 store for offloadable blobs (SPEC §7.4): the credential file, object keys and the requests. rusty-s3
//! signs them, reqwest sends them. Nothing here knows about the database; `offload` does the moving.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use axum::body::Bytes;
use base64::Engine as _;
use md5::{Digest as _, Md5};
use reqwest::{Response, StatusCode, header};
use rusty_s3::actions::{ListObjectsV2, S3Action as _};
use rusty_s3::{Bucket, Credentials, UrlStyle};
use serde::Deserialize;

use crate::domain::{BlobId, format_uuid, hex_decode};
use crate::store::{S3Location, UserId};

/// A signed request only has to start within this.
const SIGNED_FOR: Duration = Duration::from_secs(15 * 60);

/// How long S3 may take to accept a connection, and to send the next bytes of a response: past them, it counts as
/// unavailable.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub connect: Duration,
    pub read: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(60),
        }
    }
}

/// The S3 credential file (SPEC §10.1): all of it is secret, so it isn't part of the configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct S3File {
    endpoint: String,
    region: String,
    bucket: String,
    prefix: String,
    access_key_id: String,
    secret_access_key: String,
    url_style: Option<String>,
}

/// The bucket, the credentials and an HTTP client: everything a request needs.
pub struct Objects {
    bucket: Bucket,
    credentials: Credentials,
    location: S3Location,
    http: reqwest::Client,
}

/// Nothing of the credential file: none of it goes in a log.
impl std::fmt::Debug for Objects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Objects").finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ObjectError {
    NotFound,
    /// S3 couldn't be reached, or answered with something else than asked for.
    Unavailable(String),
}

impl std::fmt::Display for ObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no such object"),
            Self::Unavailable(why) => write!(f, "S3 is unavailable: {why}"),
        }
    }
}

fn unavailable(e: impl std::fmt::Display) -> ObjectError {
    ObjectError::Unavailable(e.to_string())
}

/// A request that failed, without its URL: a signed one names the endpoint, the bucket and the key ID, and lets
/// anyone holding it make that request for a while.
fn failed(e: reqwest::Error) -> ObjectError {
    let e = e.without_url();
    // The causes say what went wrong: refused, timed out, a certificate not trusted.
    let causes = std::iter::successors(std::error::Error::source(&e), |cause| cause.source());
    let chain: Vec<String> = std::iter::once(e.to_string())
        .chain(causes.map(ToString::to_string))
        .collect();
    unavailable(chain.join(": "))
}

impl Objects {
    /// From the credential file's contents.
    pub fn from_file(text: &str) -> anyhow::Result<Self> {
        Self::with_timeouts(text, Timeouts::default())
    }

    pub fn with_timeouts(text: &str, timeouts: Timeouts) -> anyhow::Result<Self> {
        let file: S3File = toml::from_str(text)?;
        let url_style = match file.url_style.as_deref() {
            None | Some("path") => UrlStyle::Path,
            Some("virtual-host") => UrlStyle::VirtualHost,
            Some(other) => bail!("url_style: {other:?} is neither \"path\" nor \"virtual-host\""),
        };
        if file.prefix.is_empty() || file.prefix.starts_with('/') {
            bail!("prefix: one of its own per instance, e.g. \"music/\", not starting with /");
        }
        let endpoint: url::Url = file.endpoint.parse().context("endpoint")?;
        let https = endpoint.scheme() == "https";
        let bucket = Bucket::new(endpoint, url_style, file.bucket.clone(), file.region)
            .map_err(|e| anyhow!("bucket: {e}"))?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls(https)?)
            .no_proxy()
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .build()?;
        Ok(Self {
            bucket,
            credentials: Credentials::new(file.access_key_id, file.secret_access_key),
            location: S3Location {
                endpoint: file.endpoint,
                bucket: file.bucket,
                prefix: file.prefix,
            },
            http,
        })
    }

    pub fn location(&self) -> &S3Location {
        &self.location
    }

    /// `<prefix><user ID>/<blob ID>`.
    pub fn key(&self, user_id: &UserId, id: BlobId) -> String {
        format!("{}{}/{id}", self.location.prefix, format_uuid(user_id))
    }

    /// The user and blob of a key `key` makes; None for anything else.
    pub fn parse_key(&self, key: &str) -> Option<(UserId, BlobId)> {
        let (user, id) = key.strip_prefix(&self.location.prefix)?.split_once('/')?;
        let user_id: UserId = hex_decode(&user.replace('-', ""))?.try_into().ok()?;
        let id = BlobId::parse(id)?;
        (format_uuid(&user_id) == user).then_some((user_id, id))
    }

    /// Stores an object. `Content-MD5` makes S3 refuse it if it arrives damaged.
    pub async fn put(&self, key: &str, content: Bytes) -> Result<(), ObjectError> {
        let url = self
            .bucket
            .put_object(Some(&self.credentials), key)
            .sign(SIGNED_FOR);
        let md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(&content));
        let response = self
            .http
            .put(url)
            .header("content-md5", md5)
            .body(content)
            .send()
            .await
            .map_err(failed)?;
        expect(response, &[StatusCode::OK]).await.map(drop)
    }

    /// An object's bytes [start, end] (inclusive, as in `Range`), or all of them, as they arrive. Checks that S3
    /// sends exactly what was asked for: `expected` is the length of the whole object.
    pub async fn get(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
        expected: u64,
    ) -> Result<Response, ObjectError> {
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGNED_FOR);
        let request = self.http.get(url);
        let request = match range {
            Some((start, end)) => request.header(header::RANGE, format!("bytes={start}-{end}")),
            None => request,
        };
        let status = if range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        };
        let response = expect(request.send().await.map_err(failed)?, &[status]).await?;
        // A proxy may leave the length out; a body shorter than the length the server promises its client fails
        // that response anyway.
        let length = range.map_or(expected, |(start, end)| end - start + 1);
        let content_range = range.map(|(start, end)| format!("bytes {start}-{end}/{expected}"));
        let header = |name| response.headers().get(name).and_then(|v| v.to_str().ok());
        let same_length = header(header::CONTENT_LENGTH).is_none_or(|l| l == length.to_string());
        if !same_length || header(header::CONTENT_RANGE) != content_range.as_deref() {
            return Err(unavailable(
                "an object came back with other bytes than asked for",
            ));
        }
        Ok(response)
    }

    /// All of an object, in memory.
    pub async fn get_all(&self, key: &str, expected: u64) -> Result<Bytes, ObjectError> {
        let content = self
            .get(key, None, expected)
            .await?
            .bytes()
            .await
            .map_err(failed)?;
        if content.len() as u64 != expected {
            return Err(unavailable("an object came back short"));
        }
        Ok(content)
    }

    /// Deletes an object; one that is already gone counts as deleted.
    pub async fn delete(&self, key: &str) -> Result<(), ObjectError> {
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(SIGNED_FOR);
        let response = self.http.delete(url).send().await.map_err(failed)?;
        expect(response, &[StatusCode::NO_CONTENT, StatusCode::OK])
            .await
            .map(drop)
    }

    /// Every key under the prefix.
    pub async fn list(&self) -> Result<Vec<String>, ObjectError> {
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
            action.with_prefix(self.location.prefix.as_str());
            if let Some(token) = &token {
                action.with_continuation_token(token.as_str());
            }
            let url = action.sign(SIGNED_FOR);
            let response = expect(
                self.http.get(url).send().await.map_err(failed)?,
                &[StatusCode::OK],
            )
            .await?;
            let text = response.text().await.map_err(failed)?;
            let page = ListObjectsV2::parse_response(&text)
                .map_err(|_| unavailable("the object list doesn't parse"))?;
            keys.extend(page.contents.into_iter().map(|object| object.key));
            match page.next_continuation_token {
                Some(next) => token = Some(next),
                None => return Ok(keys),
            }
        }
    }
}

/// TLS on ring, which builds with nothing but cc, trusting the system's CA certificates (`SSL_CERT_FILE` when set).
/// Without any, only plain HTTP works: worth a warning when the endpoint is HTTPS, not a refusal to start.
fn tls(https: bool) -> anyhow::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if https && roots.is_empty() {
        tracing::warn!("no CA certificates found (SSL_CERT_FILE): S3 over HTTPS will fail");
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// The response if its status is one of `ok`; 404 is `NotFound`, anything else `Unavailable`.
async fn expect(response: Response, ok: &[StatusCode]) -> Result<Response, ObjectError> {
    let status = response.status();
    if ok.contains(&status) {
        return Ok(response);
    }
    if status == StatusCode::NOT_FOUND {
        return Err(ObjectError::NotFound);
    }
    // S3's error bodies are short XML documents saying why, which can name the bucket and the key: only their code
    // goes in the log.
    let body = response.text().await.unwrap_or_default();
    let code = body
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map_or("", |(code, _)| code);
    Err(ObjectError::Unavailable(format!("HTTP {status} {code}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
endpoint = "https://s3.example.com"
region = "eu-1"
bucket = "music"
prefix = "music/"
access_key_id = "id"
secret_access_key = "secret"
"#;

    #[test]
    fn the_credential_file_is_checked() {
        let objects = Objects::from_file(FILE).unwrap();
        assert_eq!(
            objects.location(),
            &S3Location {
                endpoint: "https://s3.example.com".into(),
                bucket: "music".into(),
                prefix: "music/".into(),
            }
        );
        let with = |line: &str| Objects::from_file(&format!("{FILE}{line}"));
        assert!(with("url_style = \"virtual-host\"").is_ok());
        assert!(with("url_style = \"other\"").is_err());
        assert!(with("extra = 1").is_err());
        assert!(Objects::from_file(&FILE.replace("\"music/\"", "\"\"")).is_err());
        assert!(Objects::from_file(&FILE.replace("\"music/\"", "\"/music\"")).is_err());
        assert!(
            Objects::from_file(&FILE.replace("https://s3.example.com", "s3.example.com")).is_err()
        );
        assert!(Objects::from_file(&FILE.replace("access_key_id = \"id\"\n", "")).is_err());
    }

    #[test]
    fn keys_name_the_user_and_the_blob() {
        let objects = Objects::from_file(FILE).unwrap();
        let user = [0xab; 16];
        let id = BlobId::of(b"x");
        let key = objects.key(&user, id);
        assert_eq!(
            key,
            format!("music/abababab-abab-abab-abab-abababababab/{id}")
        );
        assert_eq!(objects.parse_key(&key), Some((user, id)));
        for other in [
            format!("other/abababab-abab-abab-abab-abababababab/{id}"),
            format!("music/abababababababababababababababab/{id}"),
            format!("music/ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB/{id}"),
            "music/abababab-abab-abab-abab-abababababab/xyz".to_owned(),
            format!("music/abababab-abab-abab-abab-abababababab/{id}/more"),
            "music/".to_owned(),
        ] {
            assert_eq!(objects.parse_key(&other), None, "{other}");
        }
    }
}
