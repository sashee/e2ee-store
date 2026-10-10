//! Test harness: the router over a temporary database, a movable clock, and a software authenticator.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use backend::config::{Config, DEFAULT_STATIC_CSP};
use backend::http::{AppState, router};
use backend::{accounts, db, store};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

pub const PHONE: &str = "6c4b9e.localhost:24038";
pub const LAPTOP: &str = "localhost:8080";
pub const PUBLIC: &str = "pw.example.com";
pub const START: i64 = 1_791_579_420_000;

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub state: AppState,
    pub app: Router,
    clock: Arc<AtomicI64>,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&self.body)))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The session token from `Set-Cookie`.
    pub fn cookie(&self) -> String {
        let set = self.header("set-cookie").unwrap_or_else(|| {
            panic!(
                "no Set-Cookie: {} {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        });
        backend::http::cookie_value(set.split(';').next().unwrap(), "session")
            .unwrap()
            .to_owned()
    }
}

/// A request as a browser on `host` sends it: `Origin` matches on anything but GET/HEAD.
pub struct Call<'a> {
    pub method: Method,
    pub host: &'a str,
    pub uri: String,
    pub cookie: Option<&'a str>,
    pub headers: Vec<(&'a str, String)>,
    pub body: Vec<u8>,
    pub content_type: Option<&'a str>,
    pub origin: Option<String>,
}

impl Harness {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let static_dir = dir.path().join("static");
        std::fs::create_dir_all(static_dir.join("js")).unwrap();
        std::fs::write(
            static_dir.join("index.html"),
            "<!doctype html><title>app</title>",
        )
        .unwrap();
        std::fs::write(static_dir.join("js/main.js"), "console.log(1)").unwrap();
        let config = Config {
            socket: dir.path().join("backend.sock"),
            database: dir.path().join("backend.sqlite3"),
            static_dir,
            static_csp: DEFAULT_STATIC_CSP.into(),
            public_hosts: vec![PUBLIC.into()],
            rp_name: "Test".into(),
            session_ttl: std::time::Duration::from_secs(4 * 3600),
            reauth_window: std::time::Duration::from_secs(300),
            max_blob_size: 1024,
        };
        db::open_and_migrate(&config.database).unwrap();
        let clock = Arc::new(AtomicI64::new(START));
        let read = clock.clone();
        let state = AppState::new(config, Arc::new(move || read.load(Ordering::SeqCst)));
        Self {
            app: router(state.clone()),
            state,
            dir,
            clock,
        }
    }

    pub fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    pub fn conn(&self) -> rusqlite::Connection {
        db::open(&self.state.config.database).unwrap()
    }

    pub fn call<'a>(&self, method: Method, host: &'a str, uri: impl Into<String>) -> Call<'a> {
        let scheme = if host == PUBLIC { "https" } else { "http" };
        Call {
            origin: Some(format!("{scheme}://{host}")),
            method,
            host,
            uri: uri.into(),
            cookie: None,
            headers: vec![],
            body: vec![],
            content_type: None,
        }
    }

    pub async fn send(&self, call: Call<'_>) -> Reply {
        let mut request = Request::builder()
            .method(call.method.clone())
            .uri(call.uri)
            .header(header::HOST, call.host);
        if !matches!(call.method, Method::GET | Method::HEAD)
            && let Some(origin) = call.origin
        {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(cookie) = call.cookie {
            request = request.header(header::COOKIE, format!("session={cookie}"));
        }
        if let Some(ct) = call.content_type {
            request = request.header(header::CONTENT_TYPE, ct);
        }
        for (name, value) in call.headers {
            request = request.header(name, value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(call.body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    pub async fn get(&self, host: &str, uri: &str, cookie: &str) -> Reply {
        self.send(Call {
            cookie: Some(cookie),
            ..self.call(Method::GET, host, uri)
        })
        .await
    }

    pub async fn post_json(
        &self,
        host: &str,
        uri: &str,
        cookie: Option<&str>,
        json: serde_json::Value,
    ) -> Reply {
        self.send(Call {
            cookie,
            body: json.to_string().into_bytes(),
            content_type: Some("application/json"),
            ..self.call(Method::POST, host, uri)
        })
        .await
    }

    pub async fn delete(&self, host: &str, uri: &str, cookie: &str) -> Reply {
        self.send(Call {
            cookie: Some(cookie),
            ..self.call(Method::DELETE, host, uri)
        })
        .await
    }

    /// Creates a user the way the CLI does and returns a setup token for them.
    pub fn create_user(&self, username: &str) -> String {
        let conn = self.conn();
        let user = accounts::create_user(&conn, username, self.now())
            .unwrap()
            .unwrap();
        accounts::issue_setup_token(&conn, &user.id, self.now())
            .unwrap()
            .0
    }

    pub fn setup_token_for(&self, username: &str) -> String {
        let conn = self.conn();
        let user = store::user_by_username(&conn, username).unwrap().unwrap();
        accounts::issue_setup_token(&conn, &user.id, self.now())
            .unwrap()
            .0
    }

    /// A new user with a session from their setup token, on `host`.
    pub async fn signed_up(&self, username: &str, host: &str) -> String {
        let token = self.create_user(username);
        let reply = self
            .post_json(
                host,
                "/api/v1/auth/setup-token",
                None,
                serde_json::json!({ "token": token }),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        reply.cookie()
    }

    /// Registers `authenticator` for the session's user on `host`.
    pub async fn register(
        &self,
        host: &str,
        cookie: &str,
        authenticator: &Authenticator,
        name: &str,
    ) -> Reply {
        let start = self
            .post_json(
                host,
                "/api/v1/me/passkeys/register/start",
                Some(cookie),
                serde_json::json!({}),
            )
            .await;
        assert_eq!(
            start.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&start.body)
        );
        let options = &start.json()["options"];
        let credential = authenticator.register(options, &origin_of(host), rp_id_of(host));
        self.post_json(
            host,
            "/api/v1/me/passkeys/register/finish",
            Some(cookie),
            serde_json::json!({ "name": name, "credential": credential }),
        )
        .await
    }

    /// Logs in with `authenticator` on `host`, as `user_handle` (base64url of the user ID bytes).
    pub async fn login(
        &self,
        host: &str,
        authenticator: &Authenticator,
        user_handle: &str,
        cookie: Option<&str>,
    ) -> Reply {
        let start = self
            .post_json(
                host,
                "/api/v1/auth/login/start",
                None,
                serde_json::json!({}),
            )
            .await;
        assert_eq!(
            start.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&start.body)
        );
        let credential = authenticator.sign(
            &start.json()["options"],
            &origin_of(host),
            rp_id_of(host),
            user_handle,
        );
        self.post_json(
            host,
            "/api/v1/auth/login/finish",
            cookie,
            serde_json::json!({ "credential": credential }),
        )
        .await
    }

    pub fn user_handle(&self, username: &str) -> String {
        let user = store::user_by_username(&self.conn(), username)
            .unwrap()
            .unwrap();
        backend::secret::b64url(&user.id)
    }
}

pub fn origin_of(host: &str) -> String {
    if host == PUBLIC {
        format!("https://{host}")
    } else {
        format!("http://{host}")
    }
}

pub fn rp_id_of(host: &str) -> &str {
    host.split(':').next().unwrap()
}

pub use authenticator::Authenticator;

/// A software authenticator shaped like the Android app's (sashee/iroh-webview-app): ES256, `none`
/// attestation, a counter that stays 0, user present and verified. Like a real client using PRF, it also
/// reports the `prf` extension and returns `hmac-secret` output the server never asked for.
mod authenticator {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use p256::pkcs8::EncodePublicKey as _;
    use sha2::{Digest, Sha256};

    pub struct Authenticator {
        pub key: SigningKey,
        pub credential_id: [u8; 16],
        /// Report PRF in the client results and `hmac-secret` in the authenticator data.
        pub prf: bool,
    }

    impl Authenticator {
        pub fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32].into()).unwrap(),
                credential_id: [seed.wrapping_add(100); 16],
                prf: true,
            }
        }

        pub fn id(&self) -> String {
            B64.encode(self.credential_id)
        }

        fn flags(&self, base: u8) -> u8 {
            if self.prf { base | 0x80 } else { base }
        }

        pub fn sign(
            &self,
            options: &serde_json::Value,
            origin: &str,
            rp_id: &str,
            user_handle: &str,
        ) -> serde_json::Value {
            let client_data = serde_json::json!({ "type": "webauthn.get", "challenge": options["challenge"], "origin": origin, "crossOrigin": false }).to_string();
            let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
            auth_data.push(self.flags(0x01 | 0x04));
            auth_data.extend(0u32.to_be_bytes());
            if self.prf {
                // {"hmac-secret": <48 bytes>}: one encrypted PRF output plus its IV, as CTAP returns it.
                head(&mut auth_data, 5, 1);
                text(&mut auth_data, "hmac-secret");
                bytes(&mut auth_data, &[7u8; 48]);
            }
            let mut signed = auth_data.clone();
            signed.extend(Sha256::digest(client_data.as_bytes()));
            let signature: Signature = self.key.sign(&signed);
            serde_json::json!({
                "id": self.id(),
                "rawId": self.id(),
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "clientExtensionResults": if self.prf { serde_json::json!({ "prf": {} }) } else { serde_json::json!({}) },
                "response": {
                    "clientDataJSON": B64.encode(&client_data),
                    "authenticatorData": B64.encode(&auth_data),
                    "signature": B64.encode(signature.to_der().as_bytes()),
                    "userHandle": user_handle,
                },
            })
        }

        pub fn register(
            &self,
            options: &serde_json::Value,
            origin: &str,
            rp_id: &str,
        ) -> serde_json::Value {
            let client_data = serde_json::json!({ "type": "webauthn.create", "challenge": options["challenge"], "origin": origin, "crossOrigin": false }).to_string();
            let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
            auth_data.push(self.flags(0x01 | 0x04 | 0x40));
            auth_data.extend(0u32.to_be_bytes());
            auth_data.extend([0u8; 16]);
            auth_data.extend((self.credential_id.len() as u16).to_be_bytes());
            auth_data.extend(self.credential_id);
            auth_data.extend(self.cose_key());
            if self.prf {
                head(&mut auth_data, 5, 1);
                text(&mut auth_data, "hmac-secret");
                auth_data.push(0xf5); // true
            }
            let mut attestation = Vec::new();
            head(&mut attestation, 5, 3);
            text(&mut attestation, "fmt");
            text(&mut attestation, "none");
            text(&mut attestation, "attStmt");
            head(&mut attestation, 5, 0);
            text(&mut attestation, "authData");
            bytes(&mut attestation, &auth_data);
            let public_key = self.key.verifying_key().to_public_key_der().unwrap();
            serde_json::json!({
                "id": self.id(),
                "rawId": self.id(),
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "clientExtensionResults": if self.prf { serde_json::json!({ "prf": { "enabled": true } }) } else { serde_json::json!({}) },
                "response": {
                    "clientDataJSON": B64.encode(&client_data),
                    "attestationObject": B64.encode(&attestation),
                    "authenticatorData": B64.encode(&auth_data),
                    "publicKey": B64.encode(public_key.as_bytes()),
                    "publicKeyAlgorithm": -7,
                    "transports": ["internal"],
                },
            })
        }

        fn cose_key(&self) -> Vec<u8> {
            let point = self.key.verifying_key().to_encoded_point(false);
            let mut out = Vec::new();
            head(&mut out, 5, 5);
            out.extend([0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
            out.push(0x21);
            bytes(&mut out, point.x().unwrap());
            out.push(0x22);
            bytes(&mut out, point.y().unwrap());
            out
        }
    }

    fn head(out: &mut Vec<u8>, major: u8, n: usize) {
        match n {
            0..=23 => out.push(major << 5 | n as u8),
            24..=0xff => out.extend([major << 5 | 24, n as u8]),
            _ => {
                out.push(major << 5 | 25);
                out.extend((n as u16).to_be_bytes());
            }
        }
    }

    fn text(out: &mut Vec<u8>, s: &str) {
        head(out, 3, s.len());
        out.extend(s.as_bytes());
    }

    fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        head(out, 2, b.len());
        out.extend(b);
    }
}
