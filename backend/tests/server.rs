//! The binary: serving on the Unix socket and shutting down (SPEC §3.1), and the admin commands (SPEC §9).

use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A backend configured only through the environment, in its own directory.
struct Instance {
    dir: tempfile::TempDir,
}

impl Instance {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("static")).unwrap();
        std::fs::write(dir.path().join("static/index.html"), "app").unwrap();
        Self { dir }
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("backend.sock")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_backend"));
        command
            .env_clear()
            .arg("--config")
            .arg(self.dir.path().join("missing.toml"))
            .args(args)
            .env("BACKEND_SOCKET", self.socket())
            .env("BACKEND_DATABASE", self.dir.path().join("backend.sqlite3"))
            .env("BACKEND_STATIC_DIR", self.dir.path().join("static"))
            .env("BACKEND_PUBLIC_HOSTS", "app.example.com");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    /// Runs a command that asks for confirmation, answering `answer`.
    fn run_answering(&self, args: &[&str], answer: &str) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(answer.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// The output of a command that must succeed.
    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The token of a printed setup link.
fn setup_token(printed: &str) -> String {
    let start = printed.find("#setup=").unwrap() + "#setup=".len();
    printed[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn the_admin_commands_manage_users() {
    let instance = Instance::new();
    let created = instance.ok(&["user", "create", "alice"]);
    assert!(created.contains("Created user alice ("), "{created}");
    let token = setup_token(&created);
    assert_eq!(token.len(), 43);
    assert!(created.contains(&format!("https://app.example.com/#setup={token}")));

    let invalid = instance.run(&["user", "create", "Alice"]);
    assert!(!invalid.status.success());
    let taken = instance.run(&["user", "create", "alice"]);
    assert!(
        stderr(&taken).contains("already exists"),
        "{}",
        stderr(&taken)
    );

    let storage = instance.ok(&["storage"]);
    assert!(storage.starts_with("where"), "{storage}");
    assert!(storage.contains("target: local"), "{storage}");
    assert!(
        storage.contains("bringing everything into the database: 0 B more; fits"),
        "{storage}"
    );

    let list = instance.ok(&["user", "list"]);
    assert!(list.starts_with("alice\t"), "{list}");
    assert!(
        list.contains("no passkeys") && list.contains("0 bytes stored"),
        "{list}"
    );

    assert_eq!(
        setup_token(&instance.ok(&["setup-token", "create", "alice"])).len(),
        43
    );
    assert!(
        !instance
            .run(&["setup-token", "create", "bob"])
            .status
            .success()
    );

    let refused = instance.run_answering(&["user", "delete", "alice"], "bob\n");
    assert!(
        stderr(&refused).contains("not confirmed"),
        "{}",
        stderr(&refused)
    );
    assert!(instance.ok(&["user", "list"]).contains("alice"));
    let confirmed = instance.run_answering(&["user", "delete", "alice"], "alice\n");
    assert!(confirmed.status.success(), "{}", stderr(&confirmed));

    instance.ok(&["user", "create", "bob"]);
    instance.ok(&["user", "delete", "bob", "--yes"]);
    assert_eq!(instance.ok(&["user", "list"]), "");
    assert!(
        !instance
            .run(&["user", "delete", "bob", "--yes"])
            .status
            .success()
    );
}

/// A blob ID made of one byte, repeated.
fn blob_id(byte: &str) -> String {
    byte.repeat(32)
}

/// Copies in backends as a server leaves them: one blob in aws alone, one here and in aws, one in aws and b2.
fn with_copies(instance: &Instance) {
    let conn = rusqlite::Connection::open(instance.dir.path().join("backend.sqlite3")).unwrap();
    let (aa, bb, cc) = (blob_id("aa"), blob_id("bb"), blob_id("cc"));
    conn.execute_batch(&format!(
        r#"INSERT INTO blobs (user_id, id, size, created_at, offloadable, content)
             SELECT id, x'{aa}', 1, 0, 1, NULL FROM users UNION ALL
             SELECT id, x'{bb}', 1, 0, 1, x'00' FROM users UNION ALL
             SELECT id, x'{cc}', 1, 0, 1, NULL FROM users;
           INSERT INTO blob_copies (user_id, blob_id, backend)
             SELECT user_id, id, 'aws' FROM blobs UNION ALL
             SELECT user_id, id, 'b2' FROM blobs WHERE id = x'{cc}';
           INSERT INTO backends (name, type, identity)
             VALUES ('aws', 's3', '{{}}'), ('b2', 's3', '{{}}');"#
    ))
    .unwrap();
}

#[test]
fn forget_drops_a_gone_backends_copies_but_not_the_last_unless_told() {
    let instance = Instance::new();
    instance.ok(&["user", "create", "alice"]);
    with_copies(&instance);
    let before = instance.ok(&["storage"]);
    assert!(before.contains("by copies: 1 with 1, 2 with 2"), "{before}");

    let invalid = instance.run(&["forget", "local"]);
    assert!(
        stderr(&invalid).contains("can't be a backend's name"),
        "{}",
        stderr(&invalid)
    );
    let typo = instance.run(&["forget", "awz"]);
    assert!(
        stderr(&typo).contains("no backend awz is recorded"),
        "{}",
        stderr(&typo)
    );
    // Still configured, a target or not: the server may still reach it.
    let config = instance.dir.path().join("missing.toml");
    std::fs::write(
        &config,
        "[backends.aws]\ntype = \"s3\"\nfile = \"/nowhere\"\n",
    )
    .unwrap();
    let configured = instance.run(&["forget", "aws", "--accept-loss"]);
    assert!(
        stderr(&configured).contains("aws is still configured"),
        "{}",
        stderr(&configured)
    );
    std::fs::remove_file(&config).unwrap();

    let refused = instance.run(&["forget", "aws"]);
    assert!(!refused.status.success());
    let why = stderr(&refused);
    assert!(
        why.contains("1 blobs have no copy anywhere but in aws"),
        "{why}"
    );
    assert!(why.contains(&blob_id("aa")), "the blob is listed: {why}");
    assert!(why.contains("nothing forgotten"), "{why}");
    assert_eq!(instance.ok(&["storage"]), before, "nothing changed");

    let forgot = instance.ok(&["forget", "aws", "--accept-loss"]);
    assert!(forgot.contains("Forgot backend aws: 3 copies"), "{forgot}");
    assert!(
        forgot.contains("1 blobs had no other copy, and are lost"),
        "{forgot}"
    );
    let after = instance.ok(&["storage"]);
    assert!(after.contains("by copies: 2 with 1\n"), "{after}");
    assert!(
        after.contains("lost, with no copy left: 1 blobs, 1 B"),
        "{after}"
    );
    assert!(
        after.contains("bringing everything into the database: 1 B more"),
        "the lost one can't come back: {after}"
    );
    assert!(!after.contains("aws"), "{after}");
    assert!(
        stderr(&instance.run(&["forget", "aws"])).contains("no backend aws is recorded"),
        "forgotten already"
    );
}

/// One HTTP/1.1 request over the socket; the whole response.
fn http(socket: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn exited(server: &mut Child) -> bool {
    server.try_wait().unwrap().is_some()
}

#[test]
fn the_server_answers_on_the_socket_and_removes_it_on_shutdown() {
    let instance = Instance::new();
    let token = setup_token(&instance.ok(&["user", "create", "alice"]));
    let mut server = instance
        .command(&["serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let socket = instance.socket();
    wait_until("the socket", || {
        assert!(!exited(&mut server), "the server stopped");
        socket.exists()
    });
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o660);

    let health = http(
        &socket,
        "GET /healthz HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n",
    );
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");
    assert!(health.ends_with("ok"), "{health}");
    let unknown = http(
        &socket,
        "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n",
    );
    assert!(unknown.starts_with("HTTP/1.1 400"), "{unknown}");

    // The token the CLI printed opens a session on the running server.
    let body = format!("{{\"token\":\"{token}\"}}");
    let exchanged = http(
        &socket,
        &format!(
            "POST /api/v1/auth/setup-token HTTP/1.1\r\nHost: localhost:8080\r\nOrigin: http://localhost:8080\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(exchanged.starts_with("HTTP/1.1 200 OK"), "{exchanged}");
    assert!(
        exchanged
            .to_ascii_lowercase()
            .contains("set-cookie: session="),
        "{exchanged}"
    );

    let signalled = Command::new("kill")
        .args(["-TERM", &server.id().to_string()])
        .status()
        .unwrap();
    assert!(signalled.success());
    wait_until("the server to stop", || exited(&mut server));
    assert!(server.wait().unwrap().success());
    assert!(!socket.exists(), "the socket is removed on shutdown");
}
