//! Configuration (SPEC §10): a TOML file, every key but `backends` overridable with `BACKEND_<KEY>`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use crate::domain::{parse_size, public_host_problem};
use crate::placement::{LOCAL, Location};

pub const DEFAULT_STATIC_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub socket: PathBuf,
    pub database: PathBuf,
    pub static_dir: PathBuf,
    pub static_csp: String,
    pub public_hosts: Vec<String>,
    pub rp_name: String,
    pub session_ttl: Duration,
    pub reauth_window: Duration,
    pub max_blob_size: u64,
    /// Where offloadable blobs belong, a copy in each (SPEC §7.4): not empty, each once, in the order reads try them.
    pub blob_target: Vec<Location>,
    /// The storage backends offloadable blobs can be in, by name (SPEC §7.4, §10).
    pub backends: BTreeMap<String, Backend>,
    /// What the database's file system keeps free: writes into the database that would take it below are refused.
    pub min_free_space: u64,
}

/// A storage backend: its type and the file with its location and credentials, which only `serve` reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub kind: Kind,
    pub file: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    S3,
}

/// A backend's name: what blobs' copies say they're in, so it can't be "local".
pub fn valid_backend_name(name: &str) -> bool {
    let chars_ok = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    (1..=32).contains(&name.len()) && chars_ok && !name.starts_with('-') && name != "local"
}

/// The file as written: every key optional, values still strings where they need parsing.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    socket: Option<String>,
    database: Option<String>,
    static_dir: Option<String>,
    static_csp: Option<String>,
    public_hosts: Option<Vec<String>>,
    rp_name: Option<String>,
    session_ttl: Option<String>,
    reauth_window: Option<String>,
    max_blob_size: Option<String>,
    blob_target: Option<Places>,
    backends: Option<BTreeMap<String, RawBackend>>,
    min_free_space: Option<String>,
}

/// `blob_target` as written: a list, or one name, a list of one, as before 2.0.
#[derive(Debug, Deserialize)]
#[serde(
    untagged,
    expecting = "a list of places: \"local\" and backends' names"
)]
enum Places {
    One(String),
    List(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackend {
    r#type: String,
    file: String,
}

/// Reads the file (a missing file counts as empty) and applies the environment.
pub fn load(path: &Path, env: &HashMap<String, String>) -> anyhow::Result<Config> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    resolve(&text, env).with_context(|| format!("in {}", path.display()))
}

/// The file's contents plus the environment, validated. Pure.
pub fn resolve(file: &str, env: &HashMap<String, String>) -> anyhow::Result<Config> {
    let raw: RawConfig = toml::from_str(file)?;
    let get = |key: &str, from_file: Option<String>| {
        env.get(&format!("BACKEND_{}", key.to_uppercase()))
            .cloned()
            .or(from_file)
    };
    let duration = |key: &str, value: Option<String>, default: &str| -> anyhow::Result<Duration> {
        let value = get(key, value).unwrap_or_else(|| default.to_owned());
        humantime::parse_duration(&value).map_err(|e| anyhow!("{key}: {e}"))
    };

    let public_hosts: Vec<String> = match env.get("BACKEND_PUBLIC_HOSTS") {
        Some(list) => list
            .split(',')
            .filter(|h| !h.trim().is_empty())
            .map(str::to_owned)
            .collect(),
        None => raw.public_hosts.unwrap_or_default(),
    }
    .iter()
    .map(|h| h.trim().to_ascii_lowercase())
    .collect();
    if let Some((host, problem)) = public_hosts
        .iter()
        .find_map(|h| public_host_problem(h).map(|problem| (h, problem)))
    {
        bail!("public_hosts: {host:?} is {problem}");
    }
    let max_blob_size = get("max_blob_size", raw.max_blob_size).unwrap_or_else(|| "16MiB".into());
    let static_dir =
        get("static_dir", raw.static_dir).ok_or_else(|| anyhow!("static_dir is required"))?;
    let backends = raw
        .backends
        .unwrap_or_default()
        .into_iter()
        .map(|(name, backend)| {
            if !valid_backend_name(&name) {
                bail!(
                    "backends: {name:?} can't be a name: 1-32 of a-z, 0-9 and -, and not \"local\""
                );
            }
            let kind = match backend.r#type.as_str() {
                "s3" => Kind::S3,
                other => {
                    bail!("backends.{name}: type {other:?} is unknown; the one there is is \"s3\"")
                }
            };
            Ok((
                name,
                Backend {
                    kind,
                    file: backend.file.into(),
                },
            ))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    let blob_target = targets(
        match env.get("BACKEND_BLOB_TARGET") {
            Some(list) => list.split(',').map(|t| t.trim().to_owned()).collect(),
            None => match raw.blob_target {
                None => vec![LOCAL.into()],
                Some(Places::One(name)) => vec![name],
                Some(Places::List(names)) => names,
            },
        },
        &backends,
    )?;
    let min_free_space = get("min_free_space", raw.min_free_space).unwrap_or_else(|| "1GiB".into());

    Ok(Config {
        socket: get("socket", raw.socket)
            .unwrap_or_else(|| "./data/backend.sock".into())
            .into(),
        database: get("database", raw.database)
            .unwrap_or_else(|| "./data/backend.sqlite3".into())
            .into(),
        static_dir: static_dir.into(),
        static_csp: get("static_csp", raw.static_csp).unwrap_or_else(|| DEFAULT_STATIC_CSP.into()),
        public_hosts,
        rp_name: get("rp_name", raw.rp_name).unwrap_or_else(|| "Backend".into()),
        session_ttl: duration("session_ttl", raw.session_ttl, "4h")?,
        reauth_window: duration("reauth_window", raw.reauth_window, "5m")?,
        max_blob_size: parse_size(&max_blob_size)
            .ok_or_else(|| anyhow!("max_blob_size: cannot parse {max_blob_size:?}"))?,
        blob_target,
        backends,
        min_free_space: parse_size(&min_free_space)
            .ok_or_else(|| anyhow!("min_free_space: cannot parse {min_free_space:?}"))?,
    })
}

/// `blob_target` checked: not empty, and each entry once, "local" or a configured backend.
fn targets(
    names: Vec<String>,
    backends: &BTreeMap<String, Backend>,
) -> anyhow::Result<Vec<Location>> {
    if names.is_empty() {
        bail!("blob_target: a list of at least one place, \"local\" or a backend");
    }
    if let Some(name) = names
        .iter()
        .enumerate()
        .find_map(|(i, name)| names[..i].contains(name).then_some(name))
    {
        bail!("blob_target: {name:?} is there more than once");
    }
    if let Some(name) = names
        .iter()
        .find(|name| *name != LOCAL && !backends.contains_key(*name))
    {
        bail!("blob_target: {name:?} is neither \"local\" nor one of the backends");
    }
    Ok(names.iter().map(|name| Location::named(name)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn defaults_apply_and_static_dir_is_required() {
        let config = resolve("static_dir = \"web\"", &env(&[])).unwrap();
        assert_eq!(config.socket, PathBuf::from("./data/backend.sock"));
        assert_eq!(config.session_ttl, Duration::from_secs(4 * 3600));
        assert_eq!(config.reauth_window, Duration::from_secs(300));
        assert_eq!(config.max_blob_size, 16 << 20);
        assert!(config.public_hosts.is_empty());
        assert_eq!(config.blob_target, [Location::Local]);
        assert!(config.backends.is_empty());
        assert_eq!(config.min_free_space, 1 << 30);
        assert!(resolve("", &env(&[])).is_err());
    }

    const BACKENDS: &str = "static_dir = \"w\"\n[backends.aws]\ntype = \"s3\"\nfile = \"/run/credentials/x/aws\"\n[backends.b2]\ntype = \"s3\"\nfile = \"/run/credentials/x/b2\"\n";

    fn named(names: &[&str]) -> Vec<Location> {
        names.iter().map(|name| Location::named(name)).collect()
    }

    #[test]
    fn backends_have_a_name_a_type_and_a_file_and_the_targets_name_them() {
        let config = resolve(&format!("blob_target = [\"b2\"]\n{BACKENDS}"), &env(&[])).unwrap();
        assert_eq!(config.blob_target, named(&["b2"]));
        assert_eq!(
            config.backends["aws"],
            Backend {
                kind: Kind::S3,
                file: "/run/credentials/x/aws".into()
            }
        );
        let several = resolve(
            &format!("blob_target = [\"local\", \"b2\", \"aws\"]\n{BACKENDS}"),
            &env(&[]),
        )
        .unwrap();
        assert_eq!(
            several.blob_target,
            named(&["local", "b2", "aws"]),
            "in their order"
        );
        let back = resolve(
            &format!("blob_target = [\"b2\"]\n{BACKENDS}"),
            &env(&[("BACKEND_BLOB_TARGET", "local")]),
        )
        .unwrap();
        assert_eq!(
            back.blob_target,
            [Location::Local],
            "the environment overrides it too"
        );
        let one = resolve(&format!("blob_target = \"b2\"\n{BACKENDS}"), &env(&[])).unwrap();
        assert_eq!(one.blob_target, named(&["b2"]), "one name, as before 2.0");
        let moved = resolve(BACKENDS, &env(&[("BACKEND_BLOB_TARGET", "aws, local")])).unwrap();
        assert_eq!(moved.blob_target, named(&["aws", "local"]));

        for bad in [
            format!("blob_target = [\"gcs\"]\n{BACKENDS}"),
            format!("blob_target = []\n{BACKENDS}"),
            format!("blob_target = 1\n{BACKENDS}"),
            format!("blob_target = [\"aws\", \"local\", \"aws\"]\n{BACKENDS}"),
            "static_dir = \"w\"\nblob_target = [\"s3\"]".to_owned(),
            BACKENDS.replace(
                "type = \"s3\"\nfile = \"/run/credentials/x/aws\"",
                "type = \"ftp\"\nfile = \"f\"",
            ),
            BACKENDS.replace("[backends.aws]", "[backends.local]"),
            BACKENDS.replace("[backends.aws]", "[backends.AWS]"),
            BACKENDS.replace("[backends.aws]", "[backends.-aws]"),
            BACKENDS.replace(
                "file = \"/run/credentials/x/aws\"",
                "file = \"f\"\nkey = \"secret\"",
            ),
            format!("min_free_space = \"lots\"\n{BACKENDS}"),
        ] {
            assert!(resolve(&bad, &env(&[])).is_err(), "{bad}");
        }
        for bad in ["", "aws,,local", "aws,aws", "gcs"] {
            let from_env = resolve(BACKENDS, &env(&[("BACKEND_BLOB_TARGET", bad)]));
            assert!(from_env.is_err(), "{bad:?}");
        }
        let reserve =
            resolve("static_dir = \"w\"\nmin_free_space = \"200MiB\"", &env(&[])).unwrap();
        assert_eq!(reserve.min_free_space, 200 << 20);
        assert!(valid_backend_name("backblaze-eu1"));
        assert!(!valid_backend_name(&"a".repeat(33)));
    }

    #[test]
    fn the_environment_overrides_the_file() {
        let file = "static_dir = \"web\"\nsession_ttl = \"1h\"\npublic_hosts = [\"a.example.com\"]";
        let config = resolve(
            file,
            &env(&[
                ("BACKEND_SESSION_TTL", "30m"),
                ("BACKEND_PUBLIC_HOSTS", "B.example.com, c.example.com:8443"),
            ]),
        )
        .unwrap();
        assert_eq!(config.session_ttl, Duration::from_secs(1800));
        assert_eq!(
            config.public_hosts,
            vec!["b.example.com", "c.example.com:8443"]
        );
    }

    #[test]
    fn bad_values_are_refused() {
        assert!(resolve("static_dir = \"w\"\nmax_blob_size = \"lots\"", &env(&[])).is_err());
        assert!(resolve("static_dir = \"w\"\nsession_ttl = \"soon\"", &env(&[])).is_err());
        assert!(
            resolve(
                "static_dir = \"w\"\npublic_hosts = [\"https://x\"]",
                &env(&[])
            )
            .is_err()
        );
        assert!(resolve("static_dir = \"w\"\nunknown = 1", &env(&[])).is_err());
    }

    #[test]
    fn public_hosts_that_could_never_match_are_refused() {
        let hosts = |list: &str| {
            resolve(
                &format!("static_dir = \"w\"\npublic_hosts = {list}"),
                &env(&[]),
            )
        };
        assert_eq!(
            hosts("[\" App.Example.com \"]").unwrap().public_hosts,
            vec!["app.example.com"]
        );
        for bad in ["[\"\"]", "[\"app.localhost\"]", "[\"app.example.com:443\"]"] {
            let error = format!("{:#}", hosts(bad).unwrap_err());
            assert!(error.contains("public_hosts"), "{bad}: {error}");
        }
        let from_env = resolve(
            "static_dir = \"w\"",
            &env(&[("BACKEND_PUBLIC_HOSTS", "a.example.com,,localhost")]),
        );
        assert!(from_env.is_err(), "the environment is checked too");
    }
}
