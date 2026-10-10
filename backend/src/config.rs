//! Configuration (SPEC §10): a TOML file, every key overridable with `BACKEND_<KEY>`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use crate::domain::parse_size;

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

    let public_hosts = match env.get("BACKEND_PUBLIC_HOSTS") {
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            .collect(),
        None => raw.public_hosts.unwrap_or_default(),
    };
    let max_blob_size = get("max_blob_size", raw.max_blob_size).unwrap_or_else(|| "16MiB".into());
    let static_dir =
        get("static_dir", raw.static_dir).ok_or_else(|| anyhow!("static_dir is required"))?;
    if public_hosts
        .iter()
        .any(|h| h.contains('/') || h.contains("://"))
    {
        bail!("public_hosts are host names (optionally with a port), not URLs");
    }

    Ok(Config {
        socket: get("socket", raw.socket)
            .unwrap_or_else(|| "./data/backend.sock".into())
            .into(),
        database: get("database", raw.database)
            .unwrap_or_else(|| "./data/backend.sqlite3".into())
            .into(),
        static_dir: static_dir.into(),
        static_csp: get("static_csp", raw.static_csp).unwrap_or_else(|| DEFAULT_STATIC_CSP.into()),
        public_hosts: public_hosts
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
        rp_name: get("rp_name", raw.rp_name).unwrap_or_else(|| "Backend".into()),
        session_ttl: duration("session_ttl", raw.session_ttl, "4h")?,
        reauth_window: duration("reauth_window", raw.reauth_window, "5m")?,
        max_blob_size: parse_size(&max_blob_size)
            .ok_or_else(|| anyhow!("max_blob_size: cannot parse {max_blob_size:?}"))?,
    })
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
        assert!(resolve("", &env(&[])).is_err());
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
}
