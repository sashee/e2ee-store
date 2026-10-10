//! Pure rules: identifiers, names, hosts, ranges, preconditions, expiry and formatting.
//! Nothing here does I/O or reads the clock; the current time is always an argument.

use std::fmt;
use std::time::{Duration, UNIX_EPOCH};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------- identifiers

/// A blob ID: the SHA-256 of the blob's content (SPEC §4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct BlobId(pub [u8; 32]);

impl BlobId {
    pub fn of(content: &[u8]) -> BlobId {
        BlobId(Sha256::digest(content).into())
    }

    /// Exactly 64 lowercase hex characters.
    pub fn parse(s: &str) -> Option<BlobId> {
        hex_decode(s)?.try_into().ok().map(BlobId)
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_encode(&self.0))
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex only, so every value has exactly one spelling.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let valid = s.len().is_multiple_of(2)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    valid.then(|| {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
            .collect()
    })
}

/// A UUIDv4 from 16 random bytes: the version and variant bits are set, the rest kept.
pub fn uuid_v4(mut random: [u8; 16]) -> [u8; 16] {
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    random
}

pub fn format_uuid(bytes: &[u8; 16]) -> String {
    let hex = hex_encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub fn valid_username(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// 1–64 characters, no control characters.
pub fn valid_passkey_name(name: &str) -> bool {
    (1..=64).contains(&name.chars().count()) && !name.chars().any(char::is_control)
}

/// 1–256 bytes of `/`-separated segments of `[A-Za-z0-9._-]+`; no empty, `.` or `..` segments.
pub fn valid_ref_name(name: &str) -> bool {
    (1..=256).contains(&name.len())
        && name.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

// ---------------------------------------------------------------- hosts and origins

/// Where a request was sent, derived from its `Host` header (SPEC §6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The `Host` header, lowercased, port included.
    pub host: String,
    /// The host name without the port: the WebAuthn RP ID.
    pub rp_id: String,
    /// The port from the `Host` header, if any.
    pub port: Option<u16>,
    /// Public hosts are reached over HTTPS; loopback names over plain HTTP.
    pub secure: bool,
}

impl Site {
    /// The origin a browser on this site sends.
    pub fn origin(&self) -> String {
        format!(
            "{}://{}",
            if self.secure { "https" } else { "http" },
            self.host
        )
    }
}

/// Classifies a `Host` header. `localhost` and `*.localhost` (any port) are loopback names; anything else
/// must be listed in `public_hosts` exactly (port included, if one is listed). IP addresses never match.
pub fn classify_host(host: &str, public_hosts: &[String]) -> Option<Site> {
    let host = host.trim().to_ascii_lowercase();
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, Some(port.parse::<u16>().ok()?)),
        None => (host.as_str(), None),
    };
    if !valid_dns_name(name) {
        return None;
    }
    let loopback = name == "localhost"
        || name
            .strip_suffix(".localhost")
            .is_some_and(|l| !l.is_empty());
    let public = public_hosts.iter().any(|p| p.eq_ignore_ascii_case(&host));
    (loopback || public).then(|| Site {
        rp_id: name.to_owned(),
        port,
        secure: !loopback,
        host: host.clone(),
    })
}

/// Dot-separated labels of `[a-z0-9-]`, not starting or ending with `-`, and not all digits (no IPs).
fn valid_dns_name(name: &str) -> bool {
    let labels_ok = name.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    let last_label_numeric = name
        .rsplit('.')
        .next()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    !name.is_empty() && name.len() <= 253 && labels_ok && !last_label_numeric
}

// ---------------------------------------------------------------- ranges

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// No usable `Range` header: send everything.
    Full,
    /// Inclusive byte positions.
    Partial {
        start: u64,
        end: u64,
    },
    Unsatisfiable,
}

/// A single `bytes=` range (`a-b`, `a-`, `-n`). Anything else, multiple ranges included, is ignored as
/// RFC 9110 allows, which means the full body.
pub fn parse_range(header: Option<&str>, size: u64) -> ByteRange {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return ByteRange::Full;
    };
    if spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return ByteRange::Full;
    };
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    match (first.is_empty(), number(first), number(last)) {
        // `-n`: the last n bytes.
        (true, _, Some(n)) => match (n, size) {
            (0, _) | (_, 0) => ByteRange::Unsatisfiable,
            _ => ByteRange::Partial {
                start: size.saturating_sub(n),
                end: size - 1,
            },
        },
        (false, Some(start), end) if last.is_empty() || end.is_some() => {
            let end = end.unwrap_or(u64::MAX);
            if end < start {
                ByteRange::Full
            } else if start >= size {
                ByteRange::Unsatisfiable
            } else {
                ByteRange::Partial {
                    start,
                    end: end.min(size - 1),
                }
            }
        }
        _ => ByteRange::Full,
    }
}

// ---------------------------------------------------------------- preconditions

/// Precondition headers the spec rejects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPrecondition;

/// What a write or delete expects about a ref's current target (SPEC §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precondition {
    None,
    /// `If-Match: "<id>"`
    PointsTo(BlobId),
    /// `If-Match: *`
    Exists,
    /// `If-None-Match: *`
    Missing,
}

/// Parses the precondition headers. `Err` for anything the spec rejects: both headers, lists, weak tags,
/// unquoted tags, `If-None-Match` other than `*`, and `If-None-Match` where it isn't allowed (DELETE).
pub fn parse_precondition(
    if_match: Option<&str>,
    if_none_match: Option<&str>,
    none_match_allowed: bool,
) -> Result<Precondition, InvalidPrecondition> {
    match (if_match.map(str::trim), if_none_match.map(str::trim)) {
        (None, None) => Ok(Precondition::None),
        (Some(_), Some(_)) => Err(InvalidPrecondition),
        (None, Some("*")) if none_match_allowed => Ok(Precondition::Missing),
        (None, Some(_)) => Err(InvalidPrecondition),
        (Some("*"), None) => Ok(Precondition::Exists),
        (Some(tag), None) => tag
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .and_then(BlobId::parse)
            .map(Precondition::PointsTo)
            .ok_or(InvalidPrecondition),
    }
}

pub fn precondition_holds(precondition: Precondition, current: Option<BlobId>) -> bool {
    match precondition {
        Precondition::None => true,
        Precondition::PointsTo(id) => current == Some(id),
        Precondition::Exists => current.is_some(),
        Precondition::Missing => current.is_none(),
    }
}

/// The ETag of a ref or blob: its blob ID, quoted.
pub fn etag(id: BlobId) -> String {
    format!("\"{id}\"")
}

// ---------------------------------------------------------------- time

/// A row with an `expires_at` is valid only while `now < expires_at` (SPEC §5.1).
pub fn is_live(now_ms: i64, expires_at_ms: i64) -> bool {
    now_ms < expires_at_ms
}

/// Step-up: the session was created within the window (SPEC §6.5).
pub fn is_fresh(now_ms: i64, created_at_ms: i64, window: Duration) -> bool {
    now_ms < created_at_ms.saturating_add(duration_ms(window))
}

pub fn duration_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// RFC 3339, UTC, milliseconds: `2026-10-09T20:57:00.123Z`.
pub fn format_timestamp(ms: i64) -> String {
    let t = UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).unwrap_or(0));
    humantime::format_rfc3339_millis(t).to_string()
}

// ---------------------------------------------------------------- config values

/// `16MiB`, `64KiB`, `1GiB` or a plain number of bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (digits, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let multiplier = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        _ => return None,
    };
    digits.parse::<u64>().ok()?.checked_mul(multiplier)
}

/// At most `max` items per page, `max` by default, at least 1.
pub fn page_limit(requested: Option<usize>, max: usize) -> usize {
    requested.unwrap_or(max).clamp(1, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> BlobId {
        BlobId([byte; 32])
    }

    #[test]
    fn blob_ids_are_lowercase_hex_sha256() {
        let blob = BlobId::of(b"hello");
        assert_eq!(
            blob.to_string(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(BlobId::parse(&blob.to_string()), Some(blob));
        assert_eq!(BlobId::parse(&blob.to_string().to_uppercase()), None);
        assert_eq!(BlobId::parse("abcd"), None);
        assert_eq!(BlobId::parse(&"g".repeat(64)), None);
    }

    #[test]
    fn uuids_have_version_and_variant() {
        let uuid = uuid_v4([0xff; 16]);
        assert_eq!(format_uuid(&uuid), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(
            format_uuid(&uuid_v4([0; 16])),
            "00000000-0000-4000-8000-000000000000"
        );
    }

    #[test]
    fn ref_names() {
        for ok in ["vault", "keys", "a/b/c", "A.b_c-d", &"x".repeat(256)] {
            assert!(valid_ref_name(ok), "{ok}");
        }
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            ".",
            "..",
            "a/../b",
            "a b",
            "ä",
            &"x".repeat(257),
        ] {
            assert!(!valid_ref_name(bad), "{bad}");
        }
    }

    #[test]
    fn usernames_and_passkey_names() {
        assert!(valid_username("alice.b-c_1"));
        assert!(!valid_username("Alice"));
        assert!(!valid_username(""));
        assert!(!valid_username(&"a".repeat(65)));
        assert!(valid_passkey_name("Passkey on localhost"));
        assert!(valid_passkey_name(&"ü".repeat(64)));
        assert!(!valid_passkey_name(""));
        assert!(!valid_passkey_name("a\nb"));
    }

    #[test]
    fn loopback_names_are_http_and_any_port() {
        let site = classify_host("LocalHost:8080", &[]).unwrap();
        assert_eq!(
            site,
            Site {
                host: "localhost:8080".into(),
                rp_id: "localhost".into(),
                port: Some(8080),
                secure: false
            }
        );
        assert_eq!(site.origin(), "http://localhost:8080");
        let phone = classify_host("6c4b9e.localhost:24038", &[]).unwrap();
        assert_eq!(phone.rp_id, "6c4b9e.localhost");
        assert_eq!(
            classify_host("localhost", &[]).unwrap().origin(),
            "http://localhost"
        );
    }

    #[test]
    fn public_hosts_are_https_and_exact() {
        let public = vec![
            "pw.example.com".to_owned(),
            "other.example.com:8443".to_owned(),
        ];
        let site = classify_host("pw.example.com", &public).unwrap();
        assert_eq!(site.origin(), "https://pw.example.com");
        assert_eq!(site.rp_id, "pw.example.com");
        assert!(site.secure);
        assert_eq!(
            classify_host("other.example.com:8443", &public)
                .unwrap()
                .rp_id,
            "other.example.com"
        );
        assert_eq!(classify_host("pw.example.com:444", &public), None);
        assert_eq!(classify_host("evil.example.com", &public), None);
    }

    #[test]
    fn everything_else_is_refused() {
        for refused in [
            "127.0.0.1:8080",
            "[::1]:8080",
            "example.com",
            "localhost.example.com",
            ".localhost",
            "localhost:http",
            "",
            "a..localhost",
            "-a.localhost",
        ] {
            assert_eq!(classify_host(refused, &[]), None, "{refused:?}");
        }
    }

    #[test]
    fn ranges() {
        let r = |h: &str| parse_range(Some(h), 100);
        assert_eq!(parse_range(None, 100), ByteRange::Full);
        assert_eq!(r("bytes=0-9"), ByteRange::Partial { start: 0, end: 9 });
        assert_eq!(r("bytes=90-"), ByteRange::Partial { start: 90, end: 99 });
        assert_eq!(
            r("bytes=90-1000"),
            ByteRange::Partial { start: 90, end: 99 }
        );
        assert_eq!(r("bytes=-10"), ByteRange::Partial { start: 90, end: 99 });
        assert_eq!(r("bytes=-1000"), ByteRange::Partial { start: 0, end: 99 });
        assert_eq!(r("bytes=100-"), ByteRange::Unsatisfiable);
        assert_eq!(r("bytes=-0"), ByteRange::Unsatisfiable);
        assert_eq!(r("bytes=0-1,5-6"), ByteRange::Full);
        assert_eq!(r("bytes=5-1"), ByteRange::Full);
        assert_eq!(r("items=0-1"), ByteRange::Full);
        assert_eq!(r("bytes=x-1"), ByteRange::Full);
        assert_eq!(r("bytes=-"), ByteRange::Full);
        assert_eq!(parse_range(Some("bytes=0-"), 0), ByteRange::Unsatisfiable);
    }

    #[test]
    fn precondition_parsing() {
        let tag = format!("\"{}\"", id(1));
        assert_eq!(parse_precondition(None, None, true), Ok(Precondition::None));
        assert_eq!(
            parse_precondition(Some(&tag), None, true),
            Ok(Precondition::PointsTo(id(1)))
        );
        assert_eq!(
            parse_precondition(Some("*"), None, false),
            Ok(Precondition::Exists)
        );
        assert_eq!(
            parse_precondition(None, Some("*"), true),
            Ok(Precondition::Missing)
        );
        assert_eq!(
            parse_precondition(None, Some("*"), false),
            Err(InvalidPrecondition)
        );
        assert_eq!(
            parse_precondition(Some(&tag), Some("*"), true),
            Err(InvalidPrecondition)
        );
        assert_eq!(
            parse_precondition(Some(&format!("{tag}, {tag}")), None, true),
            Err(InvalidPrecondition)
        );
        assert_eq!(
            parse_precondition(Some(&format!("W/{tag}")), None, true),
            Err(InvalidPrecondition)
        );
        assert_eq!(
            parse_precondition(Some(&id(1).to_string()), None, true),
            Err(InvalidPrecondition)
        );
        assert_eq!(
            parse_precondition(None, Some(&tag), true),
            Err(InvalidPrecondition)
        );
    }

    #[test]
    fn precondition_table() {
        use Precondition::*;
        let cases = [
            (None, Option::None, true),
            (None, Some(id(1)), true),
            (Missing, Option::None, true),
            (Missing, Some(id(1)), false),
            (PointsTo(id(1)), Some(id(1)), true),
            (PointsTo(id(1)), Some(id(2)), false),
            (PointsTo(id(1)), Option::None, false),
            (Exists, Some(id(2)), true),
            (Exists, Option::None, false),
        ];
        for (precondition, current, expected) in cases {
            assert_eq!(
                precondition_holds(precondition, current),
                expected,
                "{precondition:?} {current:?}"
            );
        }
    }

    #[test]
    fn expiry_and_freshness() {
        assert!(is_live(99, 100));
        assert!(!is_live(100, 100));
        let window = Duration::from_secs(300);
        assert!(is_fresh(1_000 + 299_999, 1_000, window));
        assert!(!is_fresh(1_000 + 300_000, 1_000, window));
    }

    #[test]
    fn timestamps() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_timestamp(1_791_579_420_123),
            "2026-10-09T20:57:00.123Z"
        );
    }

    #[test]
    fn sizes_and_limits() {
        assert_eq!(parse_size("16MiB"), Some(16 << 20));
        assert_eq!(parse_size("64 KiB"), Some(64 << 10));
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("1MB"), None);
        assert_eq!(page_limit(None, 1000), 1000);
        assert_eq!(page_limit(Some(5000), 1000), 1000);
        assert_eq!(page_limit(Some(0), 1000), 1);
    }
}
