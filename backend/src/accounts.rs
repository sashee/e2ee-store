//! Account operations shared by the HTTP API and the admin CLI.

use rusqlite::Connection;

use crate::domain::{uuid_v4, valid_username};
use crate::secret::{new_token, random_bytes};
use crate::store::{self, User, UserId};

/// Setup tokens expire 15 minutes after creation (SPEC §6.6); fixed, not configurable.
pub const SETUP_TOKEN_TTL_MS: i64 = 15 * 60 * 1000;
/// Pending WebAuthn ceremonies expire after 5 minutes (SPEC §5.1).
pub const CEREMONY_TTL_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, PartialEq, Eq)]
pub enum CreateUserError {
    InvalidUsername,
    Taken,
}

pub fn create_user(
    conn: &Connection,
    username: &str,
    now: i64,
) -> anyhow::Result<Result<User, CreateUserError>> {
    if !valid_username(username) {
        return Ok(Err(CreateUserError::InvalidUsername));
    }
    let user = User {
        id: uuid_v4(random_bytes()),
        username: username.to_owned(),
        created_at: now,
    };
    Ok(if store::insert_user(conn, &user)? {
        Ok(user)
    } else {
        Err(CreateUserError::Taken)
    })
}

/// A new setup token for the user: the token (shown once) and when it expires.
pub fn issue_setup_token(
    conn: &Connection,
    user_id: &UserId,
    now: i64,
) -> rusqlite::Result<(String, i64)> {
    let (token, hash) = new_token();
    let expires_at = now + SETUP_TOKEN_TTL_MS;
    store::insert_setup_token(conn, &hash, user_id, now, expires_at)?;
    Ok((token, expires_at))
}

/// One setup link per public host. Loopback addresses have arbitrary ports, so they get none.
pub fn setup_links(public_hosts: &[String], token: &str) -> Vec<String> {
    public_hosts
        .iter()
        .map(|host| format!("https://{host}/#setup={token}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_built_for_public_hosts_only() {
        assert_eq!(setup_links(&[], "t"), Vec::<String>::new());
        assert_eq!(
            setup_links(&["pw.example.com".into(), "b.example.com:8443".into()], "t"),
            vec![
                "https://pw.example.com/#setup=t",
                "https://b.example.com:8443/#setup=t"
            ]
        );
    }
}
