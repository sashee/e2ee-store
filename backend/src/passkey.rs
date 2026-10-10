//! WebAuthn ceremonies (SPEC §6.2), on top of `webauthn_rp`.
//!
//! Ceremony state is serialized so it can live in the `ceremonies` table, keyed by its challenge: the
//! browser's response carries the challenge, so no separate ceremony ID is needed.
//!
//! The options are the ones the Android app's authenticator can satisfy (ES256 offered, `none`
//! attestation, no `credProtect`, a counter that never moves) and nothing the server didn't ask for is
//! refused: the client adds the `prf` extension itself (SPEC §6.3), so its results and the authenticator's
//! `hmac-secret` output must not fail verification.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use webauthn_rp::bin::{Decode as _, Encode as _};
use webauthn_rp::request::auth::AuthenticationVerificationOptions;
use webauthn_rp::request::register::{
    CredProtect, Nickname, PublicKeyCredentialUserEntity, RegistrationVerificationOptions,
    UserHandle16, Username,
};
use webauthn_rp::request::{
    AsciiDomain, DomainOrigin, Port, PublicKeyCredentialDescriptor, RpId, Scheme,
    TimedCeremony as _,
};
use webauthn_rp::response::auth::ser_relaxed::DiscoverableAuthenticationRelaxed16;
use webauthn_rp::response::register::ser_relaxed::RegistrationRelaxed;
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{AuthTransports, CredentialId, SentChallenge};
use webauthn_rp::{
    AuthenticatedCredential, DiscoverableAuthentication16, DiscoverableAuthenticationServerState,
    DiscoverableCredentialRequestOptions, PublicKeyCredentialCreationOptions, Registration,
    RegistrationServerState,
};

use crate::domain::Site;

#[derive(Debug)]
pub enum PasskeyError {
    /// The host can't be used as an RP ID.
    BadRpId,
    /// The username can't be used as a WebAuthn account name.
    BadUsername,
    /// The response didn't parse.
    Malformed(String),
    /// The response parsed but didn't verify, or stored state didn't decode.
    Refused(String),
}

impl fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRpId => f.write_str("the host can't be a WebAuthn RP ID"),
            Self::BadUsername => f.write_str("the username can't be a WebAuthn account name"),
            Self::Malformed(e) => write!(f, "malformed response: {e}"),
            Self::Refused(e) => write!(f, "verification failed: {e}"),
        }
    }
}

/// A started ceremony: what to store and what to send.
pub struct Started {
    pub challenge: [u8; 16],
    pub state: Vec<u8>,
    pub options: serde_json::Value,
    /// When the library itself stops accepting the response, in unix ms.
    pub expires_at: i64,
}

/// What a verified registration stores.
pub struct Registered {
    pub credential_id: Vec<u8>,
    pub static_state: Vec<u8>,
    pub dynamic_state: Vec<u8>,
}

fn challenge_bytes(challenge: SentChallenge) -> [u8; 16] {
    challenge.0.to_le_bytes()
}

fn unix_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn rp_id(site: &Site) -> Result<RpId, PasskeyError> {
    AsciiDomain::try_from(site.rp_id.clone())
        .map(RpId::Domain)
        .map_err(|_| PasskeyError::BadRpId)
}

/// The origin the browser signed for. The host check has already matched `Origin` to `Host`.
fn origin(site: &Site) -> DomainOrigin<'_, '_> {
    DomainOrigin {
        scheme: if site.secure {
            Scheme::Https
        } else {
            Scheme::Other("http")
        },
        host: &site.rp_id,
        port: site.port.map_or(Port::None, Port::Val),
    }
}

fn user_handle(user_id: [u8; 16]) -> UserHandle16 {
    let Ok(handle) = UserHandle16::decode(user_id);
    handle
}

fn refused(e: impl fmt::Debug) -> PasskeyError {
    PasskeyError::Refused(format!("{e:?}"))
}

// ---------------------------------------------------------------- registration

pub fn start_registration(
    site: &Site,
    user_id: [u8; 16],
    username: &str,
    existing: &[Vec<u8>],
) -> Result<Started, PasskeyError> {
    let rp_id = rp_id(site)?;
    let handle = user_handle(user_id);
    let entity = PublicKeyCredentialUserEntity {
        name: Username::try_from(username).map_err(|_| PasskeyError::BadUsername)?,
        id: &handle,
        display_name: Nickname::try_from(username).ok(),
    };
    let no_transports = AuthTransports::decode(0)
        .unwrap_or_else(|_| unreachable!("0 is the empty set of transports"));
    let exclude = existing
        .iter()
        .filter_map(|id| CredentialId::<Vec<u8>>::decode(id.clone()).ok())
        .map(|id| PublicKeyCredentialDescriptor {
            id,
            transports: no_transports,
        })
        .collect();

    let mut options = PublicKeyCredentialCreationOptions::passkey(&rp_id, entity, exclude);
    // The library requests and enforces credProtect by default; the Android app doesn't implement it.
    // User verification, which its strictest level would add, is required anyway.
    options.extensions.cred_protect = CredProtect::None;
    let (server, client) = options.start_ceremony().map_err(refused)?;
    Ok(Started {
        challenge: challenge_bytes(server.sent_challenge()),
        expires_at: unix_ms(server.expiration()),
        state: server.encode().map_err(refused)?,
        options: serde_json::to_value(&client)
            .map_err(|e| PasskeyError::Malformed(e.to_string()))?,
    })
}

/// Parses a registration response far enough to find its ceremony.
pub fn parse_registration(
    json: &serde_json::Value,
) -> Result<([u8; 16], Registration), PasskeyError> {
    let registration = serde_json::from_value::<RegistrationRelaxed>(json.clone())
        .map_err(|e| PasskeyError::Malformed(e.to_string()))?
        .0;
    let challenge = registration
        .challenge_relaxed()
        .map_err(|e| PasskeyError::Malformed(e.to_string()))?;
    Ok((challenge_bytes(challenge), registration))
}

pub fn finish_registration(
    state: &[u8],
    site: &Site,
    user_id: [u8; 16],
    registration: &Registration,
) -> Result<Registered, PasskeyError> {
    let server = RegistrationServerState::<16>::decode(state).map_err(refused)?;
    let origins = [origin(site)];
    let registered = server
        .verify(
            &rp_id(site)?,
            registration,
            &RegistrationVerificationOptions::<DomainOrigin<'_, '_>, &str> {
                allowed_origins: &origins,
                error_on_unsolicited_extensions: false,
                ..Default::default()
            },
        )
        .map_err(refused)?;
    if *registered.user_id() != user_handle(user_id) {
        return Err(PasskeyError::Refused(
            "the response names another user".into(),
        ));
    }
    let Ok(static_state) = registered.static_state().encode();
    let Ok(dynamic_state) = registered.dynamic_state().encode();
    Ok(Registered {
        credential_id: registered.id().as_ref().to_vec(),
        static_state,
        dynamic_state: dynamic_state.to_vec(),
    })
}

// ---------------------------------------------------------------- login

/// A discoverable login: no `allowCredentials`, no username.
pub fn start_login(site: &Site) -> Result<Started, PasskeyError> {
    let rp_id = rp_id(site)?;
    let (server, client) = DiscoverableCredentialRequestOptions::passkey(&rp_id)
        .start_ceremony()
        .map_err(refused)?;
    Ok(Started {
        challenge: challenge_bytes(server.sent_challenge()),
        expires_at: unix_ms(server.expiration()),
        state: server.encode().map_err(refused)?,
        options: serde_json::to_value(&client)
            .map_err(|e| PasskeyError::Malformed(e.to_string()))?,
    })
}

/// A parsed login response, so its credential and challenge can be looked up before verification.
pub struct Assertion(DiscoverableAuthentication16);

impl Assertion {
    pub fn parse(json: &serde_json::Value) -> Result<Self, PasskeyError> {
        serde_json::from_value::<DiscoverableAuthenticationRelaxed16>(json.clone())
            .map(|relaxed| Self(relaxed.0))
            .map_err(|e| PasskeyError::Malformed(e.to_string()))
    }

    pub fn challenge(&self) -> Result<[u8; 16], PasskeyError> {
        self.0
            .challenge_relaxed()
            .map(challenge_bytes)
            .map_err(|e| PasskeyError::Malformed(e.to_string()))
    }

    pub fn credential_id(&self) -> Vec<u8> {
        self.0.raw_id().as_ref().to_vec()
    }
}

/// The stored parts of a passkey that verification needs.
pub struct StoredCredential<'a> {
    pub id: &'a [u8],
    pub user_id: [u8; 16],
    pub static_state: &'a [u8],
    pub dynamic_state: &'a [u8],
}

/// Verifies a login. Returns the passkey's new dynamic state when verification changed it.
pub fn finish_login(
    state: &[u8],
    site: &Site,
    assertion: &Assertion,
    stored: &StoredCredential,
) -> Result<Option<Vec<u8>>, PasskeyError> {
    let server = DiscoverableAuthenticationServerState::decode(state).map_err(refused)?;
    let handle = user_handle(stored.user_id);
    let static_state =
        StaticState::<CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>>::decode(
            stored.static_state,
        )
        .map_err(refused)?;
    let dynamic_state = <[u8; 7]>::try_from(stored.dynamic_state)
        .ok()
        .and_then(|bytes| DynamicState::decode(bytes).ok())
        .ok_or_else(|| PasskeyError::Refused("the stored dynamic state doesn't decode".into()))?;
    let id = CredentialId::<&[u8]>::decode(stored.id).map_err(refused)?;
    // Checks the response's user handle against the passkey's owner.
    let mut credential =
        AuthenticatedCredential::new(id, &handle, static_state, dynamic_state).map_err(refused)?;
    let origins = [origin(site)];
    let changed = server
        .verify(
            &rp_id(site)?,
            &assertion.0,
            &mut credential,
            &AuthenticationVerificationOptions::<DomainOrigin<'_, '_>, &str> {
                allowed_origins: &origins,
                error_on_unsolicited_extensions: false,
                ..Default::default()
            },
        )
        .map_err(refused)?;
    let Ok(dynamic_state) = credential.dynamic_state().encode();
    Ok(changed.then(|| dynamic_state.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::classify_host;

    #[test]
    fn registration_options_suit_the_android_app() {
        let site = classify_host("abc.localhost:1234", &[]).unwrap();
        let started = start_registration(&site, [7; 16], "alice", &[vec![1; 16]]).unwrap();
        let options = &started.options;
        assert_eq!(options["rp"]["id"], "abc.localhost");
        assert!(
            options["pubKeyCredParams"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["alg"] == -7)
        );
        assert_eq!(options["extensions"], serde_json::json!({}));
        assert_eq!(
            options["authenticatorSelection"]["userVerification"],
            "required"
        );
        assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(options["attestation"], "none");
        assert_eq!(options["excludeCredentials"].as_array().unwrap().len(), 1);
        assert!(RegistrationServerState::<16>::decode(started.state.as_slice()).is_ok());
    }

    #[test]
    fn login_options_are_discoverable() {
        let site = classify_host("localhost:8080", &[]).unwrap();
        let started = start_login(&site).unwrap();
        assert_eq!(started.options["rpId"], "localhost");
        assert_eq!(started.options["userVerification"], "required");
        assert_eq!(started.options["allowCredentials"], serde_json::json!([]));
        assert!(DiscoverableAuthenticationServerState::decode(started.state.as_slice()).is_ok());
    }
}
