//! Secret tokens (sessions, setup tokens): 32 random bytes as base64url; only the SHA-256 is stored.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    bytes
}

/// A new token and the hash to store for it.
pub fn new_token() -> (String, [u8; 32]) {
    let bytes = random_bytes::<32>();
    (B64.encode(bytes), Sha256::digest(bytes).into())
}

/// The stored hash for a presented token. `None` when it isn't 32 bytes of base64url, so a malformed
/// token never reaches the database.
pub fn token_hash(token: &str) -> Option<[u8; 32]> {
    let bytes = B64.decode(token.trim()).ok().filter(|b| b.len() == 32)?;
    Some(Sha256::digest(bytes).into())
}

pub fn b64url(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn from_b64url(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_hashes_to_what_was_stored() {
        let (token, hash) = new_token();
        assert_eq!(token.len(), 43);
        assert_eq!(token_hash(&token), Some(hash));
        assert_eq!(token_hash("short"), None);
        assert_eq!(token_hash(&format!("{token}A")), None);
    }
}
