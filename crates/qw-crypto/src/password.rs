//! Password hashing (Argon2id) and random token generation for auth.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

use crate::error::CryptoError;

fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|e| CryptoError::Other(format!("rng failed: {e}")))
}

/// Hash a password with Argon2id, producing a PHC-format string suitable for
/// storage in config (`$argon2id$...`).
///
/// The salt is drawn from the system RNG via getrandom and encoded directly,
/// avoiding the rand_core version skew between `password_hash` and the
/// PQC crates' RNG.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let mut salt_bytes = [0u8; 16];
    fill_random(&mut salt_bytes)?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| CryptoError::Other(format!("salt encode failed: {e}")))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CryptoError::Other(format!("argon2 hash failed: {e}")))
}

/// Verify a password against a stored PHC hash. Returns false on any error
/// (malformed hash, mismatch) rather than leaking which.
pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    match PasswordHash::new(phc_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Generate a URL-safe random token of `bytes` entropy (hex-encoded).
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    // Fall back to a uuid-derived value only if the OS RNG is unavailable.
    if fill_random(&mut buf).is_err() {
        return uuid::Uuid::new_v4().simple().to_string();
    }
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(!verify_password("anything", "not-a-phc-hash"));
    }

    #[test]
    fn random_token_is_unique_and_sized() {
        let a = random_token(32);
        let b = random_token(32);
        assert_eq!(a.len(), 64); // 32 bytes -> 64 hex chars
        assert_ne!(a, b);
    }
}
