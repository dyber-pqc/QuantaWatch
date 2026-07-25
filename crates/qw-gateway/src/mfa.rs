//! Two-factor auth primitives: TOTP (RFC 6238) + one-time backup recovery codes.
//!
//! Secrets are base32 (what authenticator apps expect); backup codes are only
//! ever persisted as SHA3-256 hashes and consumed on use.

use qw_crypto::{random_token, sha3_256_hex};
use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "QuantaWatch";
/// Number of one-time backup codes issued at enrollment.
pub const BACKUP_CODE_COUNT: usize = 10;

/// Generate a fresh base32 TOTP secret to hand to the user's authenticator app.
pub fn generate_secret() -> String {
    match Secret::generate_secret().to_encoded() {
        Secret::Encoded(s) => s,
        // to_encoded() always yields Encoded; Raw is unreachable here.
        Secret::Raw(bytes) => Secret::Raw(bytes).to_encoded().to_string(),
    }
}

fn build(secret_b32: &str, account: &str) -> Result<TOTP, String> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| format!("invalid TOTP secret: {e:?}"))?;
    TOTP::new(
        Algorithm::SHA1, // what Google Authenticator / most apps default to
        6,
        1, // ±1 step (30s) skew tolerance
        30,
        bytes,
        Some(ISSUER.to_string()),
        account.to_string(),
    )
    .map_err(|e| format!("totp init: {e}"))
}

/// The `otpauth://` provisioning URL (render as a QR, or show the secret for
/// manual entry).
pub fn otpauth_url(secret_b32: &str, account: &str) -> Result<String, String> {
    Ok(build(secret_b32, account)?.get_url())
}

/// Verify a 6-digit TOTP code for `secret`/`account` (tolerates ±1 time step).
pub fn verify_totp(secret_b32: &str, account: &str, code: &str) -> bool {
    match build(secret_b32, account) {
        Ok(t) => t.check_current(code.trim()).unwrap_or(false),
        Err(_) => false,
    }
}

/// Generate `BACKUP_CODE_COUNT` recovery codes: returns `(plaintext, hashes)`.
/// Show the plaintext to the user exactly once; persist only the hashes.
pub fn generate_backup_codes() -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::with_capacity(BACKUP_CODE_COUNT);
    let mut hashes = Vec::with_capacity(BACKUP_CODE_COUNT);
    for _ in 0..BACKUP_CODE_COUNT {
        // 10 hex chars, grouped for readability: "a1b2c-3d4e5".
        let raw = random_token(5);
        let code = format!("{}-{}", &raw[..5], &raw[5..]);
        hashes.push(hash_backup_code(&code));
        plain.push(code);
    }
    (plain, hashes)
}

/// Hash a backup code for storage / lookup (normalized: trimmed, lowercased).
pub fn hash_backup_code(code: &str) -> String {
    sha3_256_hex(code.trim().to_lowercase().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrips_and_verifies() {
        let secret = generate_secret();
        // A URL is produced and carries the issuer.
        let url = otpauth_url(&secret, "admin@host").unwrap();
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("QuantaWatch"));
        // The current code from the same secret verifies.
        let t = build(&secret, "admin@host").unwrap();
        let now = t.generate_current().unwrap();
        assert!(verify_totp(&secret, "admin@host", &now));
        // A wrong code does not.
        assert!(!verify_totp(&secret, "admin@host", "000000"));
    }

    #[test]
    fn backup_codes_are_hashed_and_matchable() {
        let (plain, hashes) = generate_backup_codes();
        assert_eq!(plain.len(), BACKUP_CODE_COUNT);
        assert_eq!(hashes.len(), BACKUP_CODE_COUNT);
        // Plaintext is never equal to its stored hash.
        assert!(plain.iter().zip(&hashes).all(|(p, h)| p != h));
        // Hash lookup matches (case/space-insensitive) and is unguessable.
        assert_eq!(hash_backup_code(&plain[0].to_uppercase()), hashes[0]);
        assert!(!hashes.contains(&hash_backup_code("not-a-code")));
    }
}
