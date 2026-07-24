//! Symmetric authenticated encryption for secrets at rest — integration tokens
//! and any stored credential. ChaCha20-Poly1305 (AEAD) with a fresh random
//! 96-bit nonce per value.
//!
//! The 256-bit data-encryption key is derived from operator-supplied key
//! material (env `QW_SECRET_KEY`) via SHA3-256 with domain separation, so key
//! material of any length yields a uniform key and a blank value is rejected
//! rather than silently producing a guessable key.
//!
//! Ciphertext is self-describing: `qwsec1:<base64(nonce ‖ ciphertext‖tag)>`.
//! A value without that prefix is treated as legacy plaintext, so turning
//! encryption on transparently migrates existing rows the next time they are
//! written, and reads keep working throughout.

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::error::CryptoError;
use crate::hashing::sha3_256;

const PREFIX: &str = "qwsec1:";
const NONCE_LEN: usize = 12;

/// An at-rest encryptor for short secret strings. Cheap to clone; holds only
/// the derived key.
#[derive(Clone)]
pub struct SecretCipher {
    key: Key,
}

impl std::fmt::Debug for SecretCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the key through Debug (it lands in logs and panics).
        f.write_str("SecretCipher(<redacted>)")
    }
}

impl SecretCipher {
    /// Derive a cipher from arbitrary key material (e.g. the value of
    /// `QW_SECRET_KEY`). Empty or whitespace-only material is rejected so a
    /// blank env var cannot silently yield a fixed, guessable key.
    pub fn from_key_material(material: &str) -> Result<Self, CryptoError> {
        let m = material.trim();
        if m.is_empty() {
            return Err(CryptoError::Other(
                "empty QW_SECRET_KEY material".to_string(),
            ));
        }
        let digest = sha3_256(format!("quantawatch/secret-at-rest/v1:{m}").as_bytes());
        Ok(Self {
            key: *Key::from_slice(&digest),
        })
    }

    /// True if `s` was produced by [`SecretCipher::encrypt`].
    pub fn is_ciphertext(s: &str) -> bool {
        s.starts_with(PREFIX)
    }

    /// Encrypt a plaintext secret. An empty string passes through unchanged
    /// (nothing to protect) and an already-encrypted value is returned as-is,
    /// so the call is idempotent and safe to apply on every write.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        if plaintext.is_empty() || Self::is_ciphertext(plaintext) {
            return Ok(plaintext.to_string());
        }
        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| CryptoError::Other(format!("rng failed: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| CryptoError::Other(format!("encrypt failed: {e}")))?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        ))
    }

    /// Decrypt a value produced by [`SecretCipher::encrypt`]. A value without
    /// the `qwsec1:` prefix is returned unchanged (legacy plaintext), so reads
    /// keep working while stored rows are migrated lazily. A prefixed value
    /// that fails authentication is a hard error (wrong key or tampering).
    pub fn decrypt(&self, stored: &str) -> Result<String, CryptoError> {
        let Some(b64) = stored.strip_prefix(PREFIX) else {
            return Ok(stored.to_string());
        };
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| CryptoError::Other(format!("bad ciphertext encoding: {e}")))?;
        if blob.len() < NONCE_LEN {
            return Err(CryptoError::Other("ciphertext too short".to_string()));
        }
        let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(&self.key);
        let pt = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|_| CryptoError::Other("decrypt/authentication failed".to_string()))?;
        String::from_utf8(pt).map_err(|e| CryptoError::Other(format!("invalid utf8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_secret() {
        let c = SecretCipher::from_key_material("hunter2-master-key").unwrap();
        let token = "ghp_ABCdef0123456789";
        let enc = c.encrypt(token).unwrap();
        assert!(SecretCipher::is_ciphertext(&enc), "output must be tagged");
        assert!(
            !enc.contains(token),
            "plaintext must not appear in ciphertext"
        );
        assert_eq!(c.decrypt(&enc).unwrap(), token);
    }

    #[test]
    fn nonce_makes_ciphertext_non_deterministic() {
        let c = SecretCipher::from_key_material("k").unwrap();
        assert_ne!(c.encrypt("same").unwrap(), c.encrypt("same").unwrap());
    }

    #[test]
    fn empty_and_already_encrypted_pass_through() {
        let c = SecretCipher::from_key_material("k").unwrap();
        assert_eq!(c.encrypt("").unwrap(), "");
        let once = c.encrypt("x").unwrap();
        assert_eq!(c.encrypt(&once).unwrap(), once, "encrypt is idempotent");
    }

    #[test]
    fn legacy_plaintext_reads_through() {
        let c = SecretCipher::from_key_material("k").unwrap();
        // A row written before encryption was enabled has no prefix.
        assert_eq!(
            c.decrypt("legacy-plain-token").unwrap(),
            "legacy-plain-token"
        );
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let a = SecretCipher::from_key_material("key-a").unwrap();
        let b = SecretCipher::from_key_material("key-b").unwrap();
        let enc = a.encrypt("secret").unwrap();
        assert!(b.decrypt(&enc).is_err(), "wrong key must not decrypt");
    }

    #[test]
    fn blank_key_material_is_rejected() {
        assert!(SecretCipher::from_key_material("   ").is_err());
    }
}
