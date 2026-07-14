use std::path::Path;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

use crate::signing::SigningKeyPair;
use crate::kem::KemKeyPair;
use crate::hashing::sha3_256_hex;
use crate::CryptoError;

/// PQC identity for an agent session.
pub struct SessionIdentity {
    pub session_id: String,
    pub agent_name: String,
    pub signing_keypair: SigningKeyPair,
    pub kem_keypair: KemKeyPair,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub request_count: u64,
    pub total_tokens: u64,
}

/// Serializable session info (without secret keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub agent_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub request_count: u64,
    pub total_tokens: u64,
    pub public_key_fingerprint: String,
}

impl SessionIdentity {
    /// Create a new session with fresh PQC key pairs.
    pub fn new(agent_name: &str, ttl_seconds: i64) -> Result<Self, CryptoError> {
        let now = Utc::now();
        let signing_keypair = SigningKeyPair::generate()?;
        let kem_keypair = KemKeyPair::generate()?;

        Ok(Self {
            session_id: Uuid::new_v4().to_string(),
            agent_name: agent_name.to_string(),
            signing_keypair,
            kem_keypair,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds),
            request_count: 0,
            total_tokens: 0,
        })
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Get public session info (safe to serialize).
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.session_id.clone(),
            agent_name: self.agent_name.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            request_count: self.request_count,
            total_tokens: self.total_tokens,
            public_key_fingerprint: sha3_256_hex(&self.signing_keypair.verifying_key_bytes()),
        }
    }

    /// Sign data with this session's signing key.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signing_keypair.sign(data)
    }

    /// Increment request counter.
    pub fn record_request(&mut self, tokens: u64) {
        self.request_count += 1;
        self.total_tokens += tokens;
    }
}

/// Master signing key for the gateway instance (used for audit signing).
pub struct GatewayIdentity {
    pub signing_keypair: SigningKeyPair,
    pub fingerprint: String,
}

impl GatewayIdentity {
    /// Generate a new gateway identity.
    pub fn generate() -> Result<Self, CryptoError> {
        let signing_keypair = SigningKeyPair::generate()?;
        let fingerprint = sha3_256_hex(&signing_keypair.verifying_key_bytes());
        Ok(Self {
            signing_keypair,
            fingerprint,
        })
    }

    /// Load from file or generate new if not present.
    pub fn load_or_generate(key_dir: &Path) -> Result<Self, CryptoError> {
        let pk_path = key_dir.join("gateway_public.key");
        let sk_path = key_dir.join("gateway_secret.key");

        if pk_path.exists() && sk_path.exists() {
            // For now, always generate fresh keys on startup
            // TODO: Implement key serialization/deserialization
            tracing::warn!("Key persistence not yet implemented, generating fresh keys");
        }

        let identity = Self::generate()?;

        // Create key directory if needed
        std::fs::create_dir_all(key_dir)?;

        // Save public key
        let pk_bytes = identity.signing_keypair.verifying_key_bytes();
        std::fs::write(&pk_path, &pk_bytes)?;

        tracing::info!(fingerprint = %identity.fingerprint, "Gateway identity initialized");
        Ok(identity)
    }

    /// Sign arbitrary data with ML-DSA-65.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signing_keypair.sign(data)
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_keypair.verifying_key_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = SessionIdentity::new("test-agent", 3600).unwrap();
        assert_eq!(session.agent_name, "test-agent");
        assert!(!session.is_expired());
        assert_eq!(session.request_count, 0);
    }

    #[test]
    fn test_session_info() {
        let session = SessionIdentity::new("test-agent", 3600).unwrap();
        let info = session.info();
        assert_eq!(info.agent_name, "test-agent");
        assert!(!info.public_key_fingerprint.is_empty());
        assert_eq!(info.public_key_fingerprint.len(), 64); // SHA3-256 hex
    }

    #[test]
    fn test_session_sign() {
        let session = SessionIdentity::new("test-agent", 3600).unwrap();
        let sig = session.sign(b"test data").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_gateway_identity() {
        let gw = GatewayIdentity::generate().unwrap();
        assert_eq!(gw.fingerprint.len(), 64);
        let sig = gw.sign(b"audit entry").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_session_expired() {
        let session = SessionIdentity::new("test-agent", -1).unwrap();
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_record_request() {
        let mut session = SessionIdentity::new("test-agent", 3600).unwrap();
        session.record_request(100);
        assert_eq!(session.request_count, 1);
        assert_eq!(session.total_tokens, 100);
        session.record_request(200);
        assert_eq!(session.request_count, 2);
        assert_eq!(session.total_tokens, 300);
    }
}
