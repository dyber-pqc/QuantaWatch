use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

use crate::hashing::sha3_256_hex;
use crate::kem::KemKeyPair;
use crate::signing::SigningKeyPair;
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

/// Write secret material, restricting it to the owner where the OS supports it.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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

    /// Reconstruct the identity from its 32-byte FIPS 204 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_keypair = SigningKeyPair::from_seed(seed)?;
        let fingerprint = sha3_256_hex(&signing_keypair.verifying_key_bytes());
        Ok(Self {
            signing_keypair,
            fingerprint,
        })
    }

    /// Load the identity from `key_dir`, or generate and persist a new one.
    ///
    /// Persists the 32-byte seed (`gateway_seed.key`, 0600) rather than the
    /// expanded key. A *stable* identity matters: the audit hash chain and the
    /// CBOM attestation are signed with it, so regenerating on every start
    /// would make every pre-restart signature unverifiable.
    pub fn load_or_generate(key_dir: &Path) -> Result<Self, CryptoError> {
        let seed_path = key_dir.join("gateway_seed.key");
        let pk_path = key_dir.join("gateway_public.key");

        if let Ok(bytes) = std::fs::read(&seed_path) {
            match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(seed) => {
                    let identity = Self::from_seed(&seed)?;
                    tracing::info!(
                        fingerprint = %identity.fingerprint,
                        "Gateway identity loaded from disk"
                    );
                    return Ok(identity);
                }
                Err(_) => tracing::warn!(
                    path = %seed_path.display(),
                    "gateway seed is not 32 bytes; generating a new identity"
                ),
            }
        }

        let identity = Self::generate()?;
        std::fs::create_dir_all(key_dir)?;
        write_secret(&seed_path, identity.signing_keypair.seed())?;
        std::fs::write(&pk_path, identity.public_key_bytes())?;

        tracing::info!(
            fingerprint = %identity.fingerprint,
            "Gateway identity generated and persisted"
        );
        Ok(identity)
    }

    /// Load the identity from a hex-encoded 32-byte seed held in `env_var`,
    /// falling back to `key_dir`.
    ///
    /// This is the seam for shared/externally-managed keys: point `env_var` at
    /// a Kubernetes Secret or a KMS-injected value and every replica derives
    /// the *same* signing identity — a prerequisite for running more than one
    /// gateway behind a load balancer.
    pub fn load_from_env_or_dir(env_var: &str, key_dir: &Path) -> Result<Self, CryptoError> {
        match std::env::var(env_var) {
            Ok(encoded) => {
                let raw = hex::decode(encoded.trim()).map_err(|e| {
                    CryptoError::Serialization(format!("{env_var} is not valid hex: {e}"))
                })?;
                let seed = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
                    CryptoError::Serialization(format!(
                        "{env_var} must decode to exactly 32 bytes (got {})",
                        raw.len()
                    ))
                })?;
                let identity = Self::from_seed(&seed)?;
                tracing::info!(
                    fingerprint = %identity.fingerprint,
                    source = env_var,
                    "Gateway identity loaded from environment"
                );
                Ok(identity)
            }
            Err(_) => Self::load_or_generate(key_dir),
        }
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
    fn gateway_identity_is_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();

        // First boot: generates and persists the seed.
        let first = GatewayIdentity::load_or_generate(dir.path()).unwrap();
        let sig = first.sign(b"audit entry written before restart").unwrap();

        // Second boot from the same key_dir: must be the SAME identity, and
        // signatures written before the restart must still verify.
        let second = GatewayIdentity::load_or_generate(dir.path()).unwrap();
        assert_eq!(
            first.fingerprint, second.fingerprint,
            "identity must survive a restart, or the audit chain becomes unverifiable"
        );
        assert!(crate::signing::verify(
            &second.public_key_bytes(),
            b"audit entry written before restart",
            &sig
        )
        .unwrap());
    }

    #[test]
    fn gateway_identity_persists_seed_not_expanded_key() {
        let dir = tempfile::tempdir().unwrap();
        GatewayIdentity::load_or_generate(dir.path()).unwrap();
        let seed = std::fs::read(dir.path().join("gateway_seed.key")).unwrap();
        assert_eq!(seed.len(), 32, "we persist the 32-byte FIPS 204 seed");
        // The public key is also written for external verifiers.
        assert!(dir.path().join("gateway_public.key").exists());
    }

    #[test]
    fn corrupt_seed_falls_back_to_a_fresh_identity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gateway_seed.key"), b"too short").unwrap();
        // Must not panic; regenerates instead.
        let id = GatewayIdentity::load_or_generate(dir.path()).unwrap();
        assert_eq!(id.fingerprint.len(), 64);
    }

    #[test]
    fn replicas_sharing_a_seed_env_derive_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [42u8; 32];
        let var = "QW_TEST_SEED_SHARED";
        std::env::set_var(var, hex::encode(seed));

        // Two "replicas" booting from the same Secret-provided seed.
        let a = GatewayIdentity::load_from_env_or_dir(var, dir.path()).unwrap();
        let b = GatewayIdentity::load_from_env_or_dir(var, dir.path()).unwrap();
        std::env::remove_var(var);

        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(
            a.fingerprint,
            GatewayIdentity::from_seed(&seed).unwrap().fingerprint
        );
    }

    #[test]
    fn bad_seed_env_is_an_error_not_a_silent_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let var = "QW_TEST_SEED_BAD";
        std::env::set_var(var, "not-hex!!");
        let res = GatewayIdentity::load_from_env_or_dir(var, dir.path());
        std::env::remove_var(var);
        assert!(res.is_err(), "a misconfigured seed must fail loudly");
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
