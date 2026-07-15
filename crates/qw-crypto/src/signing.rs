use crate::CryptoError;
use ml_dsa::{KeyGen, KeyPair, MlDsa65, B32};
use zeroize::Zeroize;

/// ML-DSA-65 signing key pair (FIPS 204, security category 3).
///
/// The 32-byte FIPS 204 seed (ξ) is retained alongside the expanded key so the
/// identity can be persisted and reconstructed byte-for-byte. That is what
/// makes a *stable* gateway identity possible — without it the audit hash chain
/// becomes unverifiable after a restart, and horizontally-scaled replicas each
/// sign with a different key.
pub struct SigningKeyPair {
    keypair: KeyPair<MlDsa65>,
    seed: [u8; 32],
}

impl SigningKeyPair {
    /// Generate a new ML-DSA-65 key pair from a fresh random seed.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| CryptoError::KeyGeneration(format!("rng failed: {e}")))?;
        let kp = Self::from_seed(&seed)?;
        seed.zeroize();
        Ok(kp)
    }

    /// Deterministically reconstruct the key pair from its 32-byte FIPS 204
    /// seed (ML-DSA.KeyGen_internal, Algorithm 6).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let mut xi = B32::default();
        xi.copy_from_slice(seed);
        let keypair = MlDsa65::from_seed(&xi);
        xi.zeroize();
        Ok(Self {
            keypair,
            seed: *seed,
        })
    }

    /// The 32-byte seed this key was derived from.
    ///
    /// **Secret material** — persist it only somewhere a secret belongs (0600
    /// file, Kubernetes Secret, KMS/HSM). Never log or export it.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Sign a message with ML-DSA-65 (deterministic).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = self
            .keypair
            .signing_key()
            .sign_deterministic(message, &[])
            .map_err(|e| CryptoError::Signing(format!("{e:?}")))?;
        Ok(sig.encode().to_vec())
    }

    /// Get the verifying (public) key bytes.
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.keypair.verifying_key().encode().to_vec()
    }

    /// Verify a signature against this key pair's public key.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<bool, CryptoError> {
        verify(&self.verifying_key_bytes(), message, signature_bytes)
    }
}

/// Zeroize the retained seed when the key pair is dropped (the expanded
/// ml-dsa `SigningKey` already zeroizes itself).
impl Drop for SigningKeyPair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Sign a message with ML-DSA-65 using a key pair.
pub fn sign(keypair: &SigningKeyPair, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    keypair.sign(message)
}

/// Verify an ML-DSA-65 signature given raw public key bytes.
pub fn verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, CryptoError> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};

    let vk_encoded = EncodedVerifyingKey::<MlDsa65>::try_from(public_key_bytes)
        .map_err(|_| CryptoError::Verification("invalid public key length".to_string()))?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_encoded);

    let sig_encoded = EncodedSignature::<MlDsa65>::try_from(signature_bytes)
        .map_err(|_| CryptoError::Verification("invalid signature length".to_string()))?;
    let sig = match Signature::<MlDsa65>::decode(&sig_encoded) {
        Some(s) => s,
        None => {
            return Err(CryptoError::Verification(
                "invalid signature encoding".to_string(),
            ))
        }
    };

    Ok(vk.verify_with_context(message, &[], &sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = SigningKeyPair::generate().unwrap();
        let message = b"hello quantawatch";
        let sig = kp.sign(message).unwrap();
        assert!(kp.verify(message, &sig).unwrap());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(b"correct message").unwrap();
        assert!(!kp.verify(b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let kp1 = SigningKeyPair::generate().unwrap();
        let kp2 = SigningKeyPair::generate().unwrap();
        let sig = kp1.sign(b"message").unwrap();
        assert!(!verify(&kp2.verifying_key_bytes(), b"message", &sig).unwrap());
    }

    #[test]
    fn test_deterministic_public_key() {
        let kp = SigningKeyPair::generate().unwrap();
        let pk1 = kp.verifying_key_bytes();
        let pk2 = kp.verifying_key_bytes();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn seed_roundtrip_reconstructs_the_same_key() {
        let original = SigningKeyPair::generate().unwrap();
        let seed = *original.seed();

        // Reconstruct from the seed alone — as a restarted process (or a second
        // replica reading the same Secret) would.
        let restored = SigningKeyPair::from_seed(&seed).unwrap();
        assert_eq!(
            original.verifying_key_bytes(),
            restored.verifying_key_bytes(),
            "same seed must yield the same public key"
        );

        // A signature made before the "restart" verifies under the restored key.
        let sig = original.sign(b"audit entry 1").unwrap();
        assert!(restored.verify(b"audit entry 1", &sig).unwrap());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [7u8; 32];
        let a = SigningKeyPair::from_seed(&seed).unwrap();
        let b = SigningKeyPair::from_seed(&seed).unwrap();
        assert_eq!(a.verifying_key_bytes(), b.verifying_key_bytes());
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let a = SigningKeyPair::from_seed(&[1u8; 32]).unwrap();
        let b = SigningKeyPair::from_seed(&[2u8; 32]).unwrap();
        assert_ne!(a.verifying_key_bytes(), b.verifying_key_bytes());
    }
}
