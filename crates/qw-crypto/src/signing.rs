use crate::CryptoError;
use ml_dsa::{KeyGen, KeyPair, MlDsa65};

/// ML-DSA-65 signing key pair (FIPS 204, security category 3).
pub struct SigningKeyPair {
    keypair: KeyPair<MlDsa65>,
}

impl SigningKeyPair {
    /// Generate a new ML-DSA-65 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let keypair = MlDsa65::key_gen(&mut rng);
        Ok(Self { keypair })
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
}
