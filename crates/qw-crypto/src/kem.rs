use ml_kem::{MlKem768, DecapsulationKey, EncapsulationKey, Ciphertext};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, Generate};
use crate::CryptoError;

/// ML-KEM-768 key pair (FIPS 203, security category 3).
pub struct KemKeyPair {
    dk: DecapsulationKey<MlKem768>,
    ek: EncapsulationKey<MlKem768>,
}

impl KemKeyPair {
    /// Generate a new ML-KEM-768 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let dk = DecapsulationKey::<MlKem768>::generate_from_rng(&mut rng);
        let ek = dk.encapsulation_key().clone();
        Ok(Self { dk, ek })
    }

    /// Get the encapsulation (public) key bytes.
    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.ek.to_bytes().to_vec()
    }

    /// Encapsulate: generate a shared secret and ciphertext.
    /// Returns (ciphertext_bytes, shared_secret_bytes).
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (ct, ss) = self.ek.encapsulate_with_rng(&mut rng);
        let ct_bytes: &[u8] = ct.as_ref();
        let ss_bytes: &[u8] = ss.as_ref();
        Ok((ct_bytes.to_vec(), ss_bytes.to_vec()))
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ct = Ciphertext::<MlKem768>::try_from(ciphertext_bytes)
            .map_err(|_| CryptoError::Decapsulation("invalid ciphertext length".to_string()))?;
        let ss = self.dk.decapsulate(&ct);
        let ss_bytes: &[u8] = ss.as_ref();
        Ok(ss_bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let kp = KemKeyPair::generate().unwrap();
        let (ct, ss_enc) = kp.encapsulate().unwrap();
        let ss_dec = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_kem_different_keys_different_secrets() {
        let kp1 = KemKeyPair::generate().unwrap();
        let kp2 = KemKeyPair::generate().unwrap();
        let (_, ss1) = kp1.encapsulate().unwrap();
        let (_, ss2) = kp2.encapsulate().unwrap();
        assert_ne!(ss1, ss2);
    }
}
