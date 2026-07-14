use sha3::{Digest, Sha3_256};

/// Compute SHA3-256 hash of data.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA3-256 hash and return as hex string.
pub fn sha3_256_hex(data: &[u8]) -> String {
    hex::encode(sha3_256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_deterministic() {
        let h1 = sha3_256(b"hello");
        let h2 = sha3_256(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha3_different_inputs() {
        let h1 = sha3_256(b"hello");
        let h2 = sha3_256(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sha3_hex_format() {
        let h = sha3_256_hex(b"test");
        assert_eq!(h.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sha3_known_vector() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let h = sha3_256_hex(b"");
        assert_eq!(
            h,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }
}
