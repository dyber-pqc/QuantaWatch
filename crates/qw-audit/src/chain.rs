use qw_crypto::{sha3_256_hex, MerkleTree};

/// Manages the hash chain state for audit entries.
pub struct AuditChain {
    last_hash: String,
    sequence: u64,
    batch_buffer: Vec<[u8; 32]>,
    batch_size: usize,
}

impl AuditChain {
    pub fn new(batch_size: usize) -> Self {
        Self {
            last_hash: String::new(),
            sequence: 0,
            batch_buffer: Vec::new(),
            batch_size,
        }
    }

    /// Resume from a known state.
    pub fn resume(last_hash: String, sequence: u64, batch_size: usize) -> Self {
        Self {
            last_hash,
            sequence,
            batch_buffer: Vec::new(),
            batch_size,
        }
    }

    /// Get the hash of the previous entry.
    pub fn prev_hash(&self) -> &str {
        &self.last_hash
    }

    /// Get the next sequence number.
    pub fn next_sequence(&self) -> u64 {
        self.sequence
    }

    /// Record a new entry's content hash, advance the chain.
    /// Returns Some(merkle_root) if a batch boundary was reached.
    pub fn advance(&mut self, content_hash: &str) -> Option<String> {
        self.last_hash = content_hash.to_string();
        self.sequence += 1;

        // Add to Merkle batch buffer
        let hash_bytes = qw_crypto::sha3_256(content_hash.as_bytes());
        self.batch_buffer.push(hash_bytes);

        // Check if batch is complete
        if self.batch_buffer.len() >= self.batch_size {
            let root = MerkleTree::compute_root(&self.batch_buffer);
            self.batch_buffer.clear();
            Some(hex::encode(root))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_advance() {
        let mut chain = AuditChain::new(4);
        assert_eq!(chain.next_sequence(), 0);
        assert_eq!(chain.prev_hash(), "");

        let root = chain.advance("hash1");
        assert!(root.is_none());
        assert_eq!(chain.next_sequence(), 1);
        assert_eq!(chain.prev_hash(), "hash1");

        chain.advance("hash2");
        chain.advance("hash3");
        let root = chain.advance("hash4");
        assert!(root.is_some()); // Batch of 4 complete
        assert_eq!(chain.next_sequence(), 4);
    }

    #[test]
    fn test_chain_resume() {
        let chain = AuditChain::resume("prev_hash".to_string(), 42, 64);
        assert_eq!(chain.next_sequence(), 42);
        assert_eq!(chain.prev_hash(), "prev_hash");
    }
}
