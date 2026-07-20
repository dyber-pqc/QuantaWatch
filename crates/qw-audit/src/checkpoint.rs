use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use qw_crypto::{sha3_256, sha3_256_hex, MerkleTree};

/// The tip (latest entry) of one writer's chain at checkpoint time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterTip {
    pub writer_id: String,
    /// Sequence of the tip entry (0-based); `count = seq + 1` entries exist.
    pub seq: u64,
    /// Content hash of the tip entry — the commitment to that writer's chain.
    pub content_hash: String,
}

/// A periodic, signed, global commitment across every writer's chain.
///
/// Each checkpoint Merkle-roots the current tips of all writer chains and links
/// to the previous checkpoint, forming a second hash chain over the shards. This
/// is what gives global tamper-evidence in the sharded model: dropping a writer,
/// truncating its history, or rewriting entries below a committed tip all break a
/// checkpoint. Checkpoints are created serialized (one global sequence) so every
/// replica sees the same anchor chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub checkpoint_seq: u64,
    pub timestamp: DateTime<Utc>,
    /// Writer tips committed by this checkpoint, sorted by `writer_id`.
    pub tips: Vec<WriterTip>,
    /// Merkle root over the (sorted) tip content hashes.
    pub merkle_root: String,
    /// Content hash of the previous checkpoint (empty for the first).
    pub prev_checkpoint_hash: String,
    pub content_hash: String,
    pub signature: String,
}

impl AuditCheckpoint {
    /// Merkle root over a set of writer tips (order-independent: tips are sorted
    /// by writer_id first, so the root is deterministic regardless of input order).
    pub fn merkle_root_of(tips: &[WriterTip]) -> String {
        let mut sorted: Vec<&WriterTip> = tips.iter().collect();
        sorted.sort_by(|a, b| a.writer_id.cmp(&b.writer_id));
        let leaves: Vec<[u8; 32]> = sorted
            .iter()
            .map(|t| sha3_256(format!("{}:{}:{}", t.writer_id, t.seq, t.content_hash).as_bytes()))
            .collect();
        if leaves.is_empty() {
            // Deterministic empty-set root.
            return sha3_256_hex(b"quantawatch-audit-empty-checkpoint");
        }
        hex::encode(MerkleTree::compute_root(&leaves))
    }

    /// Build an unsigned checkpoint (content_hash computed, signature empty).
    /// `sign_hash` is left to the caller so the signing identity stays in the
    /// gateway, not the store.
    pub fn build(
        checkpoint_seq: u64,
        prev_checkpoint_hash: &str,
        tips: Vec<WriterTip>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let mut tips = tips;
        tips.sort_by(|a, b| a.writer_id.cmp(&b.writer_id));
        let merkle_root = Self::merkle_root_of(&tips);
        let mut cp = Self {
            checkpoint_seq,
            timestamp,
            tips,
            merkle_root,
            prev_checkpoint_hash: prev_checkpoint_hash.to_string(),
            content_hash: String::new(),
            signature: String::new(),
        };
        cp.content_hash = sha3_256_hex(&cp.content_bytes());
        cp
    }

    /// Bytes hashed and signed (everything except content_hash + signature).
    pub fn content_bytes(&self) -> Vec<u8> {
        let content = serde_json::json!({
            "checkpoint_seq": self.checkpoint_seq,
            "timestamp": self.timestamp.to_rfc3339(),
            "tips": self.tips,
            "merkle_root": self.merkle_root,
            "prev_checkpoint_hash": self.prev_checkpoint_hash,
        });
        serde_json::to_vec(&content).unwrap_or_default()
    }
}
