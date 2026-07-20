use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::checkpoint::AuditCheckpoint;
use crate::entry::AuditEntry;
use crate::AuditError;
use qw_crypto::{sha3_256_hex, verify as verify_signature};

/// Result of audit chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub entries_checked: u64,
    pub signatures_valid: u64,
    pub chain_intact: bool,
    pub merkle_roots_valid: u64,
    pub errors: Vec<String>,
    /// Number of distinct writer chains checked (sharded model).
    #[serde(default)]
    pub writers_checked: u64,
    /// Number of global checkpoints checked (sharded model).
    #[serde(default)]
    pub checkpoints_checked: u64,
}

/// Verify the sharded audit log: every per-writer chain, plus the global
/// checkpoint chain that anchors them.
///
/// Each writer's entries are verified as an independent hash chain (content
/// hash, contiguous sequence, `prev_hash` linkage, ML-DSA signature). The
/// checkpoint chain is then verified (linkage, signature, Merkle root over the
/// tips it committed) and cross-checked against the entries: a tip a checkpoint
/// committed to must still be present and unchanged, which is what detects a
/// writer being dropped or its history rewritten below a committed point.
///
/// `entries` may be a partial tail (e.g. a size-capped export): linkage is
/// checked relative to entries present, so a sub-chain still verifies. A missing
/// entry that a checkpoint references is reported.
pub fn verify_sharded(
    entries: &[AuditEntry],
    checkpoints: &[AuditCheckpoint],
    public_key_bytes: &[u8],
) -> VerificationResult {
    let mut result = VerificationResult {
        valid: true,
        entries_checked: 0,
        signatures_valid: 0,
        chain_intact: true,
        merkle_roots_valid: 0,
        errors: Vec::new(),
        writers_checked: 0,
        checkpoints_checked: 0,
    };

    // Group entries by writer, keeping (seq -> entry) for cross-checks.
    let mut by_writer: BTreeMap<&str, Vec<&AuditEntry>> = BTreeMap::new();
    for e in entries {
        by_writer.entry(&e.writer_id).or_default().push(e);
    }
    // (writer_id, seq) -> content_hash, for checkpoint tip validation.
    let mut tip_index: BTreeMap<(&str, u64), &str> = BTreeMap::new();

    for (writer_id, mut chain) in by_writer {
        result.writers_checked += 1;
        chain.sort_by_key(|e| e.sequence);

        let mut prev_hash: Option<String> = None;
        let mut prev_seq: Option<u64> = None;
        for e in &chain {
            result.entries_checked += 1;
            tip_index.insert((writer_id, e.sequence), &e.content_hash);

            // Content hash integrity.
            let computed = sha3_256_hex(&e.content_bytes());
            if computed != e.content_hash {
                result.valid = false;
                result.chain_intact = false;
                result.errors.push(format!(
                    "writer {writer_id} entry {}: content hash mismatch",
                    e.sequence
                ));
            }

            // Sequence contiguity within the presented set.
            if let Some(ps) = prev_seq {
                if e.sequence != ps + 1 {
                    result.valid = false;
                    result.chain_intact = false;
                    result.errors.push(format!(
                        "writer {writer_id}: sequence gap {ps} -> {} (missing entries)",
                        e.sequence
                    ));
                }
            } else if e.sequence == 0 && !e.prev_hash.is_empty() {
                // Genesis entry must have an empty prev_hash.
                result.valid = false;
                result.chain_intact = false;
                result
                    .errors
                    .push(format!("writer {writer_id}: genesis prev_hash not empty"));
            }

            // Linkage to the previous entry in the set.
            if let Some(ph) = &prev_hash {
                if &e.prev_hash != ph {
                    result.valid = false;
                    result.chain_intact = false;
                    result.errors.push(format!(
                        "writer {writer_id} entry {}: chain broken (prev_hash mismatch)",
                        e.sequence
                    ));
                }
            }

            // Signature.
            match decode_and_verify(public_key_bytes, &e.content_hash, &e.signature) {
                Ok(true) => result.signatures_valid += 1,
                Ok(false) => {
                    result.valid = false;
                    result.errors.push(format!(
                        "writer {writer_id} entry {}: signature invalid",
                        e.sequence
                    ));
                }
                Err(msg) => {
                    result.valid = false;
                    result
                        .errors
                        .push(format!("writer {writer_id} entry {}: {msg}", e.sequence));
                }
            }

            prev_hash = Some(e.content_hash.clone());
            prev_seq = Some(e.sequence);
        }
    }

    // Verify the checkpoint chain.
    let mut cps: Vec<&AuditCheckpoint> = checkpoints.iter().collect();
    cps.sort_by_key(|c| c.checkpoint_seq);
    let mut prev_cp_hash: Option<String> = None;
    let mut prev_cp_seq: Option<u64> = None;
    for cp in cps {
        result.checkpoints_checked += 1;

        // Content hash + Merkle root integrity.
        let computed = sha3_256_hex(&cp.content_bytes());
        if computed != cp.content_hash {
            result.valid = false;
            result.errors.push(format!(
                "checkpoint {}: content hash mismatch",
                cp.checkpoint_seq
            ));
        }
        if AuditCheckpoint::merkle_root_of(&cp.tips) == cp.merkle_root {
            result.merkle_roots_valid += 1;
        } else {
            result.valid = false;
            result.errors.push(format!(
                "checkpoint {}: Merkle root mismatch",
                cp.checkpoint_seq
            ));
        }

        // Checkpoint-chain contiguity + linkage.
        if let Some(ps) = prev_cp_seq {
            if cp.checkpoint_seq != ps + 1 {
                result.valid = false;
                result.errors.push(format!(
                    "checkpoint chain: sequence gap {ps} -> {}",
                    cp.checkpoint_seq
                ));
            }
        }
        if let Some(ph) = &prev_cp_hash {
            if &cp.prev_checkpoint_hash != ph {
                result.valid = false;
                result.errors.push(format!(
                    "checkpoint {}: broken link to previous",
                    cp.checkpoint_seq
                ));
            }
        }

        // Signature.
        match decode_and_verify(public_key_bytes, &cp.content_hash, &cp.signature) {
            Ok(true) => {}
            Ok(false) => {
                result.valid = false;
                result.errors.push(format!(
                    "checkpoint {}: signature invalid",
                    cp.checkpoint_seq
                ));
            }
            Err(msg) => {
                result.valid = false;
                result
                    .errors
                    .push(format!("checkpoint {}: {msg}", cp.checkpoint_seq));
            }
        }

        // Each committed tip must still be present and unchanged.
        for tip in &cp.tips {
            match tip_index.get(&(tip.writer_id.as_str(), tip.seq)) {
                Some(h) if **h == tip.content_hash => {}
                Some(_) => {
                    result.valid = false;
                    result.chain_intact = false;
                    result.errors.push(format!(
                        "checkpoint {}: writer {} entry {} was altered since it was committed",
                        cp.checkpoint_seq, tip.writer_id, tip.seq
                    ));
                }
                None => {
                    result.valid = false;
                    result.chain_intact = false;
                    result.errors.push(format!(
                        "checkpoint {}: committed tip missing (writer {} entry {} dropped/truncated)",
                        cp.checkpoint_seq, tip.writer_id, tip.seq
                    ));
                }
            }
        }

        prev_cp_hash = Some(cp.content_hash.clone());
        prev_cp_seq = Some(cp.checkpoint_seq);
    }

    result
}

fn decode_and_verify(pk: &[u8], content_hash: &str, signature: &str) -> Result<bool, String> {
    let sig = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature)
        .map_err(|e| format!("invalid base64 signature: {e}"))?;
    verify_signature(pk, content_hash.as_bytes(), &sig).map_err(|e| format!("verify error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{AuditCheckpoint, WriterTip};
    use crate::entry::AuditEvent;
    use qw_crypto::GatewayIdentity;

    fn b64(sig: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig)
    }

    fn signed_entry(id: &GatewayIdentity, writer: &str, seq: u64, prev: &str) -> AuditEntry {
        let event = AuditEvent::SessionClosed {
            total_requests: seq,
            total_tokens: 0,
        };
        let mut e = AuditEntry::new(writer, seq, "sess", event, prev);
        e.content_hash = sha3_256_hex(&e.content_bytes());
        e.signature = b64(&id.sign(e.content_hash.as_bytes()).unwrap());
        e
    }

    fn signed_checkpoint(
        id: &GatewayIdentity,
        seq: u64,
        prev: &str,
        tips: Vec<WriterTip>,
    ) -> AuditCheckpoint {
        let mut cp = AuditCheckpoint::build(seq, prev, tips, chrono::Utc::now());
        cp.signature = b64(&id.sign(cp.content_hash.as_bytes()).unwrap());
        cp
    }

    fn identity() -> GatewayIdentity {
        let dir = tempfile::tempdir().unwrap();
        GatewayIdentity::load_or_generate(dir.path()).unwrap()
    }

    /// Two writer chains + a checkpoint that commits both tips: fully valid.
    #[test]
    fn sharded_valid_across_writers_and_checkpoint() {
        let id = identity();
        let pk = id.public_key_bytes();

        let w1_0 = signed_entry(&id, "w1", 0, "");
        let w1_1 = signed_entry(&id, "w1", 1, &w1_0.content_hash);
        let w2_0 = signed_entry(&id, "w2", 0, "");
        let tips = vec![
            WriterTip {
                writer_id: "w1".into(),
                seq: 1,
                content_hash: w1_1.content_hash.clone(),
            },
            WriterTip {
                writer_id: "w2".into(),
                seq: 0,
                content_hash: w2_0.content_hash.clone(),
            },
        ];
        let cp = signed_checkpoint(&id, 0, "", tips);

        let entries = vec![w1_0, w1_1, w2_0];
        let r = verify_sharded(&entries, &[cp], &pk);
        assert!(r.valid, "expected valid, errors: {:?}", r.errors);
        assert_eq!(r.writers_checked, 2);
        assert_eq!(r.checkpoints_checked, 1);
        assert_eq!(r.entries_checked, 3);
        assert_eq!(r.signatures_valid, 3);
    }

    /// Mutating an entry after signing breaks its content hash.
    #[test]
    fn sharded_detects_tampered_entry() {
        let id = identity();
        let pk = id.public_key_bytes();
        let e0 = signed_entry(&id, "w1", 0, "");
        let mut e1 = signed_entry(&id, "w1", 1, &e0.content_hash);
        e1.session_id = "tampered".into(); // content no longer matches content_hash
        let r = verify_sharded(&[e0, e1], &[], &pk);
        assert!(!r.valid);
        assert!(!r.chain_intact);
    }

    /// A checkpoint committed to a tip that is later dropped is caught even
    /// though the remaining per-writer chain is internally consistent.
    #[test]
    fn sharded_checkpoint_catches_dropped_writer() {
        let id = identity();
        let pk = id.public_key_bytes();
        let w1_0 = signed_entry(&id, "w1", 0, "");
        let w2_0 = signed_entry(&id, "w2", 0, "");
        let tips = vec![
            WriterTip {
                writer_id: "w1".into(),
                seq: 0,
                content_hash: w1_0.content_hash.clone(),
            },
            WriterTip {
                writer_id: "w2".into(),
                seq: 0,
                content_hash: w2_0.content_hash.clone(),
            },
        ];
        let cp = signed_checkpoint(&id, 0, "", tips);

        // w2's entry is dropped from the log, but the checkpoint still commits it.
        let entries = vec![w1_0];
        let r = verify_sharded(&entries, &[cp], &pk);
        assert!(!r.valid);
        assert!(!r.chain_intact);
        assert!(r.errors.iter().any(|e| e.contains("dropped/truncated")));
    }
}

/// Verify an entire audit log file.
pub fn verify_audit_log(
    path: &Path,
    public_key_bytes: &[u8],
) -> Result<VerificationResult, AuditError> {
    let content = std::fs::read_to_string(path)?;
    let mut result = VerificationResult {
        valid: true,
        entries_checked: 0,
        signatures_valid: 0,
        chain_intact: true,
        merkle_roots_valid: 0,
        errors: Vec::new(),
        writers_checked: 0,
        checkpoints_checked: 0,
    };

    let mut prev_hash = String::new();

    for (line_num, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry = serde_json::from_str(line)
            .map_err(|e| AuditError::ChainViolation(format!("line {}: {e}", line_num + 1)))?;

        result.entries_checked += 1;

        // Verify content hash
        let computed_hash = sha3_256_hex(&entry.content_bytes());
        if computed_hash != entry.content_hash {
            result.valid = false;
            result.chain_intact = false;
            result.errors.push(format!(
                "entry {}: content hash mismatch (computed: {}, stored: {})",
                entry.sequence, computed_hash, entry.content_hash
            ));
            continue;
        }

        // Verify chain linkage
        if entry.prev_hash != prev_hash {
            result.valid = false;
            result.chain_intact = false;
            result.errors.push(format!(
                "entry {}: chain broken (expected prev_hash: {}, got: {})",
                entry.sequence, prev_hash, entry.prev_hash
            ));
        }

        // Verify ML-DSA-65 signature
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &entry.signature)
                .map_err(|e| {
                    AuditError::ChainViolation(format!(
                        "entry {}: invalid base64 signature: {e}",
                        entry.sequence
                    ))
                })?;

        match verify_signature(public_key_bytes, entry.content_hash.as_bytes(), &sig_bytes) {
            Ok(true) => {
                result.signatures_valid += 1;
            }
            Ok(false) => {
                result.valid = false;
                result
                    .errors
                    .push(format!("entry {}: signature invalid", entry.sequence));
            }
            Err(e) => {
                result.valid = false;
                result.errors.push(format!(
                    "entry {}: signature verification error: {e}",
                    entry.sequence
                ));
            }
        }

        prev_hash = entry.content_hash.clone();
    }

    Ok(result)
}
