use serde::{Deserialize, Serialize};
use std::path::Path;

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
