//! Data-at-rest crypto posture scanner.
//!
//! Evaluates declared data stores (databases, object stores, volumes, KMS-wrapped
//! datasets) for at-rest encryption posture — WITHOUT touching the data. It reads
//! store metadata (cipher, key-wrap/KEK, key age, in-transit TLS) and classifies.
//!
//! The differentiated insight vs. a plain "is it encrypted?" check: a store can
//! use AES-256 at rest and still be **harvest-now-decrypt-later exposed** if the
//! data-encryption key is wrapped by a quantum-vulnerable KEK (RSA/ECDH). An
//! attacker who copies the ciphertext blob + the wrapped key today recovers the
//! key once a CRQC exists. We surface that as a first-class finding.

use crate::registry::{Scanner, ScannerError};
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;

pub struct DataAtRestScanner {
    max_key_age_days: u32,
}

impl DataAtRestScanner {
    pub fn new(config: &DataAtRestScannerConfig) -> Self {
        Self {
            max_key_age_days: config.max_key_age_days,
        }
    }

    fn asset(target: &ScanTarget, cipher: &str) -> CryptoAsset {
        CryptoAsset {
            id: uuid::Uuid::new_v4().to_string(),
            asset_type: CryptoAssetType::DataStore,
            name: target.address.clone(),
            algorithm: (!cipher.is_empty()).then(|| cipher.to_string()),
            key_length: None,
            protocol_version: None,
            location: AssetLocation {
                source_type: "data_store".to_string(),
                path: target.address.clone(),
                line: None,
            },
            discovered_by: "data_at_rest".to_string(),
            discovered_at: Utc::now(),
        }
    }
}

fn meta<'a>(t: &'a ScanTarget, k: &str) -> &'a str {
    t.metadata.get(k).map(String::as_str).unwrap_or("")
}

/// A quantum-vulnerable asymmetric key-wrap (KEK) — the HNDL-critical case.
fn wrap_is_quantum_vulnerable(wrap: &str) -> bool {
    ["rsa", "ecdh", "ecdsa", "ecc", "-dh", "diffie"]
        .iter()
        .any(|p| wrap.contains(p))
}
fn wrap_is_pqc(wrap: &str) -> bool {
    ["ml-kem", "mlkem", "kyber", "hybrid", "ml-dsa"]
        .iter()
        .any(|p| wrap.contains(p))
}

impl DataAtRestScanner {
    fn classify(&self, target: &ScanTarget) -> Vec<Finding> {
        let kind = meta(target, "kind");
        let enc = meta(target, "encryption").to_lowercase();
        let wrap = meta(target, "key_wrap").to_lowercase();
        let env = meta(target, "environment");
        let key_age: u32 = meta(target, "key_age_days").parse().unwrap_or(0);
        let in_transit_tls = meta(target, "in_transit_tls") == "true";

        let mut findings = Vec::new();
        let mk = |cat: FindingCategory,
                  sev: FindingSeverity,
                  pqc: PqcStatus,
                  title: String,
                  desc: String,
                  rem: &str,
                  cipher: &str|
         -> Finding {
            Finding {
                id: uuid::Uuid::new_v4().to_string(),
                category: cat,
                severity: sev,
                title,
                description: desc,
                asset: Self::asset(target, cipher),
                remediation: (!rem.is_empty()).then(|| rem.to_string()),
                pqc_status: pqc,
                metadata: HashMap::from([
                    ("kind".to_string(), kind.to_string()),
                    ("environment".to_string(), env.to_string()),
                    ("keyWrap".to_string(), wrap.clone()),
                ]),
            }
        };

        // 1. No encryption at all — the worst case.
        let unencrypted = enc.is_empty()
            || ["none", "off", "disabled", "plaintext", "false"].contains(&enc.as_str());
        if unencrypted {
            findings.push(mk(
                FindingCategory::UnencryptedAtRest,
                FindingSeverity::Critical,
                PqcStatus::ClassicalWeak,
                format!("Data at rest is not encrypted: {}", target.address),
                format!(
                    "{kind} '{}' stores data at rest with no encryption. Anyone with disk/backup/snapshot access reads it directly.",
                    target.address
                ),
                "Enable at-rest encryption (AES-256-GCM minimum) with a KMS-managed key.",
                &enc,
            ));
            return findings; // nothing else matters until it's encrypted
        }

        // 2. Weak / legacy at-rest cipher.
        let weak_cipher = [
            "aes-128", "aes128", "3des", "des", "rc4", "blowfish", "aes-ecb",
        ]
        .iter()
        .any(|p| enc.contains(p));
        if weak_cipher {
            findings.push(mk(
                FindingCategory::WeakAlgorithm,
                FindingSeverity::High,
                PqcStatus::ClassicalWeak,
                format!("Weak at-rest cipher ({enc})"),
                format!(
                    "{kind} '{}' encrypts at rest with {enc}. Grover's algorithm halves symmetric strength, so 128-bit (or legacy) ciphers fall below the CNSA 2.0 bar.",
                    target.address
                ),
                "Re-encrypt at rest with AES-256-GCM (or ChaCha20-Poly1305).",
                &enc,
            ));
        }

        // 3. THE HNDL insight — strong data cipher, quantum-vulnerable KEK.
        if !wrap.is_empty() && wrap_is_quantum_vulnerable(&wrap) {
            findings.push(mk(
                FindingCategory::MissingPqc,
                FindingSeverity::High,
                PqcStatus::ClassicalWeak,
                "At-rest key wrapped by a quantum-vulnerable KEK".to_string(),
                format!(
                    "{kind} '{}' encrypts data with {} but wraps the data key using {wrap}. An adversary who harvests the ciphertext plus the wrapped key today recovers the key once a CRQC exists — the data is HNDL-exposed even though the bulk cipher is strong.",
                    target.address,
                    if enc.is_empty() { "a symmetric cipher" } else { &enc }
                ),
                "Migrate the key-encryption key (KEK) to ML-KEM-768 or a hybrid (X25519+ML-KEM) envelope.",
                &enc,
            ));
        }

        // 4. Stale key rotation.
        if key_age > 0 && key_age > self.max_key_age_days {
            let sev = if key_age > self.max_key_age_days * 2 {
                FindingSeverity::Medium
            } else {
                FindingSeverity::Low
            };
            findings.push(mk(
                FindingCategory::StaleKeyRotation,
                sev,
                PqcStatus::ClassicalSecure,
                format!("At-rest key not rotated in {key_age} days"),
                format!(
                    "The data-encryption key for '{}' is {key_age} days old (policy: {} days). Long-lived keys widen the blast radius of a compromise.",
                    target.address, self.max_key_age_days
                ),
                "Rotate the data-encryption key and schedule automatic rotation.",
                &enc,
            ));
        }

        // 5. Not encrypted in transit to the store.
        if !in_transit_tls {
            findings.push(mk(
                FindingCategory::DeprecatedProtocol,
                FindingSeverity::Medium,
                PqcStatus::ClassicalWeak,
                "Store connections are not TLS-protected".to_string(),
                format!(
                    "Connections to {kind} '{}' are not encrypted in transit; credentials and data cross the network in the clear.",
                    target.address
                ),
                "Require TLS 1.3 for all client connections to this store.",
                &enc,
            ));
        }

        // 6. Everything strong → record a clean, PQC-aware baseline.
        if findings.is_empty() {
            let (pqc, title) = if wrap_is_pqc(&wrap) {
                (
                    PqcStatus::PqcReady,
                    "At-rest encryption is PQC-ready".to_string(),
                )
            } else {
                (
                    PqcStatus::ClassicalSecure,
                    "At-rest encryption is strong (classical)".to_string(),
                )
            };
            findings.push(mk(
                FindingCategory::PqcReady,
                FindingSeverity::Info,
                pqc,
                title,
                format!(
                    "{kind} '{}' encrypts at rest with {enc}{}.",
                    target.address,
                    if wrap.is_empty() {
                        String::new()
                    } else {
                        format!(", key-wrapped with {wrap}")
                    }
                ),
                "",
                &enc,
            ));
        }

        findings
    }
}

#[async_trait]
impl Scanner for DataAtRestScanner {
    fn id(&self) -> &str {
        "data_at_rest"
    }
    fn display_name(&self) -> &str {
        "Data-at-Rest Scanner"
    }
    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::UnencryptedAtRest,
            FindingCategory::WeakAlgorithm,
            FindingCategory::MissingPqc,
            FindingCategory::StaleKeyRotation,
            FindingCategory::DeprecatedProtocol,
            FindingCategory::PqcReady,
        ]
    }
    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::DataStore)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let findings = self.classify(target);
        Ok(ScanResult {
            scanner_id: "data_at_rest".to_string(),
            target_id: target.id.clone(),
            started_at,
            completed_at: Utc::now(),
            findings,
            status: ScanStatus::Completed,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(meta: &[(&str, &str)]) -> ScanTarget {
        let m: HashMap<String, String> = meta
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        ScanTarget::data_store("db.internal:5432", m)
    }

    #[tokio::test]
    async fn unencrypted_is_critical() {
        let s = DataAtRestScanner::new(&DataAtRestScannerConfig::default());
        let r = s
            .scan(&store(&[("kind", "database"), ("encryption", "none")]))
            .await
            .unwrap();
        assert_eq!(r.findings.len(), 1);
        assert!(matches!(
            r.findings[0].category,
            FindingCategory::UnencryptedAtRest
        ));
        assert_eq!(r.findings[0].severity, FindingSeverity::Critical);
    }

    #[tokio::test]
    async fn strong_cipher_but_rsa_kek_is_hndl() {
        let s = DataAtRestScanner::new(&DataAtRestScannerConfig::default());
        let r = s
            .scan(&store(&[
                ("kind", "object_store"),
                ("encryption", "aes-256-gcm"),
                ("key_wrap", "rsa-2048"),
                ("in_transit_tls", "true"),
            ]))
            .await
            .unwrap();
        assert!(
            r.findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::MissingPqc)),
            "AES-256 wrapped by RSA KEK must flag an HNDL/MissingPqc finding"
        );
    }

    #[tokio::test]
    async fn strong_cipher_pqc_wrap_is_clean() {
        let s = DataAtRestScanner::new(&DataAtRestScannerConfig::default());
        let r = s
            .scan(&store(&[
                ("kind", "database"),
                ("encryption", "aes-256-gcm"),
                ("key_wrap", "ml-kem-768"),
                ("in_transit_tls", "true"),
            ]))
            .await
            .unwrap();
        assert_eq!(r.findings.len(), 1);
        assert!(matches!(r.findings[0].pqc_status, PqcStatus::PqcReady));
    }

    #[tokio::test]
    async fn weak_cipher_and_stale_key() {
        let cfg = DataAtRestScannerConfig {
            max_key_age_days: 90,
            ..Default::default()
        };
        let s = DataAtRestScanner::new(&cfg);
        let r = s
            .scan(&store(&[
                ("kind", "volume"),
                ("encryption", "aes-128"),
                ("key_age_days", "400"),
                ("in_transit_tls", "true"),
            ]))
            .await
            .unwrap();
        assert!(r
            .findings
            .iter()
            .any(|f| matches!(f.category, FindingCategory::WeakAlgorithm)));
        assert!(r
            .findings
            .iter()
            .any(|f| matches!(f.category, FindingCategory::StaleKeyRotation)));
    }
}
