use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use crate::types::*;
use crate::registry::{Scanner, ScannerError};

pub struct CertificateScanner {
    #[allow(dead_code)]
    config: CertScannerConfig,
}

impl CertificateScanner {
    pub fn new(config: CertScannerConfig) -> Self {
        Self { config }
    }

    /// Classify the PQC status of a certificate's signature algorithm.
    fn classify_signature(sig_alg: &str, rsa_bits: Option<u32>) -> PqcStatus {
        if sig_alg.contains("ml-dsa") || sig_alg.contains("dilithium") {
            PqcStatus::PqcReady
        } else if sig_alg.contains("ecdsa") || sig_alg.contains("1.2.840.10045") {
            PqcStatus::ClassicalSecure
        } else if sig_alg.contains("rsa") || sig_alg.contains("1.2.840.113549") {
            if let Some(bits) = rsa_bits {
                if bits < 2048 {
                    return PqcStatus::ClassicalWeak;
                }
            }
            PqcStatus::ClassicalSecure
        } else {
            PqcStatus::Unknown
        }
    }
}

#[async_trait]
impl Scanner for CertificateScanner {
    fn id(&self) -> &str { "certificate" }
    fn display_name(&self) -> &str { "Certificate Scanner" }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::ExpiredCertificate,
            FindingCategory::ExpiringCertificate,
            FindingCategory::WeakAlgorithm,
            FindingCategory::ShortKeyLength,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::Certificate)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let mut findings = Vec::new();

        let bytes = tokio::fs::read(&target.address)
            .await
            .map_err(ScannerError::IoError)?;

        let der: Vec<u8> = if bytes.starts_with(b"-----BEGIN") {
            let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes)
                .map_err(|e| ScannerError::ParseError(format!("PEM parse failed: {e}")))?;
            pem.contents
        } else {
            bytes.clone()
        };

        let (_, parsed) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| ScannerError::ParseError(format!("X.509 parse failed: {e}")))?;

        let subject = parsed.subject().to_string();
        let issuer = parsed.issuer().to_string();
        let sig_alg = parsed.signature_algorithm.algorithm.to_string();
        let sig_alg_lower = sig_alg.to_lowercase();
        let pubkey_alg = parsed.public_key().algorithm.algorithm.to_string();

        let rsa_bits: Option<u32> = match parsed.public_key().parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => Some(rsa.key_size() as u32),
            _ => None,
        };

        let pqc_status = Self::classify_signature(&sig_alg_lower, rsa_bits);

        let not_before = parsed.validity().not_before.to_datetime();
        let not_after = parsed.validity().not_after.to_datetime();

        let not_after_chrono = chrono::DateTime::<Utc>::from_timestamp(
            not_after.unix_timestamp(),
            not_after.nanosecond(),
        ).unwrap_or_else(Utc::now);
        let now_utc = Utc::now();

        if not_after_chrono < now_utc {
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                category: FindingCategory::ExpiredCertificate,
                severity: FindingSeverity::Critical,
                title: format!("Expired certificate: {subject}"),
                description: format!(
                    "Certificate for {subject} expired at {not_after} (issuer: {issuer})"
                ),
                asset: CryptoAsset {
                    id: uuid::Uuid::new_v4().to_string(),
                    asset_type: CryptoAssetType::Certificate,
                    name: format!("Certificate for {subject}"),
                    algorithm: Some(sig_alg.clone()),
                    key_length: rsa_bits,
                    protocol_version: None,
                    location: AssetLocation {
                        source_type: "file".to_string(),
                        path: target.address.clone(),
                        line: None,
                    },
                    discovered_by: "certificate".to_string(),
                    discovered_at: Utc::now(),
                },
                remediation: Some("Reissue and replace the expired certificate".to_string()),
                pqc_status: pqc_status.clone(),
                metadata: HashMap::new(),
            });
        } else if not_after_chrono < now_utc + chrono::Duration::days(30) {
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                category: FindingCategory::ExpiringCertificate,
                severity: FindingSeverity::High,
                title: format!("Expiring certificate: {subject}"),
                description: format!(
                    "Certificate for {subject} expires at {not_after} (issuer: {issuer})"
                ),
                asset: CryptoAsset {
                    id: uuid::Uuid::new_v4().to_string(),
                    asset_type: CryptoAssetType::Certificate,
                    name: format!("Certificate for {subject}"),
                    algorithm: Some(sig_alg.clone()),
                    key_length: rsa_bits,
                    protocol_version: None,
                    location: AssetLocation {
                        source_type: "file".to_string(),
                        path: target.address.clone(),
                        line: None,
                    },
                    discovered_by: "certificate".to_string(),
                    discovered_at: Utc::now(),
                },
                remediation: Some("Renew the certificate before it expires".to_string()),
                pqc_status: pqc_status.clone(),
                metadata: HashMap::new(),
            });
        }

        if pqc_status == PqcStatus::ClassicalWeak {
            if let Some(bits) = rsa_bits {
                findings.push(Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: FindingCategory::ShortKeyLength,
                    severity: FindingSeverity::High,
                    title: format!("Short RSA key ({bits} bits): {subject}"),
                    description: format!(
                        "Certificate for {subject} uses a {bits}-bit RSA key, which is below the 2048-bit minimum"
                    ),
                    asset: CryptoAsset {
                        id: uuid::Uuid::new_v4().to_string(),
                        asset_type: CryptoAssetType::Certificate,
                        name: format!("Certificate for {subject}"),
                        algorithm: Some(sig_alg.clone()),
                        key_length: Some(bits),
                        protocol_version: None,
                        location: AssetLocation {
                            source_type: "file".to_string(),
                            path: target.address.clone(),
                            line: None,
                        },
                        discovered_by: "certificate".to_string(),
                        discovered_at: Utc::now(),
                    },
                    remediation: Some("Reissue the certificate with at least a 2048-bit RSA key".to_string()),
                    pqc_status: PqcStatus::ClassicalWeak,
                    metadata: HashMap::new(),
                });
            }
        }

        let (algo_severity, algo_category) = if pqc_status == PqcStatus::PqcReady {
            (FindingSeverity::Info, FindingCategory::PqcReady)
        } else {
            (FindingSeverity::Medium, FindingCategory::MissingPqc)
        };

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            category: algo_category,
            severity: algo_severity,
            title: format!("Certificate signature algorithm: {sig_alg}"),
            description: format!(
                "Certificate for {subject} (issuer: {issuer}) signed with {sig_alg}, public key algorithm {pubkey_alg}, valid {not_before} to {not_after}"
            ),
            asset: CryptoAsset {
                id: uuid::Uuid::new_v4().to_string(),
                asset_type: CryptoAssetType::Certificate,
                name: format!("Certificate for {subject}"),
                algorithm: Some(sig_alg.clone()),
                key_length: rsa_bits,
                protocol_version: None,
                location: AssetLocation {
                    source_type: "file".to_string(),
                    path: target.address.clone(),
                    line: None,
                },
                discovered_by: "certificate".to_string(),
                discovered_at: Utc::now(),
            },
            remediation: if pqc_status != PqcStatus::PqcReady {
                Some("Reissue certificate with a PQC signature algorithm (e.g., ML-DSA-65)".to_string())
            } else {
                None
            },
            pqc_status: pqc_status.clone(),
            metadata: HashMap::from([
                ("public_key_algorithm".to_string(), pubkey_alg),
            ]),
        });

        Ok(ScanResult {
            scanner_id: "certificate".to_string(),
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

    #[test]
    fn test_classify_signature_pqc_ready() {
        assert_eq!(CertificateScanner::classify_signature("ml-dsa-65", None), PqcStatus::PqcReady);
        assert_eq!(CertificateScanner::classify_signature("dilithium3", None), PqcStatus::PqcReady);
    }

    #[test]
    fn test_classify_signature_ecdsa_classical_secure() {
        assert_eq!(CertificateScanner::classify_signature("ecdsa-with-sha256", None), PqcStatus::ClassicalSecure);
        assert_eq!(CertificateScanner::classify_signature("1.2.840.10045.4.3.2", None), PqcStatus::ClassicalSecure);
    }

    #[test]
    fn test_classify_signature_rsa() {
        assert_eq!(CertificateScanner::classify_signature("sha256withrsaencryption", Some(2048)), PqcStatus::ClassicalSecure);
        assert_eq!(CertificateScanner::classify_signature("1.2.840.113549.1.1.11", Some(4096)), PqcStatus::ClassicalSecure);
        assert_eq!(CertificateScanner::classify_signature("sha256withrsaencryption", None), PqcStatus::ClassicalSecure);
        assert_eq!(CertificateScanner::classify_signature("sha1withrsaencryption", Some(1024)), PqcStatus::ClassicalWeak);
    }

    #[test]
    fn test_classify_signature_unknown() {
        assert_eq!(CertificateScanner::classify_signature("some-unknown-alg", None), PqcStatus::Unknown);
    }
}
