use crate::registry::{Scanner, ScannerError};
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Install the ring CryptoProvider as the process default exactly once.
fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub struct TlsScanner {
    config: TlsScannerConfig,
}

impl TlsScanner {
    pub fn new(config: TlsScannerConfig) -> Self {
        Self { config }
    }

    fn classify_cipher_suite(name: &str) -> PqcStatus {
        let name_upper = name.to_uppercase();
        // Check hybrid first: hybrid names contain PQC algorithm names (e.g. X25519_KYBER contains KYBER)
        if name_upper.contains("X25519_KYBER")
            || name_upper.contains("X25519MLKEM")
            || name_upper.contains("X25519_ML_KEM")
        {
            PqcStatus::Hybrid
        } else if name_upper.contains("KYBER")
            || name_upper.contains("ML_KEM")
            || name_upper.contains("MLKEM")
        {
            PqcStatus::PqcReady
        } else if name_upper.contains("AES_256")
            || name_upper.contains("CHACHA20")
            || name_upper.contains("AES_128")
        {
            PqcStatus::ClassicalSecure
        } else if name_upper.contains("3DES")
            || name_upper.contains("RC4")
            || name_upper.contains("NULL")
        {
            PqcStatus::ClassicalWeak
        } else {
            PqcStatus::Unknown
        }
    }

    fn classify_tls_version(version: &str) -> PqcStatus {
        match version {
            "TLS 1.3" => PqcStatus::ClassicalSecure,
            "TLS 1.2" => PqcStatus::ClassicalSecure,
            "TLS 1.1" | "TLS 1.0" => PqcStatus::ClassicalWeak,
            _ => PqcStatus::Unknown,
        }
    }
}

#[async_trait]
impl Scanner for TlsScanner {
    fn id(&self) -> &str {
        "tls"
    }
    fn display_name(&self) -> &str {
        "TLS Endpoint Scanner"
    }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::DeprecatedProtocol,
            FindingCategory::MissingPqc,
            FindingCategory::PqcReady,
            FindingCategory::ClassicalCrypto,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::TlsEndpoint)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let mut findings = Vec::new();

        let address = if target.address.contains(':') {
            target.address.clone()
        } else {
            format!("{}:443", target.address)
        };

        let host = address.split(':').next().unwrap_or(&target.address);
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| ScannerError::ConnectionFailed(format!("Invalid hostname: {e}")))?;

        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // rustls 0.23 requires a process CryptoProvider. Install the ring provider
        // once; ignore the error if another part of the process already installed one.
        ensure_crypto_provider();

        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));

        let timeout = std::time::Duration::from_secs(self.config.timeout_secs);
        let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(&address))
            .await
            .map_err(|_| ScannerError::Timeout)?
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| ScannerError::Timeout)?
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        let (_, conn) = tls_stream.get_ref();

        let protocol_version = conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "unknown".to_string());

        let tls_version_display = match protocol_version.as_str() {
            "TLSv1_3" => "TLS 1.3",
            "TLSv1_2" => "TLS 1.2",
            "TLSv1_1" => "TLS 1.1",
            "TLSv1_0" => "TLS 1.0",
            other => other,
        };

        let cipher_suite = conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{cs:?}"))
            .unwrap_or_else(|| "unknown".to_string());

        let tls_pqc = Self::classify_tls_version(tls_version_display);
        let cipher_pqc = Self::classify_cipher_suite(&cipher_suite);

        // Determine overall PQC status (worst of TLS version and cipher)
        let overall_pqc = match (&tls_pqc, &cipher_pqc) {
            (PqcStatus::ClassicalWeak, _) | (_, PqcStatus::ClassicalWeak) => {
                PqcStatus::ClassicalWeak
            }
            (PqcStatus::PqcReady, PqcStatus::PqcReady) => PqcStatus::PqcReady,
            (PqcStatus::Hybrid, _) | (_, PqcStatus::Hybrid) => PqcStatus::Hybrid,
            (PqcStatus::PqcReady, _) | (_, PqcStatus::PqcReady) => PqcStatus::Hybrid,
            _ => PqcStatus::ClassicalSecure,
        };

        // TLS protocol finding
        let (tls_severity, tls_category) =
            if tls_version_display.contains("1.0") || tls_version_display.contains("1.1") {
                (FindingSeverity::High, FindingCategory::DeprecatedProtocol)
            } else if tls_version_display.contains("1.2") {
                (FindingSeverity::Medium, FindingCategory::ClassicalCrypto)
            } else {
                (FindingSeverity::Info, FindingCategory::ClassicalCrypto)
            };

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            category: tls_category,
            severity: tls_severity,
            title: format!("TLS {tls_version_display} on {host}"),
            description: format!(
                "Endpoint {address} negotiated {tls_version_display} with cipher suite {cipher_suite}"
            ),
            asset: CryptoAsset {
                id: uuid::Uuid::new_v4().to_string(),
                asset_type: CryptoAssetType::TlsConnection,
                name: format!("TLS connection to {host}"),
                algorithm: Some(cipher_suite.clone()),
                key_length: None,
                protocol_version: Some(tls_version_display.to_string()),
                location: AssetLocation {
                    source_type: "endpoint".to_string(),
                    path: address.clone(),
                    line: None,
                },
                discovered_by: "tls".to_string(),
                discovered_at: Utc::now(),
            },
            remediation: if overall_pqc != PqcStatus::PqcReady {
                Some("Enable PQC key exchange (e.g., X25519Kyber768) on this endpoint".to_string())
            } else {
                None
            },
            pqc_status: overall_pqc.clone(),
            metadata: std::collections::HashMap::from([
                ("tls_version".to_string(), tls_version_display.to_string()),
                ("cipher_suite".to_string(), cipher_suite),
            ]),
        });

        // Check peer certificates
        if let Some(certs) = conn.peer_certificates() {
            for (i, cert) in certs.iter().enumerate() {
                if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
                    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
                    let issuer = parsed.issuer().to_string();
                    let subject = parsed.subject().to_string();
                    let not_after = parsed.validity().not_after.to_datetime();

                    let cert_pqc = if sig_alg.contains("ml-dsa") || sig_alg.contains("dilithium") {
                        PqcStatus::PqcReady
                    } else if sig_alg.contains("ecdsa")
                        || sig_alg.contains("1.2.840.10045")
                        || sig_alg.contains("rsa")
                        || sig_alg.contains("1.2.840.113549")
                    {
                        PqcStatus::ClassicalSecure
                    } else {
                        PqcStatus::Unknown
                    };

                    // Convert time::OffsetDateTime to chrono::DateTime<Utc>
                    let not_after_chrono = chrono::DateTime::<Utc>::from_timestamp(
                        not_after.unix_timestamp(),
                        not_after.nanosecond(),
                    )
                    .unwrap_or_else(Utc::now);
                    let now_utc = Utc::now();
                    let cert_severity = if not_after_chrono < now_utc {
                        FindingSeverity::Critical
                    } else if not_after_chrono < now_utc + chrono::Duration::days(30) {
                        FindingSeverity::High
                    } else {
                        FindingSeverity::Info
                    };

                    let cert_category = if not_after_chrono < now_utc {
                        FindingCategory::ExpiredCertificate
                    } else if not_after_chrono < now_utc + chrono::Duration::days(30) {
                        FindingCategory::ExpiringCertificate
                    } else {
                        FindingCategory::ClassicalCrypto
                    };

                    findings.push(Finding {
                        id: uuid::Uuid::new_v4().to_string(),
                        category: cert_category,
                        severity: cert_severity,
                        title: format!("Certificate #{} for {host}", i + 1),
                        description: format!(
                            "Subject: {subject}, Issuer: {issuer}, Signature: {sig_alg}"
                        ),
                        asset: CryptoAsset {
                            id: uuid::Uuid::new_v4().to_string(),
                            asset_type: CryptoAssetType::Certificate,
                            name: format!("Certificate for {subject}"),
                            algorithm: Some(sig_alg),
                            key_length: None,
                            protocol_version: None,
                            location: AssetLocation {
                                source_type: "endpoint".to_string(),
                                path: address.clone(),
                                line: None,
                            },
                            discovered_by: "tls".to_string(),
                            discovered_at: Utc::now(),
                        },
                        remediation: if cert_pqc != PqcStatus::PqcReady {
                            Some("Reissue certificate with PQC signature algorithm (e.g., ML-DSA-65)".to_string())
                        } else {
                            None
                        },
                        pqc_status: cert_pqc,
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }

        Ok(ScanResult {
            scanner_id: "tls".to_string(),
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
    fn test_classify_cipher_suite_pqc_ready() {
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_AES_256_GCM_SHA384_MLKEM768"),
            PqcStatus::PqcReady
        );
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_KYBER768"),
            PqcStatus::PqcReady
        );
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_ML_KEM_768"),
            PqcStatus::PqcReady
        );
    }

    #[test]
    fn test_classify_cipher_suite_hybrid() {
        assert_eq!(
            TlsScanner::classify_cipher_suite("X25519_KYBER768"),
            PqcStatus::Hybrid
        );
        assert_eq!(
            TlsScanner::classify_cipher_suite("X25519MLKEM768"),
            PqcStatus::Hybrid
        );
    }

    #[test]
    fn test_classify_cipher_suite_classical_secure() {
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_AES_256_GCM_SHA384"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_CHACHA20_POLY1305_SHA256"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_AES_128_GCM_SHA256"),
            PqcStatus::ClassicalSecure
        );
    }

    #[test]
    fn test_classify_cipher_suite_classical_weak() {
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_RSA_WITH_RC4_128_SHA"),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            TlsScanner::classify_cipher_suite("TLS_NULL_WITH_NULL_NULL"),
            PqcStatus::ClassicalWeak
        );
    }

    #[test]
    fn test_classify_tls_version() {
        assert_eq!(
            TlsScanner::classify_tls_version("TLS 1.3"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            TlsScanner::classify_tls_version("TLS 1.2"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            TlsScanner::classify_tls_version("TLS 1.1"),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            TlsScanner::classify_tls_version("TLS 1.0"),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            TlsScanner::classify_tls_version("SSL 3.0"),
            PqcStatus::Unknown
        );
    }
}
