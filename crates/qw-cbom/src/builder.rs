use chrono::Utc;
use qw_scanner::{CryptoAssetType, Finding, PqcStatus, ScanResult};

use crate::model::*;
use crate::posture::PostureEngine;

pub struct CbomBuilder {
    components: Vec<CryptoComponent>,
    services: Vec<CryptoService>,
}

impl CbomBuilder {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            services: Vec::new(),
        }
    }

    /// Ingest scan results and convert findings to CBOM components.
    ///
    /// Deduplicated via [`crate::dedupe_scan_results`], so a dependency used in
    /// many manifests appears once rather than once per manifest.
    pub fn ingest_scan_results(&mut self, results: &[ScanResult]) {
        for result in crate::dedupe_scan_results(results) {
            for finding in &result.findings {
                let component = self.finding_to_component(finding, &result.scanner_id);
                self.components.push(component);
            }
        }
    }

    /// Ingest live provider crypto info as services
    pub fn ingest_provider_info(&mut self, providers: &[ProviderCryptoInfo]) {
        for provider in providers {
            let score = PostureEngine::score_service(provider);
            self.services.push(CryptoService {
                bom_ref: format!("service-{}", provider.provider_name),
                name: format!("{} API", capitalize(&provider.provider_name)),
                endpoints: vec![provider.endpoint.clone()],
                authenticated: true,
                tls_version: Some(provider.tls_version.clone()),
                cipher_suite: Some(provider.cipher_suite.clone()),
                pqc_status: provider.pqc_status.clone(),
                posture_score: score,
            });
        }
    }

    fn finding_to_component(&self, finding: &Finding, scanner_id: &str) -> CryptoComponent {
        let score = PostureEngine::score_finding(finding);

        let crypto_properties = match finding.asset.asset_type {
            CryptoAssetType::TlsConnection | CryptoAssetType::ProtocolEndpoint => {
                let tls_version = finding
                    .metadata
                    .get("tls_version")
                    .cloned()
                    .unwrap_or_default();
                let cipher = finding
                    .metadata
                    .get("cipher_suite")
                    .cloned()
                    .unwrap_or_default();
                Some(CryptoProperties {
                    asset_type: "protocol".to_string(),
                    algorithm_properties: None,
                    certificate_properties: None,
                    protocol_properties: Some(ProtocolProperties {
                        protocol_type: "tls".to_string(),
                        version: tls_version,
                        cipher_suites: vec![CipherSuiteInfo {
                            name: cipher,
                            pqc_status: finding.pqc_status.clone(),
                        }],
                    }),
                    oid: None,
                })
            }
            CryptoAssetType::Certificate => Some(CryptoProperties {
                asset_type: "certificate".to_string(),
                algorithm_properties: None,
                certificate_properties: None,
                protocol_properties: None,
                oid: None,
            }),
            CryptoAssetType::CryptoLibrary => {
                let alg = finding.asset.algorithm.clone().unwrap_or_default();
                Some(CryptoProperties {
                    asset_type: "related-crypto-material".to_string(),
                    algorithm_properties: Some(AlgorithmProperties {
                        primitive: classify_primitive(&alg),
                        parameter_set_identifier: Some(alg),
                        classical_security_level: None,
                        nist_quantum_security_level: match finding.pqc_status {
                            PqcStatus::PqcReady => Some(3),
                            PqcStatus::Hybrid => Some(3),
                            _ => None,
                        },
                    }),
                    certificate_properties: None,
                    protocol_properties: None,
                    oid: None,
                })
            }
            _ => None,
        };

        let component_type = match finding.asset.asset_type {
            CryptoAssetType::CryptoLibrary => "library",
            _ => "crypto-asset",
        };

        CryptoComponent {
            bom_ref: format!("comp-{}", finding.id),
            component_type: component_type.to_string(),
            name: finding.asset.name.clone(),
            version: finding.asset.protocol_version.clone(),
            crypto_properties,
            evidence: ComponentEvidence {
                scanner_id: scanner_id.to_string(),
                scan_timestamp: finding.asset.discovered_at,
                source: finding.asset.location.path.clone(),
                confidence: 0.9,
            },
            posture_score: score,
            pqc_status: finding.pqc_status.clone(),
        }
    }

    /// Build the final CBOM document
    pub fn build(self, gateway_fingerprint: &str) -> CryptoBom {
        let posture = PostureEngine::summarize(&[], &[]);

        CryptoBom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            version: 1,
            metadata: BomMetadata {
                timestamp: Utc::now(),
                tools: vec![ToolInfo {
                    vendor: "Dyber, Inc.".to_string(),
                    name: "QuantaWatch".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    fingerprint: Some(gateway_fingerprint.to_string()),
                }],
            },
            components: self.components,
            services: self.services,
            posture,
            attestation: None,
        }
    }

    /// Build with a pre-computed posture summary
    pub fn build_with_posture(
        self,
        gateway_fingerprint: &str,
        posture: PostureSummary,
    ) -> CryptoBom {
        CryptoBom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            version: 1,
            metadata: BomMetadata {
                timestamp: Utc::now(),
                tools: vec![ToolInfo {
                    vendor: "Dyber, Inc.".to_string(),
                    name: "QuantaWatch".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    fingerprint: Some(gateway_fingerprint.to_string()),
                }],
            },
            components: self.components,
            services: self.services,
            posture,
            attestation: None,
        }
    }

    /// Export CBOM as JSON string
    pub fn export_json(bom: &CryptoBom) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(bom)
    }
}

impl Default for CbomBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn classify_primitive(alg: &str) -> String {
    let lower = alg.to_lowercase();
    if lower.contains("dsa")
        || lower.contains("ecdsa")
        || lower.contains("ed25519")
        || lower.contains("rsa")
    {
        "signature".to_string()
    } else if lower.contains("kem")
        || lower.contains("kyber")
        || lower.contains("dh")
        || lower.contains("x25519")
    {
        "kem".to_string()
    } else if lower.contains("aes") || lower.contains("chacha") || lower.contains("3des") {
        "ae".to_string()
    } else if lower.contains("sha") || lower.contains("blake") || lower.contains("md5") {
        "hash".to_string()
    } else if lower.contains("hmac") || lower.contains("poly1305") {
        "mac".to_string()
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_produces_valid_cyclonedx_json() {
        let builder = CbomBuilder::new();
        let bom = builder.build("test-fingerprint-abc123");

        let json = CbomBuilder::export_json(&bom).expect("JSON serialization failed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON parsing failed");

        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.6");
        assert_eq!(parsed["version"], 1);
        assert!(parsed["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("urn:uuid:"));
        assert_eq!(parsed["metadata"]["tools"][0]["vendor"], "Dyber, Inc.");
        assert_eq!(parsed["metadata"]["tools"][0]["name"], "QuantaWatch");
        assert_eq!(
            parsed["metadata"]["tools"][0]["fingerprint"],
            "test-fingerprint-abc123"
        );
        assert!(parsed["components"].as_array().unwrap().is_empty());
        assert!(parsed["services"].as_array().unwrap().is_empty());
        assert!(parsed["x-quantawatch-posture"]["overallScore"]
            .as_f64()
            .is_some());
    }
}
