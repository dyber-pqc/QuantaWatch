use chrono::{DateTime, Utc};
use qw_scanner::PqcStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level CBOM document (CycloneDX 1.6 compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoBom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: BomMetadata,
    pub components: Vec<CryptoComponent>,
    pub services: Vec<CryptoService>,
    #[serde(rename = "x-quantawatch-posture")]
    pub posture: PostureSummary,
    #[serde(rename = "x-quantawatch-attestation", skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
}

/// A signed attestation quote over the CBOM, binding the inventory to the
/// gateway's PQC identity plus platform measurements. This is the software
/// stand-in for a hardware QuantaTPM quote (same interface; honestly labelled).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// e.g. "software-ml-dsa-65" (vs. a future "quantatpm-hardware").
    pub attestation_type: String,
    pub algorithm: String,
    pub signer_fingerprint: String,
    /// SHA3-256 of the canonical CBOM payload that was quoted.
    pub bom_digest: String,
    pub nonce: String,
    /// PCR-style platform measurements folded into the quote.
    pub measurements: Vec<Measurement>,
    /// Hex ML-DSA-65 signature over the quote payload.
    pub signature: String,
    /// Hex ML-DSA-65 verifying key, so the quote can be independently checked.
    pub public_key: String,
    pub signed_at: DateTime<Utc>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Measurement {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomMetadata {
    pub timestamp: DateTime<Utc>,
    pub tools: Vec<ToolInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub vendor: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// A CycloneDX component with cryptoProperties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoComponent {
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CryptoProperties>,
    pub evidence: ComponentEvidence,
    #[serde(rename = "x-quantawatch-posture-score")]
    pub posture_score: f64,
    #[serde(rename = "x-quantawatch-pqc-status")]
    pub pqc_status: PqcStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    pub asset_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_properties: Option<CertificateProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_properties: Option<ProtocolProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    pub primitive: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classical_security_level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nist_quantum_security_level: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProperties {
    pub subject_name: String,
    pub issuer_name: String,
    pub not_valid_before: DateTime<Utc>,
    pub not_valid_after: DateTime<Utc>,
    pub signature_algorithm: String,
    pub subject_public_key_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_length: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolProperties {
    pub protocol_type: String,
    pub version: String,
    pub cipher_suites: Vec<CipherSuiteInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherSuiteInfo {
    pub name: String,
    pub pqc_status: PqcStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentEvidence {
    pub scanner_id: String,
    pub scan_timestamp: DateTime<Utc>,
    pub source: String,
    pub confidence: f64,
}

/// Live endpoint service entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoService {
    pub bom_ref: String,
    pub name: String,
    pub endpoints: Vec<String>,
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    pub pqc_status: PqcStatus,
    pub posture_score: f64,
}

/// Posture summary (QuantaWatch extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureSummary {
    pub overall_score: f64,
    pub total_assets: u32,
    pub by_status: HashMap<String, u32>,
    pub by_category: Vec<CategoryScore>,
    pub by_provider: Vec<ProviderScore>,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: String,
    pub score: f64,
    pub asset_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderScore {
    pub provider: String,
    pub score: f64,
    pub tls_version: Option<String>,
    pub pqc_status: PqcStatus,
}

/// Provider crypto info captured from live traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCryptoInfo {
    pub provider_name: String,
    pub endpoint: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub pqc_status: PqcStatus,
    pub last_seen: DateTime<Utc>,
}
