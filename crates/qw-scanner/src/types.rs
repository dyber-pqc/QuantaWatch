use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PqcStatus {
    PqcReady,
    Hybrid,
    ClassicalSecure,
    ClassicalWeak,
    Unknown,
}

impl std::fmt::Display for PqcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PqcReady => write!(f, "pqc_ready"),
            Self::Hybrid => write!(f, "hybrid"),
            Self::ClassicalSecure => write!(f, "classical_secure"),
            Self::ClassicalWeak => write!(f, "classical_weak"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    TlsEndpoint,
    DependencyFile,
    Certificate,
    CodeDirectory,
    CloudKeyStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: String,
    pub target_type: TargetType,
    pub address: String,
    pub metadata: HashMap<String, String>,
}

impl ScanTarget {
    pub fn tls(address: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::TlsEndpoint,
            address: address.to_string(),
            metadata: HashMap::new(),
        }
    }

    pub fn dependency_file(path: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::DependencyFile,
            address: path.to_string(),
            metadata: HashMap::new(),
        }
    }

    pub fn code_directory(path: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::CodeDirectory,
            address: path.to_string(),
            metadata: HashMap::new(),
        }
    }

    pub fn certificate(path: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::Certificate,
            address: path.to_string(),
            metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    WeakAlgorithm,
    ShortKeyLength,
    ExpiredCertificate,
    ExpiringCertificate,
    DeprecatedProtocol,
    HardcodedKey,
    MissingPqc,
    PqcReady,
    VulnerableLibrary,
    ClassicalCrypto,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakAlgorithm => write!(f, "weak_algorithm"),
            Self::ShortKeyLength => write!(f, "short_key_length"),
            Self::ExpiredCertificate => write!(f, "expired_certificate"),
            Self::ExpiringCertificate => write!(f, "expiring_certificate"),
            Self::DeprecatedProtocol => write!(f, "deprecated_protocol"),
            Self::HardcodedKey => write!(f, "hardcoded_key"),
            Self::MissingPqc => write!(f, "missing_pqc"),
            Self::PqcReady => write!(f, "pqc_ready"),
            Self::VulnerableLibrary => write!(f, "vulnerable_library"),
            Self::ClassicalCrypto => write!(f, "classical_crypto"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoAssetType {
    TlsConnection,
    Certificate,
    SigningKey,
    EncryptionKey,
    HashFunction,
    CryptoLibrary,
    ProtocolEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetLocation {
    pub source_type: String,
    pub path: String,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAsset {
    pub id: String,
    pub asset_type: CryptoAssetType,
    pub name: String,
    pub algorithm: Option<String>,
    pub key_length: Option<u32>,
    pub protocol_version: Option<String>,
    pub location: AssetLocation,
    pub discovered_by: String,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: FindingCategory,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub asset: CryptoAsset,
    pub remediation: Option<String>,
    pub pqc_status: PqcStatus,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Completed,
    PartialFailure,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner_id: String,
    pub target_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub findings: Vec<Finding>,
    pub status: ScanStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRecord {
    pub id: String,
    pub scanner_id: String,
    pub target_id: String,
    pub target_address: String,
    pub status: ScanStatus,
    pub finding_count: u32,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingRecord {
    pub id: String,
    pub scan_id: String,
    pub category: FindingCategory,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub asset_type: CryptoAssetType,
    pub algorithm: Option<String>,
    pub pqc_status: PqcStatus,
    pub location: String,
    pub remediation: Option<String>,
    pub created_at: DateTime<Utc>,
}

// Scanner config types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_store_path")]
    pub store_path: String,
    #[serde(default)]
    pub auto_scan_on_start: bool,
    #[serde(default)]
    pub tls: TlsScannerConfig,
    #[serde(default)]
    pub dependencies: DependencyScannerConfig,
    #[serde(default)]
    pub certificates: CertScannerConfig,
    #[serde(default)]
    pub code: CodeScannerConfig,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            store_path: default_store_path(),
            auto_scan_on_start: false,
            tls: TlsScannerConfig::default(),
            dependencies: DependencyScannerConfig::default(),
            certificates: CertScannerConfig::default(),
            code: CodeScannerConfig::default(),
        }
    }
}

fn default_store_path() -> String {
    "./scans".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub targets: Vec<String>,
}

impl Default for TlsScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 10,
            targets: vec![],
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dep_paths")]
    pub paths: Vec<String>,
}

impl Default for DependencyScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: default_dep_paths(),
        }
    }
}

fn default_dep_paths() -> Vec<String> {
    vec![".".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for CertScannerConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeScannerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_status_display() {
        assert_eq!(PqcStatus::PqcReady.to_string(), "pqc_ready");
        assert_eq!(PqcStatus::Hybrid.to_string(), "hybrid");
        assert_eq!(PqcStatus::ClassicalSecure.to_string(), "classical_secure");
        assert_eq!(PqcStatus::ClassicalWeak.to_string(), "classical_weak");
        assert_eq!(PqcStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_finding_category_display() {
        assert_eq!(FindingCategory::WeakAlgorithm.to_string(), "weak_algorithm");
        assert_eq!(FindingCategory::HardcodedKey.to_string(), "hardcoded_key");
        assert_eq!(FindingCategory::MissingPqc.to_string(), "missing_pqc");
        assert_eq!(FindingCategory::PqcReady.to_string(), "pqc_ready");
    }

    #[test]
    fn test_scan_target_tls() {
        let target = ScanTarget::tls("example.com:443");
        assert_eq!(target.address, "example.com:443");
        assert!(matches!(target.target_type, TargetType::TlsEndpoint));
        assert!(!target.id.is_empty());
    }

    #[test]
    fn test_scan_target_dependency_file() {
        let target = ScanTarget::dependency_file("Cargo.toml");
        assert_eq!(target.address, "Cargo.toml");
        assert!(matches!(target.target_type, TargetType::DependencyFile));
    }

    #[test]
    fn test_scan_target_code_directory() {
        let target = ScanTarget::code_directory("/src");
        assert_eq!(target.address, "/src");
        assert!(matches!(target.target_type, TargetType::CodeDirectory));
    }

    #[test]
    fn test_scanner_config_defaults() {
        let config = ScannerConfig::default();
        assert_eq!(config.store_path, "./scans");
        assert!(!config.auto_scan_on_start);
        assert!(config.tls.enabled);
        assert_eq!(config.tls.timeout_secs, 10);
        assert!(config.dependencies.enabled);
        assert!(config.certificates.enabled);
        assert!(!config.code.enabled);
    }

    #[test]
    fn test_finding_severity_ordering() {
        assert!(FindingSeverity::Info < FindingSeverity::Low);
        assert!(FindingSeverity::Low < FindingSeverity::Medium);
        assert!(FindingSeverity::Medium < FindingSeverity::High);
        assert!(FindingSeverity::High < FindingSeverity::Critical);
    }
}
