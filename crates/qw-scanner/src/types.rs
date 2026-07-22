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
    /// A data store evaluated for at-rest encryption posture (DB, object store,
    /// volume, KMS-wrapped dataset).
    DataStore,
    /// An SSH server whose negotiated key-exchange, host-key, cipher and MAC
    /// algorithms are fingerprinted for post-quantum readiness.
    SshEndpoint,
    /// A host to sweep for open, crypto-relevant TCP ports (network discovery).
    NetworkHost,
    /// An endpoint that upgrades to TLS mid-session via STARTTLS (PostgreSQL
    /// SSLRequest, SMTP STARTTLS). `metadata.protocol` selects the dialect.
    StartTlsEndpoint,
    /// A Remote Desktop (RDP, 3389) endpoint: negotiate the security layer
    /// (Standard RDP Security vs TLS vs CredSSP/NLA), then fingerprint the TLS.
    RdpEndpoint,
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

    pub fn data_store(address: &str, metadata: HashMap<String, String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::DataStore,
            address: address.to_string(),
            metadata,
        }
    }

    pub fn ssh(address: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::SshEndpoint,
            address: address.to_string(),
            metadata: HashMap::new(),
        }
    }

    pub fn network_host(address: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::NetworkHost,
            address: address.to_string(),
            metadata: HashMap::new(),
        }
    }

    pub fn rdp(address: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::RdpEndpoint,
            address: address.to_string(),
            metadata: HashMap::new(),
        }
    }

    /// A STARTTLS target. `protocol` is "postgres" | "smtp" | "" (empty infers
    /// from the port).
    pub fn starttls(address: &str, protocol: &str) -> Self {
        let mut metadata = HashMap::new();
        if !protocol.is_empty() {
            metadata.insert("protocol".to_string(), protocol.to_string());
        }
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::StartTlsEndpoint,
            address: address.to_string(),
            metadata,
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
    /// Data at rest with no encryption at all.
    UnencryptedAtRest,
    /// At-rest data encryption keys not rotated within policy.
    StaleKeyRotation,
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
            Self::UnencryptedAtRest => write!(f, "unencrypted_at_rest"),
            Self::StaleKeyRotation => write!(f, "stale_key_rotation"),
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
    /// A data store (database, object store, volume) evaluated at rest.
    DataStore,
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

/// How much we trust a finding. High = directly measured (a handshake
/// completed, a cert parsed); Medium = a static/heuristic match (a dependency
/// or code pattern); Low = a port answered but the crypto wasn't characterized.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}
impl Default for Confidence {
    fn default() -> Self {
        Confidence::Medium
    }
}

/// Triage state. Suppressed drops out of the work list (false positive /
/// won't-fix) but is retained for the audit trail.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Suppressed,
}
impl Default for FindingStatus {
    fn default() -> Self {
        FindingStatus::Open
    }
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
    // Confidence + evidence + triage. `#[serde(default)]` keeps older stored
    // findings (written before these existed) deserializable.
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub status: FindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Derive a confidence level from what the probe actually observed.
pub fn confidence_of(f: &Finding) -> Confidence {
    // A port that answered but whose crypto we couldn't read is a "characterize",
    // not a confirmed weakness — low confidence regardless of who found it.
    if matches!(f.pqc_status, PqcStatus::Unknown) {
        return Confidence::Low;
    }
    match f.asset.asset_type {
        // Live measurements: a handshake completed, a certificate parsed, an
        // at-rest cipher read from the store's config.
        CryptoAssetType::TlsConnection
        | CryptoAssetType::Certificate
        | CryptoAssetType::ProtocolEndpoint
        | CryptoAssetType::DataStore => Confidence::High,
        // Static / heuristic matches (dependency manifests, code patterns): real,
        // but likelier to false-positive than a live measurement.
        CryptoAssetType::CryptoLibrary => Confidence::Medium,
        _ => Confidence::Medium,
    }
}

/// Build a human-readable evidence trail: what was observed, by which probe.
pub fn evidence_of(f: &Finding, scanner_id: &str) -> Vec<String> {
    let mut ev = Vec::new();
    ev.push(format!(
        "Probe: {} scanner",
        if scanner_id.is_empty() { &f.asset.discovered_by } else { scanner_id }
    ));
    ev.push(format!("Observed: {}", f.asset.discovered_at.to_rfc3339()));
    ev.push(format!("Location: {}", f.asset.location.path));
    if let Some(a) = &f.asset.algorithm {
        ev.push(format!("Algorithm: {a}"));
    }
    if let Some(p) = &f.asset.protocol_version {
        ev.push(format!("Protocol: {p}"));
    }
    if let Some(k) = f.asset.key_length {
        ev.push(format!("Key length: {k} bits"));
    }
    ev.push(format!("Classified: {}", f.pqc_status));
    // Surface a couple of scanner-specific facts (RDP security mode, exposure…).
    for key in ["security_mode", "exposed", "source", "tls_version"] {
        if let Some(v) = f.metadata.get(key) {
            ev.push(format!("{key}: {v}"));
        }
    }
    ev
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
    #[serde(default)]
    pub data_at_rest: DataAtRestScannerConfig,
    #[serde(default)]
    pub ssh: SshScannerConfig,
    #[serde(default)]
    pub network: NetworkScannerConfig,
    #[serde(default)]
    pub starttls: StartTlsScannerConfig,
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
            data_at_rest: DataAtRestScannerConfig::default(),
            ssh: SshScannerConfig::default(),
            network: NetworkScannerConfig::default(),
            starttls: StartTlsScannerConfig::default(),
        }
    }
}

/// STARTTLS fingerprinting (PostgreSQL SSLRequest, SMTP STARTTLS). Only probes
/// declared targets — negotiates the plaintext upgrade, then reads the TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartTlsScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Declared targets as "protocol://host:port" or "host:port" (protocol
    /// inferred from the port). e.g. "postgres://db.internal:5432".
    #[serde(default)]
    pub targets: Vec<String>,
}

impl Default for StartTlsScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 10,
            targets: vec![],
        }
    }
}

/// SSH key-exchange fingerprinting. Only ever probes hosts explicitly listed in
/// `targets` (or handed to `POST /api/scans`) — never a discovered range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub targets: Vec<String>,
}

impl Default for SshScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 10,
            targets: vec![],
        }
    }
}

/// TCP connect-scan of crypto-relevant ports on **authorized** hosts. Active
/// scanning is opt-in and strictly scoped: it only touches hosts in `targets`
/// (host or host:port), never a discovered or inferred range, and it makes a
/// plain connect (no exploitation). Open TLS/SSH ports are handed to the TLS
/// and SSH scanners for algorithm fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScannerConfig {
    /// Off by default — active network scanning must be deliberately enabled.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    /// Crypto-relevant ports to probe when a target names a bare host.
    #[serde(default = "default_crypto_ports")]
    pub ports: Vec<u16>,
    /// Authorized hosts (host or host:port). Empty = scan nothing.
    #[serde(default)]
    pub targets: Vec<String>,
}

impl Default for NetworkScannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            connect_timeout_ms: default_connect_timeout(),
            ports: default_crypto_ports(),
            targets: vec![],
        }
    }
}

fn default_connect_timeout() -> u64 {
    1500
}

/// Ports where a cryptographic protocol is expected — the ones worth
/// fingerprinting for PQC readiness.
fn default_crypto_ports() -> Vec<u16> {
    vec![
        22,    // SSH
        25,    // SMTP (STARTTLS)
        443,   // HTTPS / TLS
        465,   // SMTPS
        587,   // SMTP submission (STARTTLS)
        636,   // LDAPS
        853,   // DNS-over-TLS
        993,   // IMAPS
        995,   // POP3S
        3389,  // RDP (TLS)
        5432,  // PostgreSQL (TLS)
        6443,  // Kubernetes API (TLS)
        8443,  // HTTPS-alt
    ]
}

/// A declared data store whose at-rest encryption posture we evaluate. Values
/// come from config or (later) from cloud connectors; the scanner classifies
/// them without touching the data itself. Fields use snake_case to match the
/// rest of the YAML config (key_wrap, key_age_days, in_transit_tls).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStoreDecl {
    pub id: String,
    /// "database" | "object_store" | "volume" | "kms_dataset" | ...
    pub kind: String,
    /// host:port, bucket URI, or logical name.
    pub address: String,
    /// At-rest cipher, e.g. "aes-256-gcm", "aes-128", "none", "chacha20".
    #[serde(default)]
    pub encryption: String,
    /// How the data-encryption key is protected: "aes-256" (symmetric envelope),
    /// "rsa-2048" / "ecdh-p256" (quantum-vulnerable envelope), "ml-kem-768"
    /// (PQC), "hsm", or "" if unknown. This is the HNDL-critical field.
    #[serde(default)]
    pub key_wrap: String,
    /// Age of the current data key in days (0 = unknown).
    #[serde(default)]
    pub key_age_days: u32,
    /// Whether connections to the store are encrypted in transit (TLS).
    #[serde(default)]
    pub in_transit_tls: bool,
    #[serde(default)]
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAtRestScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Rotate at-rest keys at least this often; older keys are flagged.
    #[serde(default = "default_rotation_days")]
    pub max_key_age_days: u32,
    #[serde(default)]
    pub stores: Vec<DataStoreDecl>,
}

impl Default for DataAtRestScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_key_age_days: default_rotation_days(),
            stores: vec![],
        }
    }
}

fn default_rotation_days() -> u32 {
    365
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

    fn golden_finding(at: CryptoAssetType, pqc: PqcStatus) -> Finding {
        Finding {
            id: "x".into(),
            category: FindingCategory::MissingPqc,
            severity: FindingSeverity::Medium,
            title: "t".into(),
            description: "d".into(),
            asset: CryptoAsset {
                id: "a".into(),
                asset_type: at,
                name: "n".into(),
                algorithm: Some("RSA-2048".into()),
                key_length: Some(2048),
                protocol_version: Some("TLS1.3".into()),
                location: AssetLocation {
                    source_type: "s".into(),
                    path: "host:443".into(),
                    line: None,
                },
                discovered_by: "tls".into(),
                discovered_at: Utc::now(),
            },
            remediation: None,
            pqc_status: pqc,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn confidence_golden_corpus() {
        use CryptoAssetType::*;
        use PqcStatus::*;
        // Live measurements -> High.
        assert_eq!(confidence_of(&golden_finding(TlsConnection, ClassicalSecure)), Confidence::High);
        assert_eq!(confidence_of(&golden_finding(Certificate, ClassicalWeak)), Confidence::High);
        assert_eq!(confidence_of(&golden_finding(DataStore, ClassicalWeak)), Confidence::High);
        // Static / heuristic match -> Medium.
        assert_eq!(confidence_of(&golden_finding(CryptoLibrary, ClassicalSecure)), Confidence::Medium);
        // Uncharacterized (port answered, crypto unread) -> Low, whatever the type.
        assert_eq!(confidence_of(&golden_finding(TlsConnection, Unknown)), Confidence::Low);
        assert_eq!(confidence_of(&golden_finding(Certificate, Unknown)), Confidence::Low);
    }

    #[test]
    fn evidence_records_probe_and_observation() {
        let ev = evidence_of(&golden_finding(CryptoAssetType::TlsConnection, PqcStatus::ClassicalSecure), "tls");
        assert!(ev.iter().any(|e| e.contains("Probe: tls")));
        assert!(ev.iter().any(|e| e.starts_with("Location: host:443")));
        assert!(ev.iter().any(|e| e.contains("Algorithm: RSA-2048")));
        assert!(ev.iter().any(|e| e.contains("Key length: 2048")));
        assert!(ev.iter().any(|e| e.starts_with("Classified: classical_secure")));
    }

    #[test]
    fn finding_record_defaults_are_backward_compatible() {
        // A record serialized before confidence/status existed must still load.
        let legacy = r#"{"id":"1","scanId":"s","category":"missing_pqc","severity":"medium",
            "title":"t","description":"d","assetType":"tls_connection","algorithm":null,
            "pqcStatus":"classical_weak","location":"h:443","remediation":null,
            "createdAt":"2026-01-01T00:00:00Z"}"#;
        let r: FindingRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(r.status, FindingStatus::Open);
        assert_eq!(r.confidence, Confidence::Medium);
        assert!(r.evidence.is_empty());
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
