use crate::registry::{Scanner, ScannerError};
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;

/// Known crypto libraries and their PQC readiness status
struct CryptoLib {
    name: &'static str,
    pqc_status: PqcStatus,
    description: &'static str,
}

const CRYPTO_LIBS: &[CryptoLib] = &[
    // PQC-ready libraries
    CryptoLib {
        name: "ml-dsa",
        pqc_status: PqcStatus::PqcReady,
        description: "NIST ML-DSA post-quantum signature scheme",
    },
    CryptoLib {
        name: "ml-kem",
        pqc_status: PqcStatus::PqcReady,
        description: "NIST ML-KEM post-quantum key encapsulation",
    },
    CryptoLib {
        name: "pqcrypto",
        pqc_status: PqcStatus::PqcReady,
        description: "Post-quantum cryptography library",
    },
    CryptoLib {
        name: "oqs",
        pqc_status: PqcStatus::PqcReady,
        description: "Open Quantum Safe library",
    },
    CryptoLib {
        name: "liboqs",
        pqc_status: PqcStatus::PqcReady,
        description: "Open Quantum Safe C library",
    },
    CryptoLib {
        name: "pqc",
        pqc_status: PqcStatus::PqcReady,
        description: "Post-quantum cryptography",
    },
    CryptoLib {
        name: "crystals-kyber",
        pqc_status: PqcStatus::PqcReady,
        description: "CRYSTALS-Kyber KEM",
    },
    CryptoLib {
        name: "crystals-dilithium",
        pqc_status: PqcStatus::PqcReady,
        description: "CRYSTALS-Dilithium signature",
    },
    // Classical secure libraries
    CryptoLib {
        name: "openssl",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "OpenSSL cryptographic library",
    },
    CryptoLib {
        name: "ring",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Safe, fast crypto using Rust",
    },
    CryptoLib {
        name: "rustls",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Modern TLS library in Rust",
    },
    CryptoLib {
        name: "boring",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "BoringSSL bindings",
    },
    CryptoLib {
        name: "boringssl",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "BoringSSL",
    },
    CryptoLib {
        name: "mbedtls",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Mbed TLS library",
    },
    CryptoLib {
        name: "libsodium",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Modern crypto library",
    },
    CryptoLib {
        name: "nacl",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Networking and Cryptography library",
    },
    CryptoLib {
        name: "tweetnacl",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Compact NaCl implementation",
    },
    CryptoLib {
        name: "bcrypt",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Bcrypt password hashing",
    },
    CryptoLib {
        name: "argon2",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Argon2 password hashing",
    },
    CryptoLib {
        name: "scrypt",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Scrypt key derivation",
    },
    CryptoLib {
        name: "aes-gcm",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "AES-GCM authenticated encryption",
    },
    CryptoLib {
        name: "chacha20poly1305",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "ChaCha20-Poly1305 AEAD",
    },
    CryptoLib {
        name: "ed25519-dalek",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Ed25519 signatures",
    },
    CryptoLib {
        name: "x25519-dalek",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "X25519 key exchange",
    },
    CryptoLib {
        name: "p256",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "NIST P-256 elliptic curve",
    },
    CryptoLib {
        name: "p384",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "NIST P-384 elliptic curve",
    },
    CryptoLib {
        name: "cryptography",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "Python cryptography package",
    },
    CryptoLib {
        name: "crypto-js",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "JavaScript crypto library",
    },
    CryptoLib {
        name: "node-forge",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "JavaScript TLS/crypto library",
    },
    CryptoLib {
        name: "jose",
        pqc_status: PqcStatus::ClassicalSecure,
        description: "JavaScript JOSE library",
    },
    // Classical weak / deprecated
    CryptoLib {
        name: "pycrypto",
        pqc_status: PqcStatus::ClassicalWeak,
        description: "Unmaintained Python crypto (use pycryptodome)",
    },
    CryptoLib {
        name: "pydes",
        pqc_status: PqcStatus::ClassicalWeak,
        description: "DES encryption (weak)",
    },
    CryptoLib {
        name: "des",
        pqc_status: PqcStatus::ClassicalWeak,
        description: "DES encryption (weak, 56-bit)",
    },
    CryptoLib {
        name: "rc4",
        pqc_status: PqcStatus::ClassicalWeak,
        description: "RC4 stream cipher (broken)",
    },
];

pub struct DependencyScanner;

impl Default for DependencyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyScanner {
    pub fn new() -> Self {
        Self
    }

    fn detect_file_type(path: &str) -> Option<&'static str> {
        if path.ends_with("Cargo.toml") {
            Some("cargo")
        } else if path.ends_with("package.json") {
            Some("npm")
        } else if path.ends_with("requirements.txt") {
            Some("pip")
        } else if path.ends_with("Cargo.lock") {
            Some("cargo_lock")
        } else if path.ends_with("go.mod") {
            Some("go")
        } else {
            None
        }
    }

    fn parse_cargo_toml(content: &str, path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let parsed: toml::Value = match content.parse() {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let sections = ["dependencies", "dev-dependencies", "build-dependencies"];
        for section in &sections {
            if let Some(deps) = parsed.get(section).and_then(|d| d.as_table()) {
                for (dep_name, _dep_value) in deps {
                    let normalized = dep_name.to_lowercase().replace('_', "-");
                    if let Some(crypto_lib) = CRYPTO_LIBS.iter().find(|cl| cl.name == normalized) {
                        let (severity, category) = match &crypto_lib.pqc_status {
                            PqcStatus::PqcReady => {
                                (FindingSeverity::Info, FindingCategory::PqcReady)
                            }
                            PqcStatus::ClassicalSecure => {
                                (FindingSeverity::Medium, FindingCategory::ClassicalCrypto)
                            }
                            PqcStatus::ClassicalWeak => {
                                (FindingSeverity::High, FindingCategory::WeakAlgorithm)
                            }
                            _ => (FindingSeverity::Low, FindingCategory::ClassicalCrypto),
                        };

                        findings.push(Finding {
                            id: uuid::Uuid::new_v4().to_string(),
                            category,
                            severity,
                            title: format!("Crypto dependency: {dep_name}"),
                            description: format!(
                                "{} found in [{section}] - {}",
                                dep_name, crypto_lib.description
                            ),
                            asset: CryptoAsset {
                                id: uuid::Uuid::new_v4().to_string(),
                                asset_type: CryptoAssetType::CryptoLibrary,
                                name: dep_name.clone(),
                                algorithm: None,
                                key_length: None,
                                protocol_version: None,
                                location: AssetLocation {
                                    source_type: "dependency_file".to_string(),
                                    path: path.to_string(),
                                    line: None,
                                },
                                discovered_by: "dependency".to_string(),
                                discovered_at: Utc::now(),
                            },
                            remediation: match &crypto_lib.pqc_status {
                                PqcStatus::PqcReady => None,
                                PqcStatus::ClassicalSecure => Some(
                                    "Consider adding PQC alternatives alongside this classical crypto library".to_string()
                                ),
                                PqcStatus::ClassicalWeak => Some(format!(
                                    "Replace {} with a modern, maintained alternative", dep_name
                                )),
                                _ => None,
                            },
                            pqc_status: crypto_lib.pqc_status.clone(),
                            metadata: HashMap::from([
                                ("section".to_string(), section.to_string()),
                                ("ecosystem".to_string(), "cargo".to_string()),
                            ]),
                        });
                    }
                }
            }
        }

        // Also check workspace dependencies
        if let Some(workspace) = parsed.get("workspace") {
            if let Some(deps) = workspace.get("dependencies").and_then(|d| d.as_table()) {
                for (dep_name, _dep_value) in deps {
                    let normalized = dep_name.to_lowercase().replace('_', "-");
                    if let Some(crypto_lib) = CRYPTO_LIBS.iter().find(|cl| cl.name == normalized) {
                        let (severity, category) = match &crypto_lib.pqc_status {
                            PqcStatus::PqcReady => {
                                (FindingSeverity::Info, FindingCategory::PqcReady)
                            }
                            PqcStatus::ClassicalSecure => {
                                (FindingSeverity::Medium, FindingCategory::ClassicalCrypto)
                            }
                            PqcStatus::ClassicalWeak => {
                                (FindingSeverity::High, FindingCategory::WeakAlgorithm)
                            }
                            _ => (FindingSeverity::Low, FindingCategory::ClassicalCrypto),
                        };

                        findings.push(Finding {
                            id: uuid::Uuid::new_v4().to_string(),
                            category,
                            severity,
                            title: format!("Crypto dependency: {dep_name}"),
                            description: format!(
                                "{} found in [workspace.dependencies] - {}",
                                dep_name, crypto_lib.description
                            ),
                            asset: CryptoAsset {
                                id: uuid::Uuid::new_v4().to_string(),
                                asset_type: CryptoAssetType::CryptoLibrary,
                                name: dep_name.clone(),
                                algorithm: None,
                                key_length: None,
                                protocol_version: None,
                                location: AssetLocation {
                                    source_type: "dependency_file".to_string(),
                                    path: path.to_string(),
                                    line: None,
                                },
                                discovered_by: "dependency".to_string(),
                                discovered_at: Utc::now(),
                            },
                            remediation: match &crypto_lib.pqc_status {
                                PqcStatus::PqcReady => None,
                                PqcStatus::ClassicalSecure => Some(
                                    "Consider adding PQC alternatives alongside this classical crypto library".to_string()
                                ),
                                PqcStatus::ClassicalWeak => Some(format!(
                                    "Replace {} with a modern, maintained alternative", dep_name
                                )),
                                _ => None,
                            },
                            pqc_status: crypto_lib.pqc_status.clone(),
                            metadata: HashMap::from([
                                ("section".to_string(), "workspace.dependencies".to_string()),
                                ("ecosystem".to_string(), "cargo".to_string()),
                            ]),
                        });
                    }
                }
            }
        }

        findings
    }

    fn parse_package_json(content: &str, path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let parsed: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let sections = ["dependencies", "devDependencies"];
        for section in &sections {
            if let Some(deps) = parsed.get(section).and_then(|d| d.as_object()) {
                for (dep_name, _) in deps {
                    let normalized = dep_name.to_lowercase();
                    if let Some(crypto_lib) = CRYPTO_LIBS.iter().find(|cl| cl.name == normalized) {
                        let (severity, category) = match &crypto_lib.pqc_status {
                            PqcStatus::PqcReady => {
                                (FindingSeverity::Info, FindingCategory::PqcReady)
                            }
                            PqcStatus::ClassicalSecure => {
                                (FindingSeverity::Medium, FindingCategory::ClassicalCrypto)
                            }
                            PqcStatus::ClassicalWeak => {
                                (FindingSeverity::High, FindingCategory::WeakAlgorithm)
                            }
                            _ => (FindingSeverity::Low, FindingCategory::ClassicalCrypto),
                        };

                        findings.push(Finding {
                            id: uuid::Uuid::new_v4().to_string(),
                            category,
                            severity,
                            title: format!("Crypto dependency: {dep_name}"),
                            description: format!(
                                "{} found in {section} - {}",
                                dep_name, crypto_lib.description
                            ),
                            asset: CryptoAsset {
                                id: uuid::Uuid::new_v4().to_string(),
                                asset_type: CryptoAssetType::CryptoLibrary,
                                name: dep_name.clone(),
                                algorithm: None,
                                key_length: None,
                                protocol_version: None,
                                location: AssetLocation {
                                    source_type: "dependency_file".to_string(),
                                    path: path.to_string(),
                                    line: None,
                                },
                                discovered_by: "dependency".to_string(),
                                discovered_at: Utc::now(),
                            },
                            remediation: match &crypto_lib.pqc_status {
                                PqcStatus::PqcReady => None,
                                PqcStatus::ClassicalSecure => Some(
                                    "Consider adding PQC alternatives alongside this classical crypto library".to_string()
                                ),
                                PqcStatus::ClassicalWeak => Some(format!(
                                    "Replace {} with a modern, maintained alternative", dep_name
                                )),
                                _ => None,
                            },
                            pqc_status: crypto_lib.pqc_status.clone(),
                            metadata: HashMap::from([
                                ("section".to_string(), section.to_string()),
                                ("ecosystem".to_string(), "npm".to_string()),
                            ]),
                        });
                    }
                }
            }
        }

        findings
    }

    fn parse_requirements_txt(content: &str, path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Match package names: handles "package", "package==1.0", "package>=1.0", "package[extra]"
        let re = Regex::new(r"^([A-Za-z0-9][\w.-]*)").unwrap();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }

            if let Some(caps) = re.captures(line) {
                let pkg_name = &caps[1];
                let normalized = pkg_name.to_lowercase().replace('_', "-");

                if let Some(crypto_lib) = CRYPTO_LIBS.iter().find(|cl| cl.name == normalized) {
                    let (severity, category) = match &crypto_lib.pqc_status {
                        PqcStatus::PqcReady => (FindingSeverity::Info, FindingCategory::PqcReady),
                        PqcStatus::ClassicalSecure => {
                            (FindingSeverity::Medium, FindingCategory::ClassicalCrypto)
                        }
                        PqcStatus::ClassicalWeak => {
                            (FindingSeverity::High, FindingCategory::WeakAlgorithm)
                        }
                        _ => (FindingSeverity::Low, FindingCategory::ClassicalCrypto),
                    };

                    findings.push(Finding {
                        id: uuid::Uuid::new_v4().to_string(),
                        category,
                        severity,
                        title: format!("Crypto dependency: {pkg_name}"),
                        description: format!(
                            "{} found in requirements - {}",
                            pkg_name, crypto_lib.description
                        ),
                        asset: CryptoAsset {
                            id: uuid::Uuid::new_v4().to_string(),
                            asset_type: CryptoAssetType::CryptoLibrary,
                            name: pkg_name.to_string(),
                            algorithm: None,
                            key_length: None,
                            protocol_version: None,
                            location: AssetLocation {
                                source_type: "dependency_file".to_string(),
                                path: path.to_string(),
                                line: None,
                            },
                            discovered_by: "dependency".to_string(),
                            discovered_at: Utc::now(),
                        },
                        remediation: match &crypto_lib.pqc_status {
                            PqcStatus::PqcReady => None,
                            PqcStatus::ClassicalSecure => Some(
                                "Consider adding PQC alternatives alongside this classical crypto library".to_string()
                            ),
                            PqcStatus::ClassicalWeak => Some(format!(
                                "Replace {} with a modern, maintained alternative", pkg_name
                            )),
                            _ => None,
                        },
                        pqc_status: crypto_lib.pqc_status.clone(),
                        metadata: HashMap::from([
                            ("ecosystem".to_string(), "pip".to_string()),
                        ]),
                    });
                }
            }
        }

        findings
    }
}

#[async_trait]
impl Scanner for DependencyScanner {
    fn id(&self) -> &str {
        "dependency"
    }
    fn display_name(&self) -> &str {
        "Dependency Scanner"
    }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::ClassicalCrypto,
            FindingCategory::WeakAlgorithm,
            FindingCategory::PqcReady,
            FindingCategory::VulnerableLibrary,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::DependencyFile)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();

        let file_type = Self::detect_file_type(&target.address).ok_or_else(|| {
            ScannerError::Other(format!("Unsupported dependency file: {}", target.address))
        })?;

        let content = if let Some(c) = target.metadata.get("content") {
            c.clone()
        } else {
            tokio::fs::read_to_string(&target.address)
                .await
                .map_err(ScannerError::IoError)?
        };

        let findings = match file_type {
            "cargo" => Self::parse_cargo_toml(&content, &target.address),
            "npm" => Self::parse_package_json(&content, &target.address),
            "pip" => Self::parse_requirements_txt(&content, &target.address),
            _ => Vec::new(),
        };

        Ok(ScanResult {
            scanner_id: "dependency".to_string(),
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
    fn test_detect_file_type() {
        assert_eq!(
            DependencyScanner::detect_file_type("Cargo.toml"),
            Some("cargo")
        );
        assert_eq!(
            DependencyScanner::detect_file_type("/path/to/Cargo.toml"),
            Some("cargo")
        );
        assert_eq!(
            DependencyScanner::detect_file_type("package.json"),
            Some("npm")
        );
        assert_eq!(
            DependencyScanner::detect_file_type("requirements.txt"),
            Some("pip")
        );
        assert_eq!(DependencyScanner::detect_file_type("go.mod"), Some("go"));
        assert_eq!(DependencyScanner::detect_file_type("random.txt"), None);
    }

    #[test]
    fn test_parse_cargo_toml_finds_crypto_deps() {
        let toml_content = "[package]\nname = \"my-app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nring = \"0.17\"\nml-dsa = \"0.1\"\ntokio = \"1\"\n\n[dev-dependencies]\npycrypto = \"0.1\"\n";

        let findings = DependencyScanner::parse_cargo_toml(toml_content, "Cargo.toml");

        // Should find ring (classical secure), ml-dsa (pqc ready), pycrypto (classical weak)
        assert_eq!(findings.len(), 3);

        let ring_finding = findings.iter().find(|f| f.title.contains("ring")).unwrap();
        assert_eq!(ring_finding.pqc_status, PqcStatus::ClassicalSecure);
        assert_eq!(ring_finding.severity, FindingSeverity::Medium);

        let ml_dsa_finding = findings
            .iter()
            .find(|f| f.title.contains("ml-dsa"))
            .unwrap();
        assert_eq!(ml_dsa_finding.pqc_status, PqcStatus::PqcReady);
        assert_eq!(ml_dsa_finding.severity, FindingSeverity::Info);

        let pycrypto_finding = findings
            .iter()
            .find(|f| f.title.contains("pycrypto"))
            .unwrap();
        assert_eq!(pycrypto_finding.pqc_status, PqcStatus::ClassicalWeak);
        assert_eq!(pycrypto_finding.severity, FindingSeverity::High);
    }

    #[test]
    fn test_parse_cargo_toml_workspace_deps() {
        let toml_content =
            "[workspace.dependencies]\nml-kem = \"0.3\"\nsha3 = \"0.10\"\nring = \"0.17\"\n";

        let findings = DependencyScanner::parse_cargo_toml(toml_content, "Cargo.toml");

        // Should find ml-kem (pqc ready) and ring (classical secure)
        assert_eq!(findings.len(), 2);

        let ml_kem = findings
            .iter()
            .find(|f| f.title.contains("ml-kem"))
            .unwrap();
        assert_eq!(ml_kem.pqc_status, PqcStatus::PqcReady);
    }

    #[test]
    fn test_parse_package_json_finds_crypto_deps() {
        let json_content = "{\"name\":\"my-app\",\"dependencies\":{\"express\":\"^4.0.0\",\"crypto-js\":\"^4.2.0\",\"node-forge\":\"^1.3.0\"},\"devDependencies\":{\"jest\":\"^29.0.0\",\"bcrypt\":\"^5.0.0\"}}";

        let findings = DependencyScanner::parse_package_json(json_content, "package.json");

        // Should find crypto-js, node-forge, bcrypt
        assert_eq!(findings.len(), 3);

        let crypto_js = findings
            .iter()
            .find(|f| f.title.contains("crypto-js"))
            .unwrap();
        assert_eq!(crypto_js.pqc_status, PqcStatus::ClassicalSecure);

        let bcrypt = findings
            .iter()
            .find(|f| f.title.contains("bcrypt"))
            .unwrap();
        assert_eq!(bcrypt.pqc_status, PqcStatus::ClassicalSecure);
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = "# Production deps\nflask==2.3.0\ncryptography>=41.0\npycrypto==2.6.1\n\n# Dev deps\n-e .\npytest>=7.0\n";

        let findings = DependencyScanner::parse_requirements_txt(content, "requirements.txt");

        // Should find cryptography (classical secure) and pycrypto (classical weak)
        assert_eq!(findings.len(), 2);

        let crypto = findings
            .iter()
            .find(|f| f.title.contains("cryptography"))
            .unwrap();
        assert_eq!(crypto.pqc_status, PqcStatus::ClassicalSecure);

        let pycrypto = findings
            .iter()
            .find(|f| f.title.contains("pycrypto"))
            .unwrap();
        assert_eq!(pycrypto.pqc_status, PqcStatus::ClassicalWeak);
        assert!(pycrypto.remediation.is_some());
    }

    #[test]
    fn test_parse_requirements_txt_skips_comments_and_flags() {
        let content = "# This is a comment\n--index-url https://example.com/simple\n-r other-requirements.txt\nbcrypt>=4.0\n";

        let findings = DependencyScanner::parse_requirements_txt(content, "requirements.txt");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("bcrypt"));
    }

    #[tokio::test]
    async fn test_scan_uses_inline_content_metadata() {
        let scanner = DependencyScanner::new();
        let mut target = ScanTarget::dependency_file("acme/Cargo.toml");
        target.metadata.insert(
            "content".to_string(),
            "[dependencies]\nml-dsa = \"0.1\"\n".to_string(),
        );

        let result = scanner.scan(&target).await.unwrap();
        assert!(matches!(result.status, ScanStatus::Completed));
        assert_eq!(result.findings.len(), 1);
        let f = &result.findings[0];
        assert!(f.title.contains("ml-dsa"));
        assert_eq!(f.pqc_status, PqcStatus::PqcReady);
    }

    #[test]
    fn test_empty_cargo_toml() {
        let toml_content = "[package]\nname = \"my-app\"\nversion = \"0.1.0\"\n";

        let findings = DependencyScanner::parse_cargo_toml(toml_content, "Cargo.toml");
        assert!(findings.is_empty());
    }
}
