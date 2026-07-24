use crate::registry::{Scanner, ScannerError};
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

const MAX_FILES: usize = 2000;
const MAX_FILE_SIZE: u64 = 1_048_576; // 1 MB
const MAX_FINDINGS: usize = 500;

const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "rb", "c", "cpp", "h", "cs",
];

const DEFAULT_SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "dist", "build"];

pub struct CodeScanner {
    config: CodeScannerConfig,
}

/// A compiled pattern with its associated classification metadata.
struct CodePattern {
    re: Regex,
    category: FindingCategory,
    severity: FindingSeverity,
    pqc_status: PqcStatus,
    asset_type: CryptoAssetType,
    title: &'static str,
    redact: bool,
}

/// The recommended PQC library for a source file's language (by extension), so
/// the fix suggestion is actionable in the developer's own stack.
fn lang_pqc_lib(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "rs" => "the RustCrypto ml-dsa / ml-kem crates",
        "py" => "liboqs-python (oqs) or pqcrypto (ML-DSA / ML-KEM)",
        "go" => "Cloudflare CIRCL (circl/sign/mldsa, circl/kem/mlkem)",
        "java" => "BouncyCastle's PQC provider (ML-DSA / ML-KEM)",
        "cs" => "BouncyCastle.NET PQC (ML-DSA / ML-KEM)",
        "js" | "ts" | "jsx" | "tsx" => "@noble/post-quantum (ml-dsa / ml-kem)",
        "c" | "cpp" | "h" => "liboqs (OQS_SIG_ml_dsa_65, OQS_KEM_ml_kem_768)",
        "rb" => "liboqs-backed bindings (ML-DSA / ML-KEM)",
        _ => return None,
    })
}

/// The PQC target for a quantum-vulnerable primitive.
fn pqc_target(algo: &str) -> &'static str {
    let a = algo.to_uppercase();
    if a.contains("RSA") {
        "ML-DSA-65 (FIPS 204) for signatures, or ML-KEM-768 (FIPS 203) for key encapsulation"
    } else if a.contains("ECDSA") || a.contains("ED25519") || a.contains("DSA") {
        "ML-DSA-65 (FIPS 204)"
    } else {
        // ECDH / X25519 / DH / secp / prime — key exchange.
        "ML-KEM-768 (FIPS 203), ideally as an X25519MLKEM768 hybrid"
    }
}

/// Build the remediation string for a code finding.
fn remediation_for(category: &FindingCategory, matched: &str, ext: &str) -> Option<String> {
    match category {
        FindingCategory::HardcodedKey => Some(
            "Remove the hardcoded secret; load it from a secret manager or environment variable, and rotate the exposed credential."
                .to_string(),
        ),
        FindingCategory::WeakAlgorithm => Some(format!(
            "{matched} is broken — replace it (SHA-256/SHA-3 for hashing, AES-256-GCM for encryption)."
        )),
        FindingCategory::MissingPqc => {
            let lib = lang_pqc_lib(ext).unwrap_or("a liboqs-backed PQC library (ML-DSA / ML-KEM)");
            Some(format!(
                "{matched} is quantum-vulnerable (harvest-now-decrypt-later). Migrate to {}. In this file's language, use {lib}.",
                pqc_target(matched)
            ))
        }
        _ => None,
    }
}

impl CodeScanner {
    pub fn new(config: CodeScannerConfig) -> Self {
        Self { config }
    }

    fn build_patterns() -> Vec<CodePattern> {
        vec![
            // Hardcoded secrets (redacted).
            CodePattern {
                re: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----").unwrap(),
                category: FindingCategory::HardcodedKey,
                severity: FindingSeverity::High,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::SigningKey,
                title: "Hardcoded private key block",
                redact: true,
            },
            CodePattern {
                re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                category: FindingCategory::HardcodedKey,
                severity: FindingSeverity::High,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::SigningKey,
                title: "Hardcoded AWS access key",
                redact: true,
            },
            CodePattern {
                re: Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']"#).unwrap(),
                category: FindingCategory::HardcodedKey,
                severity: FindingSeverity::High,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::SigningKey,
                title: "Hardcoded API key or token",
                redact: true,
            },
            CodePattern {
                re: Regex::new(r#"(?i)password\s*[:=]\s*["'][^"']{8,}["']"#).unwrap(),
                category: FindingCategory::HardcodedKey,
                severity: FindingSeverity::High,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::SigningKey,
                title: "Hardcoded password",
                redact: true,
            },
            // Weak / broken algorithms.
            CodePattern {
                re: Regex::new(r"(?i)\bMD5\b").unwrap(),
                category: FindingCategory::WeakAlgorithm,
                severity: FindingSeverity::Medium,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::HashFunction,
                title: "Weak algorithm: MD5",
                redact: false,
            },
            CodePattern {
                re: Regex::new(r"(?i)\bSHA1\b").unwrap(),
                category: FindingCategory::WeakAlgorithm,
                severity: FindingSeverity::Medium,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::HashFunction,
                title: "Weak algorithm: SHA1",
                redact: false,
            },
            CodePattern {
                re: Regex::new(r"(?i)\bDES\b").unwrap(),
                category: FindingCategory::WeakAlgorithm,
                severity: FindingSeverity::Medium,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::CryptoLibrary,
                title: "Weak algorithm: DES",
                redact: false,
            },
            CodePattern {
                re: Regex::new(r"(?i)\bRC4\b").unwrap(),
                category: FindingCategory::WeakAlgorithm,
                severity: FindingSeverity::Medium,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::CryptoLibrary,
                title: "Weak algorithm: RC4",
                redact: false,
            },
            CodePattern {
                re: Regex::new(r"(?i)\bECB\b").unwrap(),
                category: FindingCategory::WeakAlgorithm,
                severity: FindingSeverity::Medium,
                pqc_status: PqcStatus::ClassicalWeak,
                asset_type: CryptoAssetType::CryptoLibrary,
                title: "Weak algorithm: ECB mode",
                redact: false,
            },
            // Quantum-vulnerable public-key crypto — the harvest-now-decrypt-later
            // surface. Each match captures the specific algorithm so the finding
            // carries a concrete PQC migration target.
            CodePattern {
                re: Regex::new(r"(?i)(\bRSA\b|\bDSA\b|\bECDSA\b|\bECDH\b|\bX25519\b|\bEd25519\b|\bsecp256r1\b|\bprime256v1\b|diffie[-_ ]?hellman)").unwrap(),
                category: FindingCategory::MissingPqc,
                severity: FindingSeverity::Medium,
                pqc_status: PqcStatus::ClassicalSecure,
                asset_type: CryptoAssetType::CryptoLibrary,
                title: "Quantum-vulnerable public-key crypto",
                redact: false,
            },
        ]
    }

    fn has_source_extension(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| SOURCE_EXTENSIONS.contains(&e.to_lowercase().as_str()))
            .unwrap_or(false)
    }

    fn should_skip_dir(name: &str, exclude: &[String]) -> bool {
        DEFAULT_SKIP_DIRS.contains(&name) || exclude.iter().any(|e| e == name)
    }

    /// Recursively collect source files under `dir`, honoring caps and exclusions.
    fn collect_files(dir: &Path, exclude: &[String], files: &mut Vec<std::path::PathBuf>) {
        if files.len() >= MAX_FILES {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            if files.len() >= MAX_FILES {
                return;
            }
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if Self::should_skip_dir(&name, exclude) {
                    continue;
                }
                Self::collect_files(&path, exclude, files);
            } else if file_type.is_file() && Self::has_source_extension(&path) {
                if let Ok(meta) = entry.metadata() {
                    if meta.len() > MAX_FILE_SIZE {
                        continue;
                    }
                }
                files.push(path);
            }
        }
    }

    /// Truncate a matched line to ~120 chars and optionally redact the matched secret.
    fn build_description(line: &str, matched: &str, redact: bool) -> String {
        let displayed = if redact {
            line.replace(matched, "***REDACTED***")
        } else {
            line.to_string()
        };
        let trimmed = displayed.trim();
        if trimmed.chars().count() > 120 {
            let truncated: String = trimmed.chars().take(120).collect();
            format!("{truncated}...")
        } else {
            trimmed.to_string()
        }
    }
}

#[async_trait]
impl Scanner for CodeScanner {
    fn id(&self) -> &str {
        "code"
    }
    fn display_name(&self) -> &str {
        "Code Scanner"
    }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::HardcodedKey,
            FindingCategory::WeakAlgorithm,
            FindingCategory::ClassicalCrypto,
            FindingCategory::MissingPqc,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::CodeDirectory)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let mut findings = Vec::new();

        let patterns = Self::build_patterns();
        let root = Path::new(&target.address);

        let mut files = Vec::new();
        Self::collect_files(root, &self.config.exclude, &mut files);

        'files: for path in &files {
            if findings.len() >= MAX_FINDINGS {
                break;
            }
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let rel_path = path.strip_prefix(root).unwrap_or(path);
            let rel_str = rel_path.to_string_lossy().to_string();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            for (line_no, line) in content.lines().enumerate() {
                for pat in &patterns {
                    if let Some(m) = pat.re.find(line) {
                        let matched = m.as_str();
                        let description = Self::build_description(line, matched, pat.redact);
                        // Capture the specific algorithm for weak / quantum-vulnerable
                        // findings so the migration planner can target a fix.
                        let algorithm = match pat.category {
                            FindingCategory::WeakAlgorithm | FindingCategory::MissingPqc => {
                                Some(matched.to_uppercase())
                            }
                            _ => None,
                        };
                        findings.push(Finding {
                            id: uuid::Uuid::new_v4().to_string(),
                            category: pat.category.clone(),
                            severity: pat.severity,
                            title: pat.title.to_string(),
                            description: format!(
                                "{} ({}:{}): {}",
                                pat.title,
                                rel_str,
                                line_no + 1,
                                description
                            ),
                            asset: CryptoAsset {
                                id: uuid::Uuid::new_v4().to_string(),
                                asset_type: pat.asset_type.clone(),
                                name: pat.title.to_string(),
                                algorithm,
                                key_length: None,
                                protocol_version: None,
                                location: AssetLocation {
                                    source_type: "code".to_string(),
                                    path: rel_str.clone(),
                                    line: Some((line_no + 1) as u32),
                                },
                                discovered_by: "code".to_string(),
                                discovered_at: Utc::now(),
                            },
                            remediation: remediation_for(&pat.category, matched, &ext),
                            pqc_status: pat.pqc_status,
                            metadata: HashMap::new(),
                        });
                        if findings.len() >= MAX_FINDINGS {
                            break 'files;
                        }
                    }
                }
            }
        }

        Ok(ScanResult {
            scanner_id: "code".to_string(),
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

    fn find_pattern(title: &str) -> CodePattern {
        CodeScanner::build_patterns()
            .into_iter()
            .find(|p| p.title == title)
            .unwrap()
    }

    #[test]
    fn test_private_key_pattern_matches() {
        let pat = find_pattern("Hardcoded private key block");
        assert!(pat.re.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(pat.re.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(pat.re.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(!pat.re.is_match("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn test_aws_key_pattern_matches() {
        let pat = find_pattern("Hardcoded AWS access key");
        assert!(pat.re.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!pat.re.is_match("not an aws key"));
    }

    #[test]
    fn test_api_key_pattern_matches() {
        let pat = find_pattern("Hardcoded API key or token");
        assert!(pat.re.is_match("api_key = \"abcd1234efgh5678ijkl\""));
        assert!(pat.re.is_match("secret-key: 'ABCDEFGHIJKLMNOP1234'"));
        assert!(!pat.re.is_match("api_key = \"short\""));
    }

    #[test]
    fn test_password_pattern_matches() {
        let pat = find_pattern("Hardcoded password");
        assert!(pat.re.is_match("password = \"supersecret\""));
        assert!(!pat.re.is_match("password = \"short\""));
    }

    #[test]
    fn test_md5_matches_but_not_aes() {
        let md5 = find_pattern("Weak algorithm: MD5");
        assert!(md5.re.is_match("let h = md5(data);"));
        assert!(md5.re.is_match("MD5"));

        let des = find_pattern("Weak algorithm: DES");
        assert!(des.re.is_match("cipher = DES.new(key)"));
        // AES must NOT match the DES word-boundary pattern.
        assert!(!des.re.is_match("cipher = AES.new(key)"));
    }

    #[test]
    fn test_sha1_matches_not_sha256() {
        let sha1 = find_pattern("Weak algorithm: SHA1");
        assert!(sha1.re.is_match("hash = SHA1(x)"));
        assert!(!sha1.re.is_match("hash = SHA256(x)"));
    }

    #[test]
    fn test_quantum_vulnerable_matches_and_captures() {
        let pat = find_pattern("Quantum-vulnerable public-key crypto");
        assert!(pat.re.is_match("use RSA for signing"));
        assert!(pat.re.is_match("let k = Ed25519::generate();"));
        assert!(pat.re.is_match("ECDSA signature"));
        assert!(pat.re.is_match("key = ECDH.compute()"));
        assert!(pat.re.is_match("Diffie-Hellman group 14"));
        // The match captures the specific token (drives the migration target).
        assert_eq!(
            pat.re.find("use RSA here").unwrap().as_str().to_uppercase(),
            "RSA"
        );
        // secp256r1 (an ECDSA/ECDH curve) is flagged; AES256 is not.
        assert!(pat.re.is_match("curve = secp256r1"));
        assert!(!pat.re.is_match("cipher = AES256"));
    }

    #[test]
    fn test_pqc_suggestions_are_algorithm_and_language_aware() {
        // RSA -> signatures/KEM target; Python -> pqcrypto/liboqs.
        let r = remediation_for(&FindingCategory::MissingPqc, "RSA", "py").unwrap();
        assert!(r.contains("ML-DSA-65"));
        assert!(r.contains("ML-KEM-768"));
        assert!(r.contains("pqcrypto") || r.contains("liboqs-python"));
        // ECDH -> KEM target; Go -> CIRCL.
        let g = remediation_for(&FindingCategory::MissingPqc, "ECDH", "go").unwrap();
        assert!(g.contains("ML-KEM-768"));
        assert!(g.contains("CIRCL"));
        // ECDSA -> signature target; Rust.
        let rs = remediation_for(&FindingCategory::MissingPqc, "ECDSA", "rs").unwrap();
        assert!(rs.contains("ML-DSA-65"));
        assert!(rs.contains("ml-dsa"));
    }

    #[test]
    fn test_redaction() {
        let line = "api_key = \"abcd1234efgh5678ijkl\"";
        let matched = "api_key = \"abcd1234efgh5678ijkl\"";
        let desc = CodeScanner::build_description(line, matched, true);
        assert!(desc.contains("***REDACTED***"));
        assert!(!desc.contains("abcd1234efgh5678ijkl"));
    }

    #[test]
    fn test_no_redaction_for_non_secret() {
        let line = "let h = md5(data);";
        let desc = CodeScanner::build_description(line, "md5", false);
        assert_eq!(desc, "let h = md5(data);");
    }

    #[test]
    fn test_description_truncation() {
        let long_line = "x".repeat(200);
        let desc = CodeScanner::build_description(&long_line, "x", false);
        assert!(desc.ends_with("..."));
        assert!(desc.chars().count() <= 123);
    }

    #[test]
    fn test_has_source_extension() {
        assert!(CodeScanner::has_source_extension(Path::new("foo.rs")));
        assert!(CodeScanner::has_source_extension(Path::new("foo.py")));
        assert!(!CodeScanner::has_source_extension(Path::new("foo.txt")));
        assert!(!CodeScanner::has_source_extension(Path::new("foo")));
    }

    #[test]
    fn test_should_skip_dir() {
        assert!(CodeScanner::should_skip_dir("target", &[]));
        assert!(CodeScanner::should_skip_dir("node_modules", &[]));
        assert!(!CodeScanner::should_skip_dir("src", &[]));
        assert!(CodeScanner::should_skip_dir(
            "vendor",
            &["vendor".to_string()]
        ));
    }
}
