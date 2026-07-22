//! Certificate-Transparency monitoring.
//!
//! Every publicly-trusted certificate is written to append-only CT logs. This
//! queries crt.sh for a domain (including its subdomains), fetches each
//! recently-logged certificate, and classifies its signature crypto. It surfaces
//! certificates you may not know about — shadow IT, forgotten subdomains,
//! mis-issuance — and their post-quantum posture. It reads only public log data:
//! no credentials, no access to any host.

use crate::certinfo::classify_cert;
use crate::registry::{Scanner, ScannerError};
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

pub struct CtScanner {
    max_certs: usize,
    timeout_secs: u64,
    /// CT aggregator base URL (default https://crt.sh). Overridable for a proxy,
    /// a private aggregator, or testing.
    base_url: String,
}

/// One row of crt.sh's `output=json` response.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct CrtShEntry {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub common_name: String,
    #[serde(default)]
    pub name_value: String,
    #[serde(default)]
    pub issuer_name: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub entry_timestamp: String,
}

impl CtScanner {
    pub fn new(max_certs: usize, timeout_secs: u64) -> Self {
        Self {
            max_certs: max_certs.clamp(1, 200),
            timeout_secs: timeout_secs.max(5),
            base_url: "https://crt.sh".to_string(),
        }
    }

    /// Point at a different CT aggregator (proxy / private mirror / test server).
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        let u = url.into();
        if !u.trim().is_empty() {
            self.base_url = u.trim_end_matches('/').to_string();
        }
        self
    }

    /// Parse crt.sh JSON, newest first, deduped by cert id, capped.
    fn parse_entries(json: &str, cap: usize) -> Vec<CrtShEntry> {
        let mut entries: Vec<CrtShEntry> = serde_json::from_str(json).unwrap_or_default();
        entries.sort_by(|a, b| b.entry_timestamp.cmp(&a.entry_timestamp));
        let mut seen = HashSet::new();
        entries.retain(|e| e.id != 0 && seen.insert(e.id));
        entries.truncate(cap);
        entries
    }

    /// Turn a classified crt.sh entry into a Finding.
    fn to_finding(e: &CrtShEntry, algorithm: String, pqc: PqcStatus) -> Finding {
        let cn = if e.common_name.is_empty() {
            e.name_value.lines().next().unwrap_or("(unknown)").to_string()
        } else {
            e.common_name.clone()
        };
        let weak = matches!(pqc, PqcStatus::ClassicalWeak);
        let (severity, category) = if weak {
            (FindingSeverity::High, FindingCategory::WeakAlgorithm)
        } else {
            (FindingSeverity::Medium, FindingCategory::MissingPqc)
        };
        let mut metadata = HashMap::new();
        metadata.insert("source".to_string(), "crt.sh".to_string());
        metadata.insert("ct_id".to_string(), e.id.to_string());
        metadata.insert("issuer".to_string(), e.issuer_name.clone());
        metadata.insert("serial".to_string(), e.serial_number.clone());
        metadata.insert("entry_timestamp".to_string(), e.entry_timestamp.clone());

        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            category,
            severity,
            title: format!("CT-logged certificate for {cn}"),
            description: format!(
                "Publicly logged certificate (crt.sh #{}) for {cn}, issued by {}. Signature: {algorithm}. {}",
                e.id,
                e.issuer_name,
                if weak {
                    "Weak signature — replace and reissue now."
                } else {
                    "Classical signature — reissue as a hybrid/ML-DSA certificate before the CNSA-2.0 deadline."
                },
            ),
            asset: CryptoAsset {
                id: uuid::Uuid::new_v4().to_string(),
                asset_type: CryptoAssetType::Certificate,
                name: format!("CT certificate for {cn}"),
                algorithm: Some(algorithm),
                key_length: None,
                protocol_version: None,
                location: AssetLocation {
                    source_type: "ct_log".to_string(),
                    path: cn.clone(),
                    line: None,
                },
                discovered_by: "ct".to_string(),
                discovered_at: Utc::now(),
            },
            remediation: Some(
                "Reissue as a hybrid (ML-DSA) certificate. Investigate any certificate you didn't expect — a CT-logged cert you don't recognise can mean shadow IT or mis-issuance.".to_string(),
            ),
            pqc_status: pqc,
            metadata,
        }
    }

    async fn get(client: &reqwest::Client, url: &str) -> Result<String, ScannerError> {
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        resp.text()
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))
    }
}

/// Percent-encode a domain for the crt.sh query string.
fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-._~".contains(c) {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

#[async_trait]
impl Scanner for CtScanner {
    fn id(&self) -> &str {
        "ct"
    }
    fn display_name(&self) -> &str {
        "Certificate-Transparency Monitor"
    }
    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::MissingPqc,
            FindingCategory::WeakAlgorithm,
            FindingCategory::ClassicalCrypto,
        ]
    }
    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::CtDomain)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let domain = target.address.trim().trim_start_matches("*.");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .user_agent("QuantaWatch-CT/1.0")
            .build()
            .map_err(|e| ScannerError::Other(e.to_string()))?;

        // Match the domain and its subdomains, and skip already-expired certs.
        let list_url = format!(
            "{}/?q={}&output=json&exclude=expired",
            self.base_url,
            urlencode(domain)
        );
        let json = Self::get(&client, &list_url).await?;
        let entries = Self::parse_entries(&json, self.max_certs);

        let mut findings = Vec::new();
        for e in &entries {
            // Fetch the actual certificate and classify its signature crypto.
            let pem = Self::get(&client, &format!("{}/?d={}", self.base_url, e.id))
                .await
                .ok();
            let (algorithm, pqc) = match pem.as_deref().and_then(|p| classify_cert(p.as_bytes())) {
                Some(s) => (s.algorithm, s.pqc_status),
                None => ("unknown".to_string(), PqcStatus::Unknown),
            };
            findings.push(Self::to_finding(e, algorithm, pqc));
        }

        Ok(ScanResult {
            scanner_id: "ct".to_string(),
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

    const SAMPLE: &str = r#"[
      {"id":11,"common_name":"a.example.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3","serial_number":"0a","entry_timestamp":"2026-07-01T00:00:00"},
      {"id":22,"common_name":"b.example.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3","serial_number":"0b","entry_timestamp":"2026-07-20T00:00:00"},
      {"id":22,"common_name":"b.example.com","issuer_name":"dup","serial_number":"0b","entry_timestamp":"2026-07-20T00:00:00"}
    ]"#;

    #[test]
    fn parses_dedupes_and_orders_newest_first() {
        let e = CtScanner::parse_entries(SAMPLE, 10);
        assert_eq!(e.len(), 2, "duplicate id collapsed");
        assert_eq!(e[0].id, 22, "newest entry_timestamp first");
        assert_eq!(e[1].id, 11);
    }

    #[test]
    fn respects_the_cap() {
        assert_eq!(CtScanner::parse_entries(SAMPLE, 1).len(), 1);
    }

    #[test]
    fn empty_or_garbage_json_is_no_findings_not_a_crash() {
        assert!(CtScanner::parse_entries("not json", 10).is_empty());
        assert!(CtScanner::parse_entries("[]", 10).is_empty());
    }

    #[test]
    fn weak_signature_becomes_a_high_severity_finding() {
        let e = CtScanner::parse_entries(SAMPLE, 1)[0].clone();
        let f = CtScanner::to_finding(&e, "sha1WithRSAEncryption".into(), PqcStatus::ClassicalWeak);
        assert_eq!(f.severity, FindingSeverity::High);
        assert!(matches!(f.category, FindingCategory::WeakAlgorithm));
        assert!(matches!(f.asset.asset_type, CryptoAssetType::Certificate));
        assert_eq!(f.metadata.get("source").unwrap(), "crt.sh");
        assert!(f.title.contains("b.example.com"));
    }

    #[test]
    fn classical_signature_is_medium_missing_pqc() {
        let e = CtScanner::parse_entries(SAMPLE, 1)[0].clone();
        let f = CtScanner::to_finding(&e, "ecdsa-with-SHA256".into(), PqcStatus::ClassicalSecure);
        assert_eq!(f.severity, FindingSeverity::Medium);
        assert!(matches!(f.category, FindingCategory::MissingPqc));
    }
}
