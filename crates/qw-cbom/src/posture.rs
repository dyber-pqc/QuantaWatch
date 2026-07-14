use crate::model::*;
use qw_scanner::{CryptoAssetType, Finding, FindingSeverity, PqcStatus, ScanResult};
use std::collections::HashMap;

pub struct PostureEngine;

impl PostureEngine {
    /// Score a single finding's crypto asset based on PQC readiness
    pub fn score_pqc_status(status: &PqcStatus) -> f64 {
        match status {
            PqcStatus::PqcReady => 100.0,
            PqcStatus::Hybrid => 90.0,
            PqcStatus::ClassicalSecure => 60.0,
            PqcStatus::ClassicalWeak => 20.0,
            PqcStatus::Unknown => 40.0,
        }
    }

    /// Apply adjustments based on finding details
    pub fn score_finding(finding: &Finding) -> f64 {
        use qw_scanner::FindingCategory;

        let mut score = Self::score_pqc_status(&finding.pqc_status);

        match finding.category {
            FindingCategory::ExpiredCertificate => score -= 40.0,
            FindingCategory::ExpiringCertificate => score -= 15.0,
            FindingCategory::ShortKeyLength => score -= 20.0,
            FindingCategory::DeprecatedProtocol => score -= 10.0,
            FindingCategory::VulnerableLibrary => score -= 30.0,
            FindingCategory::HardcodedKey => score -= 25.0,
            FindingCategory::WeakAlgorithm => score -= 15.0,
            _ => {}
        }

        if finding.severity >= FindingSeverity::Critical {
            score -= 10.0;
        }

        score.clamp(0.0, 100.0)
    }

    /// Score a service (AI provider endpoint)
    pub fn score_service(info: &ProviderCryptoInfo) -> f64 {
        let mut score = Self::score_pqc_status(&info.pqc_status);

        if !info.tls_version.contains("1.3") {
            score -= 10.0;
        }

        score.clamp(0.0, 100.0)
    }

    /// Build a posture summary from scan results and provider info
    pub fn summarize(
        results: &[ScanResult],
        providers: &[ProviderCryptoInfo],
    ) -> PostureSummary {
        let mut by_status: HashMap<String, u32> = HashMap::new();
        let mut tls_scores: Vec<f64> = Vec::new();
        let mut cert_scores: Vec<f64> = Vec::new();
        let mut dep_scores: Vec<f64> = Vec::new();
        let mut key_scores: Vec<f64> = Vec::new();

        let mut total_assets = 0u32;

        for result in results {
            for finding in &result.findings {
                total_assets += 1;
                let status_key = finding.pqc_status.to_string();
                *by_status.entry(status_key).or_insert(0) += 1;

                let score = Self::score_finding(finding);

                match finding.asset.asset_type {
                    CryptoAssetType::TlsConnection | CryptoAssetType::ProtocolEndpoint => {
                        tls_scores.push(score);
                    }
                    CryptoAssetType::Certificate => {
                        cert_scores.push(score);
                    }
                    CryptoAssetType::CryptoLibrary => {
                        dep_scores.push(score);
                    }
                    CryptoAssetType::SigningKey
                    | CryptoAssetType::EncryptionKey
                    | CryptoAssetType::HashFunction => {
                        key_scores.push(score);
                    }
                }
            }
        }

        // Add provider scores to TLS category
        let mut provider_scores_list = Vec::new();
        for provider in providers {
            let score = Self::score_service(provider);
            tls_scores.push(score);
            total_assets += 1;
            let status_key = provider.pqc_status.to_string();
            *by_status.entry(status_key).or_insert(0) += 1;

            provider_scores_list.push(ProviderScore {
                provider: provider.provider_name.clone(),
                score,
                tls_version: Some(provider.tls_version.clone()),
                pqc_status: provider.pqc_status.clone(),
            });
        }

        let avg = |scores: &[f64]| -> f64 {
            if scores.is_empty() {
                100.0
            } else {
                scores.iter().sum::<f64>() / scores.len() as f64
            }
        };

        let tls_avg = avg(&tls_scores);
        let cert_avg = avg(&cert_scores);
        let dep_avg = avg(&dep_scores);
        let key_avg = avg(&key_scores);

        // Weighted overall: TLS 30%, Certs 25%, Deps 25%, Keys 20%
        let overall = tls_avg * 0.30 + cert_avg * 0.25 + dep_avg * 0.25 + key_avg * 0.20;

        let by_category = vec![
            CategoryScore {
                category: "TLS & Protocols".to_string(),
                score: tls_avg,
                asset_count: tls_scores.len() as u32,
            },
            CategoryScore {
                category: "Certificates".to_string(),
                score: cert_avg,
                asset_count: cert_scores.len() as u32,
            },
            CategoryScore {
                category: "Dependencies".to_string(),
                score: dep_avg,
                asset_count: dep_scores.len() as u32,
            },
            CategoryScore {
                category: "Keys & Code".to_string(),
                score: key_avg,
                asset_count: key_scores.len() as u32,
            },
        ];

        PostureSummary {
            overall_score: (overall * 10.0).round() / 10.0,
            total_assets,
            by_status,
            by_category,
            by_provider: provider_scores_list,
            calculated_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use qw_scanner::{
        AssetLocation, CryptoAsset, CryptoAssetType, Finding, FindingCategory, FindingSeverity,
        PqcStatus, ScanResult, ScanStatus,
    };
    use std::collections::HashMap;

    #[test]
    fn test_score_pqc_status_returns_correct_values() {
        assert_eq!(PostureEngine::score_pqc_status(&PqcStatus::PqcReady), 100.0);
        assert_eq!(PostureEngine::score_pqc_status(&PqcStatus::Hybrid), 90.0);
        assert_eq!(
            PostureEngine::score_pqc_status(&PqcStatus::ClassicalSecure),
            60.0
        );
        assert_eq!(
            PostureEngine::score_pqc_status(&PqcStatus::ClassicalWeak),
            20.0
        );
        assert_eq!(PostureEngine::score_pqc_status(&PqcStatus::Unknown), 40.0);
    }

    #[test]
    fn test_scoring_weights_sum_to_one() {
        // TLS 30% + Certs 25% + Deps 25% + Keys 20% = 100%
        let weights: f64 = 0.30 + 0.25 + 0.25 + 0.20;
        assert!((weights - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_empty_scan_results_produce_100_overall() {
        let summary = PostureEngine::summarize(&[], &[]);
        assert_eq!(summary.overall_score, 100.0);
        assert_eq!(summary.total_assets, 0);
    }

    #[test]
    fn test_classical_weak_finding_lowers_score() {
        let now = Utc::now();
        let finding = Finding {
            id: "f1".to_string(),
            category: FindingCategory::WeakAlgorithm,
            severity: FindingSeverity::High,
            title: "Weak RSA".to_string(),
            description: "RSA-1024 is weak".to_string(),
            asset: CryptoAsset {
                id: "a1".to_string(),
                asset_type: CryptoAssetType::SigningKey,
                name: "RSA-1024".to_string(),
                algorithm: Some("RSA".to_string()),
                key_length: Some(1024),
                protocol_version: None,
                location: AssetLocation {
                    source_type: "code".to_string(),
                    path: "src/main.rs".to_string(),
                    line: Some(42),
                },
                discovered_by: "dep-scanner".to_string(),
                discovered_at: now,
            },
            remediation: Some("Upgrade to RSA-2048+".to_string()),
            pqc_status: PqcStatus::ClassicalWeak,
            metadata: HashMap::new(),
        };

        let scan_result = ScanResult {
            scanner_id: "test-scanner".to_string(),
            target_id: "test-project".to_string(),
            started_at: now,
            completed_at: now,
            findings: vec![finding],
            status: ScanStatus::Completed,
            error: None,
        };

        let summary = PostureEngine::summarize(&[scan_result], &[]);
        // ClassicalWeak (20) - WeakAlgorithm (15) = 5, placed in Keys category
        // TLS: 100 (empty), Certs: 100 (empty), Deps: 100 (empty), Keys: 5
        // Overall = 100*0.30 + 100*0.25 + 100*0.25 + 5*0.20 = 30 + 25 + 25 + 1 = 81.0
        assert!(summary.overall_score < 100.0);
        assert_eq!(summary.total_assets, 1);
        // The Keys category should have a low score
        let keys_cat = summary
            .by_category
            .iter()
            .find(|c| c.category == "Keys & Code")
            .unwrap();
        assert_eq!(keys_cat.score, 5.0);
        assert_eq!(keys_cat.asset_count, 1);
    }
}
