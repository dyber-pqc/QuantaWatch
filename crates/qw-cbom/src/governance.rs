//! Crypto-agility governance.
//!
//! Discovery tells you what crypto you *have*; governance tells you whether
//! that inventory matches the target state you've *committed to* — and whether
//! you're converging on it or drifting away. It closes the loop:
//!
//!   declare a policy  ->  measure the inventory against it  ->  gate CI on it
//!   ->  track the agility score over time.
//!
//! A [`CryptoPolicy`] declares which algorithms are outright **forbidden**,
//! which are **deprecated** (allowed today but must be migrated before a
//! deadline), and the **target** post-quantum set. [`evaluate`] scores the
//! inventory against it and returns a PASS / AT-RISK / FAIL verdict plus a
//! single crypto-agility score.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use qw_scanner::{FindingRecord, PqcStatus};

/// The target-state crypto policy the organization is governing toward.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoPolicy {
    #[serde(default)]
    pub name: String,
    /// Never acceptable (e.g. 3DES, RC4, MD5, SHA1, RSA-1024). Any occurrence
    /// is a violation.
    #[serde(default)]
    pub forbidden: Vec<String>,
    /// Allowed today but quantum-vulnerable — must be migrated before `deadline`
    /// (e.g. RSA, ECDSA, ECDH, DH).
    #[serde(default)]
    pub deprecated: Vec<String>,
    /// The post-quantum target set (e.g. ML-DSA, ML-KEM). Informational.
    #[serde(default)]
    pub target: Vec<String>,
    /// When deprecated algorithms must be gone (e.g. CNSA 2.0's 2030).
    #[serde(default)]
    pub deadline: Option<DateTime<Utc>>,
}

/// Where a single asset stands against the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetVerdict {
    /// PQC-ready/hybrid, or classical-but-acceptable (not deprecated/forbidden).
    Compliant,
    /// Quantum-vulnerable or weak — allowed for now, must migrate.
    Deprecated,
    /// Explicitly banned.
    Forbidden,
    /// Could not be classified against the policy.
    Unknown,
}

/// Overall governance verdict for the inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// No forbidden and no deprecated assets remain.
    Pass,
    /// Migration is incomplete (deprecated assets remain, deadline not yet passed).
    AtRisk,
    /// A forbidden algorithm is in use, or the deadline passed with deprecated
    /// assets still present. This is what a CI gate should block on.
    Fail,
}

/// The governance report over an inventory at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceReport {
    pub policy_name: String,
    pub total: u32,
    pub compliant: u32,
    pub deprecated: u32,
    pub forbidden: u32,
    pub unknown: u32,
    /// Percent of assets that are compliant (0-100).
    pub agility_score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_to_deadline: Option<i64>,
    pub deadline_passed: bool,
    pub verdict: Verdict,
}

fn matches_any(patterns: &[String], algo_upper: &str) -> bool {
    patterns
        .iter()
        .any(|p| algo_upper.contains(&p.to_uppercase()))
}

/// Classify one asset (by algorithm + PQC status) against the policy.
pub fn classify_asset(policy: &CryptoPolicy, algorithm: &str, pqc: &PqcStatus) -> AssetVerdict {
    let a = algorithm.to_uppercase();
    // An explicit ban wins over everything, even a PQC status.
    if matches_any(&policy.forbidden, &a) {
        return AssetVerdict::Forbidden;
    }
    if matches!(pqc, PqcStatus::PqcReady | PqcStatus::Hybrid) {
        return AssetVerdict::Compliant;
    }
    if matches_any(&policy.deprecated, &a) {
        return AssetVerdict::Deprecated;
    }
    match pqc {
        // Weak-but-not-explicitly-forbidden still has to move.
        PqcStatus::ClassicalWeak => AssetVerdict::Deprecated,
        // Classical-secure and not on the deprecated list (e.g. AES-256).
        PqcStatus::ClassicalSecure => AssetVerdict::Compliant,
        PqcStatus::Unknown => AssetVerdict::Unknown,
        _ => AssetVerdict::Compliant,
    }
}

/// Evaluate the inventory against the policy at time `now`.
pub fn evaluate(
    policy: &CryptoPolicy,
    findings: &[FindingRecord],
    now: DateTime<Utc>,
) -> GovernanceReport {
    let (mut compliant, mut deprecated, mut forbidden, mut unknown) = (0u32, 0u32, 0u32, 0u32);
    for f in findings {
        let algo = f.algorithm.as_deref().unwrap_or("");
        match classify_asset(policy, algo, &f.pqc_status) {
            AssetVerdict::Compliant => compliant += 1,
            AssetVerdict::Deprecated => deprecated += 1,
            AssetVerdict::Forbidden => forbidden += 1,
            AssetVerdict::Unknown => unknown += 1,
        }
    }
    let total = compliant + deprecated + forbidden + unknown;
    let agility_score = if total == 0 {
        100.0
    } else {
        (compliant as f64 / total as f64 * 1000.0).round() / 10.0
    };

    let days_to_deadline = policy.deadline.map(|d| (d - now).num_days());
    let deadline_passed = policy.deadline.map(|d| now > d).unwrap_or(false);

    let verdict = if forbidden > 0 || (deadline_passed && deprecated > 0) {
        Verdict::Fail
    } else if deprecated > 0 {
        Verdict::AtRisk
    } else {
        Verdict::Pass
    };

    GovernanceReport {
        policy_name: policy.name.clone(),
        total,
        compliant,
        deprecated,
        forbidden,
        unknown,
        agility_score,
        deadline: policy.deadline,
        days_to_deadline,
        deadline_passed,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use qw_scanner::{CryptoAssetType, FindingCategory, FindingSeverity};

    fn policy() -> CryptoPolicy {
        CryptoPolicy {
            name: "CNSA 2.0".into(),
            forbidden: vec!["3DES".into(), "RC4".into(), "MD5".into(), "SHA1".into()],
            deprecated: vec!["RSA".into(), "ECDSA".into(), "ECDH".into()],
            target: vec!["ML-DSA".into(), "ML-KEM".into()],
            deadline: Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        }
    }

    fn finding(algo: &str, pqc: PqcStatus) -> FindingRecord {
        FindingRecord {
            id: "f".into(),
            scan_id: "s".into(),
            category: FindingCategory::ClassicalCrypto,
            severity: FindingSeverity::Medium,
            title: "t".into(),
            description: "d".into(),
            asset_type: CryptoAssetType::Certificate,
            algorithm: Some(algo.into()),
            pqc_status: pqc,
            location: "x".into(),
            remediation: None,
            created_at: Utc::now(),
            confidence: Default::default(),
            evidence: Vec::new(),
            status: Default::default(),
            note: None,
        }
    }

    #[test]
    fn classification_covers_each_verdict() {
        let p = policy();
        assert_eq!(
            classify_asset(&p, "3DES", &PqcStatus::ClassicalWeak),
            AssetVerdict::Forbidden
        );
        assert_eq!(
            classify_asset(&p, "ECDSA-SHA256", &PqcStatus::ClassicalSecure),
            AssetVerdict::Deprecated
        );
        assert_eq!(
            classify_asset(&p, "ML-DSA-65", &PqcStatus::PqcReady),
            AssetVerdict::Compliant
        );
        // AES-256 is classical but not deprecated -> compliant.
        assert_eq!(
            classify_asset(&p, "AES-256-GCM", &PqcStatus::ClassicalSecure),
            AssetVerdict::Compliant
        );
        assert_eq!(
            classify_asset(&p, "", &PqcStatus::Unknown),
            AssetVerdict::Unknown
        );
    }

    #[test]
    fn forbidden_beats_pqc_status() {
        // Even if somehow marked PqcReady, an explicitly-forbidden algo is a violation.
        let p = policy();
        assert_eq!(
            classify_asset(&p, "RC4", &PqcStatus::PqcReady),
            AssetVerdict::Forbidden
        );
    }

    #[test]
    fn all_pqc_passes() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let r = evaluate(&policy(), &[finding("ML-DSA-65", PqcStatus::PqcReady)], now);
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.agility_score, 100.0);
    }

    #[test]
    fn deprecated_before_deadline_is_at_risk() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let r = evaluate(
            &policy(),
            &[
                finding("ML-DSA-65", PqcStatus::PqcReady),
                finding("ECDSA-SHA256", PqcStatus::ClassicalSecure),
            ],
            now,
        );
        assert_eq!(r.verdict, Verdict::AtRisk);
        assert_eq!(r.deprecated, 1);
        assert_eq!(r.agility_score, 50.0);
        assert!(r.days_to_deadline.unwrap() > 0 && !r.deadline_passed);
    }

    #[test]
    fn forbidden_fails_the_gate() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let r = evaluate(&policy(), &[finding("3DES", PqcStatus::ClassicalWeak)], now);
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.forbidden, 1);
    }

    #[test]
    fn deprecated_after_deadline_fails() {
        // Same deprecated finding, but now it's past the 2030 deadline.
        let now = Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap();
        let r = evaluate(
            &policy(),
            &[finding("RSA-2048", PqcStatus::ClassicalSecure)],
            now,
        );
        assert!(r.deadline_passed);
        assert_eq!(
            r.verdict,
            Verdict::Fail,
            "missed-deadline deprecated crypto must fail the gate"
        );
    }

    #[test]
    fn empty_inventory_is_a_clean_pass() {
        let now = Utc::now();
        let r = evaluate(&policy(), &[], now);
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.agility_score, 100.0);
        assert_eq!(r.total, 0);
    }
}
