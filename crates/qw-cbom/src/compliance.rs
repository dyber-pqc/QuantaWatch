//! Compliance & migration intelligence.
//!
//! Maps cryptographic findings to post-quantum compliance frameworks
//! (CNSA 2.0, NIST IR 8547, FIPS 203/204) with migration deadlines, then
//! produces a prioritized migration roadmap. This is the "so what do I do, and
//! by when" layer on top of the raw posture.

use chrono::{DateTime, Utc};
use qw_scanner::{CryptoAssetType, FindingCategory, FindingRecord, FindingSeverity, PqcStatus};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    AtRisk,
    NonCompliant,
    NotApplicable,
}

/// How a finding's crypto behaves with respect to a quantum adversary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoClass {
    /// Post-quantum or hybrid — safe.
    Pqc,
    /// Classical asymmetric (RSA/ECDSA/ECDH/TLS-KEX) — broken by Shor's algorithm.
    QuantumVulnerable,
    /// Already weak or broken today (MD5/SHA-1/DES/RC4, short keys, expired certs).
    Weak,
    /// Certificate nearing expiry — operational risk, not crypto-strength.
    ExpiringCert,
    /// Symmetric/hash at adequate strength — quantum-resistant enough.
    SafeSymmetric,
    /// Uncharacterized.
    Unknown,
}

fn classify(f: &FindingRecord) -> CryptoClass {
    match f.category {
        FindingCategory::ExpiredCertificate => return CryptoClass::Weak,
        FindingCategory::ExpiringCertificate => return CryptoClass::ExpiringCert,
        _ => {}
    }
    match f.pqc_status {
        PqcStatus::PqcReady | PqcStatus::Hybrid => CryptoClass::Pqc,
        PqcStatus::ClassicalWeak => CryptoClass::Weak,
        PqcStatus::ClassicalSecure => match f.asset_type {
            CryptoAssetType::HashFunction => CryptoClass::SafeSymmetric,
            _ => CryptoClass::QuantumVulnerable,
        },
        PqcStatus::Unknown => CryptoClass::Unknown,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameworkSummary {
    pub id: String,
    pub name: String,
    pub authority: String,
    pub description: String,
    pub compliant: u32,
    pub at_risk: u32,
    pub non_compliant: u32,
    pub compliance_pct: f64,
    /// Soonest migration deadline that applies to a non-compliant/at-risk asset.
    pub nearest_deadline: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationItem {
    pub id: String,
    pub title: String,
    /// "P0" | "P1" | "P2"
    pub priority: String,
    pub current_state: String,
    pub target_state: String,
    pub deadline_year: u32,
    pub affected_count: u32,
    pub severity: String,
    pub frameworks: Vec<String>,
    pub recommendation: String,
    pub finding_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReport {
    pub overall_compliance_pct: f64,
    pub total_findings: u32,
    pub compliant: u32,
    pub at_risk: u32,
    pub non_compliant: u32,
    pub frameworks: Vec<FrameworkSummary>,
    pub migration_items: Vec<MigrationItem>,
    pub generated_at: DateTime<Utc>,
}

struct FrameworkDef {
    id: &'static str,
    name: &'static str,
    authority: &'static str,
    description: &'static str,
}

const FRAMEWORKS: &[FrameworkDef] = &[
    FrameworkDef {
        id: "cnsa-2.0",
        name: "CNSA 2.0",
        authority: "NSA",
        description: "Commercial National Security Algorithm Suite 2.0 — mandates post-quantum key establishment (ML-KEM) and signatures (ML-DSA).",
    },
    FrameworkDef {
        id: "nist-ir-8547",
        name: "NIST IR 8547",
        authority: "NIST",
        description: "Transition to post-quantum standards — classical asymmetric crypto deprecated after 2030, disallowed after 2035.",
    },
    FrameworkDef {
        id: "fips-203-204",
        name: "FIPS 203 / 204",
        authority: "NIST",
        description: "Standardized post-quantum algorithms (ML-KEM, ML-DSA). Adoption demonstrates conformance to approved PQC.",
    },
];

/// Per (class, framework) → (status, deadline year applicable).
fn status_for(class: CryptoClass, framework_id: &str) -> (ComplianceStatus, Option<u32>) {
    use ComplianceStatus::*;
    match framework_id {
        "cnsa-2.0" => match class {
            CryptoClass::Pqc | CryptoClass::SafeSymmetric => (Compliant, None),
            CryptoClass::QuantumVulnerable => (NonCompliant, Some(2030)),
            CryptoClass::Weak => (NonCompliant, Some(2025)),
            CryptoClass::ExpiringCert => (AtRisk, Some(2025)),
            CryptoClass::Unknown => (AtRisk, Some(2030)),
        },
        "nist-ir-8547" => match class {
            CryptoClass::Pqc | CryptoClass::SafeSymmetric => (Compliant, None),
            CryptoClass::QuantumVulnerable => (AtRisk, Some(2030)),
            CryptoClass::Weak => (NonCompliant, Some(2025)),
            CryptoClass::ExpiringCert => (AtRisk, Some(2025)),
            CryptoClass::Unknown => (AtRisk, Some(2035)),
        },
        "fips-203-204" => match class {
            CryptoClass::Pqc => (Compliant, None),
            CryptoClass::SafeSymmetric => (Compliant, None),
            CryptoClass::QuantumVulnerable => (NonCompliant, Some(2030)),
            CryptoClass::Weak => (NonCompliant, Some(2025)),
            CryptoClass::ExpiringCert => (NotApplicable, None),
            CryptoClass::Unknown => (AtRisk, Some(2030)),
        },
        _ => (NotApplicable, None),
    }
}

fn severity_label(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

pub struct ComplianceEngine;

impl ComplianceEngine {
    pub fn assess(findings: &[FindingRecord]) -> ComplianceReport {
        // Per-framework tallies.
        let mut frameworks: Vec<FrameworkSummary> = Vec::new();
        for fw in FRAMEWORKS {
            let (mut compliant, mut at_risk, mut non_compliant) = (0u32, 0u32, 0u32);
            let mut nearest: Option<u32> = None;
            for f in findings {
                let class = classify(f);
                let (status, deadline) = status_for(class, fw.id);
                match status {
                    ComplianceStatus::Compliant => compliant += 1,
                    ComplianceStatus::AtRisk => at_risk += 1,
                    ComplianceStatus::NonCompliant => non_compliant += 1,
                    ComplianceStatus::NotApplicable => {}
                }
                if matches!(
                    status,
                    ComplianceStatus::AtRisk | ComplianceStatus::NonCompliant
                ) {
                    if let Some(y) = deadline {
                        nearest = Some(nearest.map_or(y, |n| n.min(y)));
                    }
                }
            }
            let applicable = compliant + at_risk + non_compliant;
            let pct = if applicable == 0 {
                100.0
            } else {
                (compliant as f64 / applicable as f64 * 1000.0).round() / 10.0
            };
            frameworks.push(FrameworkSummary {
                id: fw.id.to_string(),
                name: fw.name.to_string(),
                authority: fw.authority.to_string(),
                description: fw.description.to_string(),
                compliant,
                at_risk,
                non_compliant,
                compliance_pct: pct,
                nearest_deadline: nearest,
            });
        }

        // Headline numbers use CNSA 2.0 (the strictest mandate).
        let headline = frameworks
            .iter()
            .find(|f| f.id == "cnsa-2.0")
            .cloned()
            .unwrap_or_else(|| frameworks[0].clone());

        let migration_items = Self::build_roadmap(findings);

        ComplianceReport {
            overall_compliance_pct: headline.compliance_pct,
            total_findings: findings.len() as u32,
            compliant: headline.compliant,
            at_risk: headline.at_risk,
            non_compliant: headline.non_compliant,
            frameworks,
            migration_items,
            generated_at: Utc::now(),
        }
    }

    fn build_roadmap(findings: &[FindingRecord]) -> Vec<MigrationItem> {
        // Bucket key -> (matching predicate result accumulation)
        struct Bucket {
            id: &'static str,
            title: &'static str,
            priority: &'static str,
            current: &'static str,
            target: &'static str,
            deadline: u32,
            frameworks: &'static [&'static str],
            recommendation: &'static str,
            refs: Vec<String>,
            max_sev: FindingSeverity,
        }
        let new_bucket = |id, title, priority, current, target, deadline, frameworks, rec| Bucket {
            id,
            title,
            priority,
            current,
            target,
            deadline,
            frameworks,
            recommendation: rec,
            refs: Vec::new(),
            max_sev: FindingSeverity::Info,
        };

        let mut weak = new_bucket(
            "remediate-weak",
            "Remove weak or broken algorithms",
            "P0",
            "MD5/SHA-1/DES/RC4, short RSA keys, or expired certificates in use",
            "Eliminate deprecated primitives; rotate to AES-256 / SHA-384+ and valid certificates",
            2025,
            &["CNSA 2.0", "NIST IR 8547", "FIPS 203 / 204"],
            "Immediate: these are exploitable today, independent of quantum risk.",
        );
        let mut certs = new_bucket(
            "renew-certs",
            "Renew expiring certificates",
            "P1",
            "Certificates approaching expiry",
            "Renew and automate certificate lifecycle (consider ML-DSA-signed certs)",
            2025,
            &["CNSA 2.0", "NIST IR 8547"],
            "Renew before expiry to avoid outages; plan PQC-signed re-issuance.",
        );
        let mut tls = new_bucket(
            "tls-pqc",
            "Enable post-quantum key exchange on TLS endpoints",
            "P1",
            "TLS endpoints negotiate classical (RSA/ECDHE) key exchange",
            "Hybrid key establishment (X25519 + ML-KEM-768), TLS 1.3 only",
            2030,
            &["CNSA 2.0", "NIST IR 8547"],
            "Deploy hybrid KEM at gateways and upstream connections ahead of the 2030 mandate.",
        );
        let mut sigs = new_bucket(
            "signatures-pqc",
            "Migrate certificates & signatures to ML-DSA",
            "P1",
            "Certificates and signing keys use classical (RSA/ECDSA) signatures",
            "ML-DSA (FIPS 204) signatures; hybrid certificates during transition",
            2030,
            &["CNSA 2.0", "FIPS 203 / 204"],
            "Inventory signing surfaces and pilot ML-DSA issuance.",
        );
        let mut deps = new_bucket(
            "dependencies-pqc",
            "Adopt PQC-capable cryptography libraries",
            "P2",
            "Application dependencies provide classical crypto only",
            "Upgrade to libraries exposing ML-KEM / ML-DSA (e.g. ml-kem, ml-dsa, liboqs)",
            2030,
            &["CNSA 2.0"],
            "Track upstream PQC support and stage dependency upgrades.",
        );
        let mut unknown = new_bucket(
            "assess-unknown",
            "Assess uncharacterized cryptographic assets",
            "P2",
            "Assets whose algorithms could not be determined",
            "Identify algorithms and classify quantum exposure",
            2030,
            &["CNSA 2.0", "NIST IR 8547"],
            "Manual review to remove blind spots from the inventory.",
        );

        let bump = |b: &mut Bucket, f: &FindingRecord| {
            if b.refs.len() < 50 {
                b.refs.push(f.id.clone());
            }
            if f.severity > b.max_sev {
                b.max_sev = f.severity.clone();
            }
        };

        for f in findings {
            match classify(f) {
                CryptoClass::Weak => bump(&mut weak, f),
                CryptoClass::ExpiringCert => bump(&mut certs, f),
                CryptoClass::QuantumVulnerable => match f.asset_type {
                    CryptoAssetType::TlsConnection | CryptoAssetType::ProtocolEndpoint => {
                        bump(&mut tls, f)
                    }
                    CryptoAssetType::Certificate
                    | CryptoAssetType::SigningKey
                    | CryptoAssetType::EncryptionKey => bump(&mut sigs, f),
                    CryptoAssetType::CryptoLibrary => bump(&mut deps, f),
                    CryptoAssetType::HashFunction => {}
                },
                CryptoClass::Unknown => bump(&mut unknown, f),
                CryptoClass::Pqc | CryptoClass::SafeSymmetric => {}
            }
        }

        let mut items: Vec<MigrationItem> = [weak, certs, tls, sigs, deps, unknown]
            .into_iter()
            .filter(|b| !b.refs.is_empty())
            .map(|b| MigrationItem {
                id: b.id.to_string(),
                title: b.title.to_string(),
                priority: b.priority.to_string(),
                current_state: b.current.to_string(),
                target_state: b.target.to_string(),
                deadline_year: b.deadline,
                affected_count: b.refs.len() as u32,
                severity: severity_label(b.max_sev).to_string(),
                frameworks: b.frameworks.iter().map(|s| s.to_string()).collect(),
                recommendation: b.recommendation.to_string(),
                finding_refs: b.refs,
            })
            .collect();

        // P0 first, then by blast radius.
        items.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then(b.affected_count.cmp(&a.affected_count))
        });
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn rec(
        category: FindingCategory,
        asset_type: CryptoAssetType,
        pqc: PqcStatus,
        sev: FindingSeverity,
    ) -> FindingRecord {
        FindingRecord {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: "s".into(),
            category,
            severity: sev,
            title: "t".into(),
            description: "d".into(),
            asset_type,
            algorithm: None,
            pqc_status: pqc,
            location: "loc".into(),
            remediation: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn pqc_findings_are_fully_compliant() {
        let findings = vec![rec(
            FindingCategory::PqcReady,
            CryptoAssetType::CryptoLibrary,
            PqcStatus::PqcReady,
            FindingSeverity::Info,
        )];
        let report = ComplianceEngine::assess(&findings);
        assert_eq!(report.overall_compliance_pct, 100.0);
        assert_eq!(report.non_compliant, 0);
        assert!(report.migration_items.is_empty());
    }

    #[test]
    fn classical_tls_is_noncompliant_with_2030_roadmap() {
        let findings = vec![rec(
            FindingCategory::ClassicalCrypto,
            CryptoAssetType::TlsConnection,
            PqcStatus::ClassicalSecure,
            FindingSeverity::Info,
        )];
        let report = ComplianceEngine::assess(&findings);
        // CNSA 2.0 treats classical asymmetric as non-compliant.
        assert_eq!(report.non_compliant, 1);
        assert_eq!(report.overall_compliance_pct, 0.0);
        let tls = report
            .migration_items
            .iter()
            .find(|m| m.id == "tls-pqc")
            .unwrap();
        assert_eq!(tls.deadline_year, 2030);
        assert_eq!(tls.priority, "P1");
        // NIST IR 8547 marks the same asset at-risk (deprecated, not yet disallowed).
        let nist = report
            .frameworks
            .iter()
            .find(|f| f.id == "nist-ir-8547")
            .unwrap();
        assert_eq!(nist.at_risk, 1);
        assert_eq!(nist.non_compliant, 0);
    }

    #[test]
    fn weak_algorithms_are_p0() {
        let findings = vec![rec(
            FindingCategory::WeakAlgorithm,
            CryptoAssetType::HashFunction,
            PqcStatus::ClassicalWeak,
            FindingSeverity::High,
        )];
        let report = ComplianceEngine::assess(&findings);
        let weak = report
            .migration_items
            .iter()
            .find(|m| m.id == "remediate-weak")
            .unwrap();
        assert_eq!(weak.priority, "P0");
    }
}
