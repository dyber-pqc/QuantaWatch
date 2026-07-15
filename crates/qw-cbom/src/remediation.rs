//! Closed-loop remediation: turn a finding into a concrete post-quantum
//! **migration plan** — the specific algorithm to move to, why, at what
//! priority, and a proposed patch — instead of just filing a ticket that says
//! "you have RSA". This is the "fix, not just report" differentiator: the plan
//! (and its patch) becomes the body of the remediation ticket / pull request.

use serde::{Deserialize, Serialize};

use qw_scanner::{CryptoAssetType, FindingRecord, FindingSeverity, PqcStatus};

/// The kind of change a plan proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationStrategy {
    /// Classical signature scheme -> ML-DSA-65 (FIPS 204).
    ReplaceSignature,
    /// Classical key exchange -> hybrid X25519 + ML-KEM-768 (FIPS 203).
    HybridKeyExchange,
    /// Weak symmetric cipher -> AES-256-GCM.
    ReplaceSymmetric,
    /// Weak hash -> SHA-384 / SHA3-256.
    ReplaceHash,
    /// Secret material exposed in code -> rotate + move to a KMS/HSM.
    RotateKey,
    /// Crypto library is quantum-vulnerable -> upgrade to a PQC-capable one.
    UpgradeLibrary,
}

/// How urgent the migration is, mapped from exposure + CNSA 2.0 timelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationPriority {
    /// Do now: actively weak, or a live secret exposure.
    P0,
    /// Harvest-now-decrypt-later exposed; migrate before the CNSA 2.0 deadlines.
    P1,
    /// Advisory / hardening.
    P2,
}

impl MigrationPriority {
    pub fn label(&self) -> &'static str {
        match self {
            Self::P0 => "P0 — immediate",
            Self::P1 => "P1 — before 2030 (CNSA 2.0)",
            Self::P2 => "P2 — advisory",
        }
    }
}

/// A proposed change to a specific file. Best-effort (a human reviews the PR),
/// so this is a before/after proposal rather than a guaranteed-applyable diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationPatch {
    pub path: String,
    /// "dependency" | "tls-config" | "code" | "certificate".
    pub kind: String,
    pub before: String,
    pub after: String,
    pub note: String,
}

/// A concrete migration proposal for one finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationPlan {
    pub finding_id: String,
    pub title: String,
    pub current_algorithm: String,
    pub target_algorithm: String,
    pub strategy: MigrationStrategy,
    pub priority: MigrationPriority,
    pub rationale: String,
    pub steps: Vec<String>,
    pub effort: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<MigrationPatch>,
}

/// True if this finding warrants a migration (not already PQC / advisory-only).
fn needs_migration(f: &FindingRecord) -> bool {
    !matches!(f.pqc_status, PqcStatus::PqcReady | PqcStatus::Hybrid)
}

fn algo_upper(f: &FindingRecord) -> String {
    f.algorithm.clone().unwrap_or_default().to_uppercase()
}

/// Classify a finding into a migration strategy + target algorithm.
fn classify(f: &FindingRecord) -> (MigrationStrategy, &'static str) {
    let a = algo_upper(f);
    // Weak symmetric / hash first (independent of asset type).
    if a.contains("3DES")
        || a.contains("DES")
        || a.contains("RC4")
        || a.contains("AES-128")
        || a.contains("AES_128")
    {
        return (MigrationStrategy::ReplaceSymmetric, "AES-256-GCM");
    }
    if a.contains("MD5") || a.contains("SHA1") || a.contains("SHA-1") {
        return (MigrationStrategy::ReplaceHash, "SHA-384");
    }
    // Hardcoded secret material -> rotate, regardless of algorithm.
    if matches!(f.category.to_string().as_str(), "hardcoded_key") {
        return (MigrationStrategy::RotateKey, "rotated key in KMS/HSM");
    }
    // Asymmetric quantum-vulnerable: pick signature vs key-exchange by role.
    match f.asset_type {
        CryptoAssetType::Certificate | CryptoAssetType::SigningKey => {
            (MigrationStrategy::ReplaceSignature, "ML-DSA-65")
        }
        CryptoAssetType::TlsConnection | CryptoAssetType::ProtocolEndpoint => (
            MigrationStrategy::HybridKeyExchange,
            "X25519 + ML-KEM-768 (hybrid)",
        ),
        CryptoAssetType::CryptoLibrary => {
            (MigrationStrategy::UpgradeLibrary, "PQC-capable library")
        }
        CryptoAssetType::HashFunction => (MigrationStrategy::ReplaceHash, "SHA-384"),
        CryptoAssetType::EncryptionKey => (
            MigrationStrategy::HybridKeyExchange,
            "X25519 + ML-KEM-768 (hybrid)",
        ),
    }
}

fn priority_of(f: &FindingRecord, strategy: MigrationStrategy) -> MigrationPriority {
    // Actively weak or a live secret exposure -> do it now.
    if matches!(f.pqc_status, PqcStatus::ClassicalWeak)
        || matches!(f.severity, FindingSeverity::Critical)
        || strategy == MigrationStrategy::RotateKey
        || strategy == MigrationStrategy::ReplaceSymmetric
        || strategy == MigrationStrategy::ReplaceHash
    {
        return MigrationPriority::P0;
    }
    // Quantum-vulnerable asymmetric: HNDL-exposed, migrate before the deadlines.
    if matches!(
        strategy,
        MigrationStrategy::ReplaceSignature
            | MigrationStrategy::HybridKeyExchange
            | MigrationStrategy::UpgradeLibrary
    ) {
        return MigrationPriority::P1;
    }
    MigrationPriority::P2
}

fn effort_of(strategy: MigrationStrategy) -> &'static str {
    match strategy {
        MigrationStrategy::ReplaceHash | MigrationStrategy::ReplaceSymmetric => "low",
        MigrationStrategy::RotateKey | MigrationStrategy::UpgradeLibrary => "medium",
        MigrationStrategy::ReplaceSignature | MigrationStrategy::HybridKeyExchange => "high",
    }
}

/// Generate a best-effort proposed patch for a finding, when its location is
/// something we can name a concrete change for.
fn build_patch(f: &FindingRecord, target: &str) -> Option<MigrationPatch> {
    let loc = &f.location;
    let a = f.algorithm.clone().unwrap_or_else(|| "classical".into());
    let is_dep = loc.ends_with("Cargo.toml")
        || loc.ends_with("package.json")
        || loc.ends_with("requirements.txt")
        || loc.ends_with("go.mod")
        || loc.ends_with("pom.xml");
    match f.asset_type {
        CryptoAssetType::CryptoLibrary if is_dep => Some(MigrationPatch {
            path: loc.clone(),
            kind: "dependency".into(),
            before: format!("# quantum-vulnerable crypto dependency ({a})"),
            after: "# add a PQC-capable provider, e.g. ml-dsa / ml-kem (RustCrypto),\n\
                    # liboqs bindings, or your platform's hybrid TLS stack"
                .into(),
            note: format!("Move signing/KEM usage from {a} to {target}."),
        }),
        CryptoAssetType::TlsConnection | CryptoAssetType::ProtocolEndpoint => {
            Some(MigrationPatch {
                path: loc.clone(),
                kind: "tls-config".into(),
                before: "# TLS key-exchange groups: classical only (e.g. x25519, secp256r1)".into(),
                after: "# enable a hybrid PQC group first, e.g.:\n\
                    #   ssl_ecdh_curve X25519MLKEM768:X25519;   # nginx / OpenSSL 3.5+\n\
                    # or the equivalent for your terminator (Envoy, HAProxy, cloud LB)"
                    .into(),
                note: format!("Negotiate {target} so captured traffic is not HNDL-exposed."),
            })
        }
        CryptoAssetType::Certificate | CryptoAssetType::SigningKey => Some(MigrationPatch {
            path: loc.clone(),
            kind: "certificate".into(),
            before: format!("# leaf/intermediate signed with {a}"),
            after: format!("# reissue with {target}; run a hybrid chain during transition"),
            note: "Coordinate with your CA / PKI for ML-DSA (or composite) issuance.".into(),
        }),
        _ => None,
    }
}

/// Produce a migration plan for a single finding, or `None` if it is already
/// PQC-ready / hybrid.
pub fn plan_migration(f: &FindingRecord) -> Option<MigrationPlan> {
    if !needs_migration(f) {
        return None;
    }
    let (strategy, target) = classify(f);
    let priority = priority_of(f, strategy);
    let current = f
        .algorithm
        .clone()
        .unwrap_or_else(|| "classical/unknown".into());

    let rationale = match strategy {
        MigrationStrategy::ReplaceSignature | MigrationStrategy::HybridKeyExchange => format!(
            "{current} is quantum-vulnerable: an adversary can harvest traffic/artifacts now and \
             decrypt or forge them once a cryptographically-relevant quantum computer exists. \
             CNSA 2.0 requires PQC by 2030-2033."
        ),
        MigrationStrategy::ReplaceSymmetric | MigrationStrategy::ReplaceHash => {
            format!("{current} is cryptographically weak by today's standards, independent of quantum risk.")
        }
        MigrationStrategy::RotateKey => {
            "Secret material is exposed in source; it must be rotated and moved to managed storage.".into()
        }
        MigrationStrategy::UpgradeLibrary => format!(
            "The crypto library exposes only quantum-vulnerable primitives ({current}); adopt a PQC-capable provider."
        ),
    };

    let steps = match strategy {
        MigrationStrategy::HybridKeyExchange => vec![
            "Enable a hybrid PQC key-exchange group (X25519 + ML-KEM-768) on the terminator."
                .into(),
            "Roll out to a canary, confirm client compatibility, then make it the default.".into(),
            "Re-scan to confirm the endpoint negotiates the hybrid group.".into(),
        ],
        MigrationStrategy::ReplaceSignature => vec![
            "Provision an ML-DSA-65 (or composite) signing key via your PKI/KMS.".into(),
            "Issue a hybrid/composite certificate chain and deploy alongside the classical one."
                .into(),
            "Cut over verification to the PQC chain; retire the classical key.".into(),
        ],
        MigrationStrategy::UpgradeLibrary => vec![
            "Add a PQC-capable crypto dependency (ml-dsa / ml-kem, liboqs).".into(),
            "Replace signing/KEM call sites; keep classical as a hybrid fallback.".into(),
            "Add tests and re-scan the dependency manifest.".into(),
        ],
        MigrationStrategy::ReplaceSymmetric => vec![
            "Replace the weak cipher with AES-256-GCM (or ChaCha20-Poly1305).".into(),
            "Re-encrypt data at rest where applicable.".into(),
        ],
        MigrationStrategy::ReplaceHash => vec![
            "Replace the weak hash with SHA-384 or SHA3-256.".into(),
            "Re-sign / re-hash affected artifacts.".into(),
        ],
        MigrationStrategy::RotateKey => vec![
            "Revoke and rotate the exposed key immediately.".into(),
            "Move the secret to a KMS/HSM and load it at runtime.".into(),
            "Purge it from history and add a secret scanner to CI.".into(),
        ],
    };

    Some(MigrationPlan {
        finding_id: f.id.clone(),
        title: format!("Migrate {} → {}", current, target),
        current_algorithm: current,
        target_algorithm: target.to_string(),
        strategy,
        priority,
        rationale,
        steps,
        effort: effort_of(strategy).to_string(),
        patch: build_patch(f, target),
    })
}

/// Plan migrations for a set of findings, most-urgent first.
pub fn plan_all(findings: &[FindingRecord]) -> Vec<MigrationPlan> {
    let mut plans: Vec<MigrationPlan> = findings.iter().filter_map(plan_migration).collect();
    plans.sort_by(|a, b| a.priority.cmp(&b.priority));
    plans
}

/// Render a plan as Markdown for a remediation ticket / pull-request body.
pub fn plan_to_markdown(p: &MigrationPlan) -> String {
    let mut s = String::new();
    s.push_str(&format!("## Post-quantum migration: {}\n\n", p.title));
    s.push_str(&format!("**Priority:** {}\n\n", p.priority.label()));
    s.push_str(&format!("**Current:** {}\n", p.current_algorithm));
    s.push_str(&format!("**Target:** {}\n", p.target_algorithm));
    s.push_str(&format!("**Effort:** {}\n\n", p.effort));
    s.push_str(&format!("**Why:** {}\n\n", p.rationale));
    s.push_str("**Steps:**\n");
    for (i, step) in p.steps.iter().enumerate() {
        s.push_str(&format!("{}. {}\n", i + 1, step));
    }
    if let Some(patch) = &p.patch {
        s.push_str(&format!(
            "\n**Proposed change — `{}`** ({})\n\n",
            patch.path, patch.kind
        ));
        s.push_str("```diff\n");
        for line in patch.before.lines() {
            s.push_str(&format!("- {line}\n"));
        }
        for line in patch.after.lines() {
            s.push_str(&format!("+ {line}\n"));
        }
        s.push_str("```\n");
        s.push_str(&format!("\n_{}_\n", patch.note));
    }
    s.push_str("\n---\n_Drafted by QuantaWatch closed-loop remediation._\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use qw_scanner::FindingCategory;

    fn finding(
        algorithm: Option<&str>,
        asset_type: CryptoAssetType,
        pqc: PqcStatus,
        sev: FindingSeverity,
        cat: FindingCategory,
        location: &str,
    ) -> FindingRecord {
        FindingRecord {
            id: "f1".into(),
            scan_id: "s1".into(),
            category: cat,
            severity: sev,
            title: "t".into(),
            description: "d".into(),
            asset_type,
            algorithm: algorithm.map(String::from),
            pqc_status: pqc,
            location: location.into(),
            remediation: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn rsa_certificate_maps_to_ml_dsa_signature() {
        let f = finding(
            Some("RSA-2048"),
            CryptoAssetType::Certificate,
            PqcStatus::ClassicalSecure,
            FindingSeverity::High,
            FindingCategory::ClassicalCrypto,
            "certs/leaf.pem",
        );
        let p = plan_migration(&f).unwrap();
        assert_eq!(p.strategy, MigrationStrategy::ReplaceSignature);
        assert_eq!(p.target_algorithm, "ML-DSA-65");
        assert_eq!(p.priority, MigrationPriority::P1);
        assert!(p.patch.is_some());
    }

    #[test]
    fn tls_endpoint_maps_to_hybrid_kem() {
        let f = finding(
            Some("ECDHE"),
            CryptoAssetType::TlsConnection,
            PqcStatus::ClassicalSecure,
            FindingSeverity::Medium,
            FindingCategory::MissingPqc,
            "api.example.com:443",
        );
        let p = plan_migration(&f).unwrap();
        assert_eq!(p.strategy, MigrationStrategy::HybridKeyExchange);
        assert!(p.target_algorithm.contains("ML-KEM-768"));
        assert_eq!(p.patch.unwrap().kind, "tls-config");
    }

    #[test]
    fn weak_cipher_is_p0() {
        let f = finding(
            Some("3DES"),
            CryptoAssetType::EncryptionKey,
            PqcStatus::ClassicalWeak,
            FindingSeverity::High,
            FindingCategory::WeakAlgorithm,
            "app/config.yaml",
        );
        let p = plan_migration(&f).unwrap();
        assert_eq!(p.strategy, MigrationStrategy::ReplaceSymmetric);
        assert_eq!(p.target_algorithm, "AES-256-GCM");
        assert_eq!(p.priority, MigrationPriority::P0);
    }

    #[test]
    fn hardcoded_key_is_rotate_p0() {
        let f = finding(
            None,
            CryptoAssetType::SigningKey,
            PqcStatus::Unknown,
            FindingSeverity::Critical,
            FindingCategory::HardcodedKey,
            "src/secrets.rs",
        );
        let p = plan_migration(&f).unwrap();
        assert_eq!(p.strategy, MigrationStrategy::RotateKey);
        assert_eq!(p.priority, MigrationPriority::P0);
    }

    #[test]
    fn pqc_ready_finding_has_no_plan() {
        let f = finding(
            Some("ML-DSA-65"),
            CryptoAssetType::SigningKey,
            PqcStatus::PqcReady,
            FindingSeverity::Info,
            FindingCategory::PqcReady,
            "certs/leaf.pem",
        );
        assert!(plan_migration(&f).is_none());
    }

    #[test]
    fn dependency_library_gets_dependency_patch_and_upgrade_strategy() {
        let f = finding(
            Some("RSA"),
            CryptoAssetType::CryptoLibrary,
            PqcStatus::ClassicalSecure,
            FindingSeverity::Medium,
            FindingCategory::VulnerableLibrary,
            "Cargo.toml",
        );
        let p = plan_migration(&f).unwrap();
        assert_eq!(p.strategy, MigrationStrategy::UpgradeLibrary);
        assert_eq!(p.patch.as_ref().unwrap().kind, "dependency");
        let md = plan_to_markdown(&p);
        assert!(md.contains("Post-quantum migration"));
        assert!(md.contains("```diff"));
    }

    #[test]
    fn plan_all_sorts_p0_before_p1() {
        let weak = finding(
            Some("RC4"),
            CryptoAssetType::EncryptionKey,
            PqcStatus::ClassicalWeak,
            FindingSeverity::High,
            FindingCategory::WeakAlgorithm,
            "c.yaml",
        );
        let rsa = finding(
            Some("RSA-2048"),
            CryptoAssetType::Certificate,
            PqcStatus::ClassicalSecure,
            FindingSeverity::High,
            FindingCategory::ClassicalCrypto,
            "leaf.pem",
        );
        let plans = plan_all(&[rsa, weak]);
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].priority, MigrationPriority::P0);
        assert_eq!(plans[1].priority, MigrationPriority::P1);
    }
}
