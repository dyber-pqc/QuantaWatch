//! Crypto-agility policy engine — "clicks not code".
//!
//! [`governance`](crate::governance) gives one estate-wide PASS/AT-RISK/FAIL
//! verdict. This engine is the actionable layer on top: a set of targeted
//! [`CryptoAgilityPolicy`] rules, each scoped to a slice of the estate
//! (`selector`) and matched against the findings that violate it (`match`),
//! with a remediation `action` and an `enforcement` mode. Evaluating a policy
//! yields the exact violating assets plus a stable fingerprint per violation so
//! the caller can detect **drift** (new violations) and **regressions** across
//! scans, and `enforce` them through the connectors (open a PR / ticket).
//!
//! This is what turns discovery into remediation you can gate and automate,
//! rather than a static report.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use qw_scanner::{FindingRecord, FindingSeverity};

/// A single crypto-agility rule the organization commits to and enforces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoAgilityPolicy {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Which slice of the estate this rule applies to. Empty = everything.
    #[serde(default)]
    pub selector: PolicySelector,
    /// The condition that makes a finding a violation of this rule.
    #[serde(default, rename = "match")]
    pub match_: PolicyMatch,
    /// Business severity of a violation (low | medium | high | critical).
    #[serde(default = "default_severity")]
    pub severity: String,
    /// When compliance is required by (e.g. CNSA 2.0's 2030-01-01).
    #[serde(default)]
    pub deadline: Option<DateTime<Utc>>,
    /// What to do about a violation: open_pr | create_ticket | alert.
    #[serde(default = "default_action")]
    pub action: String,
    /// monitor = report only; auto = enforce automatically after each scan.
    #[serde(default = "default_enforcement")]
    pub enforcement: String,
}

fn default_severity() -> String {
    "high".to_string()
}
fn default_action() -> String {
    "open_pr".to_string()
}
fn default_enforcement() -> String {
    "monitor".to_string()
}

/// Scopes a policy to part of the estate. All set fields must match (AND).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySelector {
    /// Finding asset types, e.g. "tls_connection", "certificate", "data_store".
    #[serde(default)]
    pub asset_types: Vec<String>,
    /// Asset environment glob (via the asset inventory), e.g. "prod*".
    #[serde(default)]
    pub environment: Option<String>,
    /// Asset kinds (via the asset inventory), e.g. "database", "object_store".
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Asset tags that must all be present (via the asset inventory).
    #[serde(default)]
    pub tags: Vec<String>,
}

/// The condition that makes an in-scope finding a violation. All set fields
/// must match (AND); an empty field is ignored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyMatch {
    /// Finding categories, e.g. "missing_pqc", "weak_algorithm", "classical_crypto".
    #[serde(default)]
    pub categories: Vec<String>,
    /// PQC statuses, e.g. "classical_weak", "classical_secure".
    #[serde(default)]
    pub pqc_status: Vec<String>,
    /// Glob over the finding's algorithm, e.g. "rsa*", "*ecdh*", "ssh-rsa".
    #[serde(default)]
    pub algorithm_glob: Option<String>,
    /// Only findings at or above this severity (info|low|medium|high|critical).
    #[serde(default)]
    pub min_severity: Option<String>,
}

/// Minimal asset context (from the asset inventory) used to resolve a policy's
/// environment/kind/tag selector for a finding. Kept free of any store types so
/// this crate stays dependency-light; the gateway maps its `AssetRow` into this.
#[derive(Debug, Clone)]
pub struct AssetContext {
    pub address: String,
    pub kind: String,
    pub environment: String,
    pub tags: Vec<String>,
}

/// One asset that violates a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Violation {
    pub finding_id: String,
    pub location: String,
    pub category: String,
    pub pqc_status: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Stable across scans (findings get fresh ids each scan): identifies the
    /// same problem on the same asset, so drift can be tracked.
    pub fingerprint: String,
}

/// The evaluation of one policy against the current inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResult {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub action: String,
    pub enforcement: String,
    /// "compliant" | "violated".
    pub status: String,
    pub violation_count: usize,
    pub violations: Vec<Violation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_to_deadline: Option<i64>,
    pub deadline_passed: bool,
}

impl PolicyResult {
    /// The set of violation fingerprints — the drift baseline for this policy.
    pub fn fingerprints(&self) -> Vec<String> {
        self.violations
            .iter()
            .map(|v| v.fingerprint.clone())
            .collect()
    }
}

/// Case-insensitive glob over `*` wildcards (no regex). Supports exact,
/// `prefix*`, `*suffix`, `*contains*`, and interior `a*b` patterns.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.to_lowercase();
    let t = text.to_lowercase();
    if !p.contains('*') {
        return t == p;
    }
    let parts: Vec<&str> = p.split('*').collect();
    let mut pos = 0usize;
    let last = parts.len() - 1;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !t[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if i == last {
            if !t[pos..].ends_with(part) {
                return false;
            }
        } else {
            match t[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Serialize a snake_case unit enum (FindingCategory, PqcStatus, …) to its string.
fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(String::from))
        .unwrap_or_default()
}

fn parse_severity(s: &str) -> Option<FindingSeverity> {
    match s.to_lowercase().as_str() {
        "info" => Some(FindingSeverity::Info),
        "low" => Some(FindingSeverity::Low),
        "medium" | "med" => Some(FindingSeverity::Medium),
        "high" => Some(FindingSeverity::High),
        "critical" | "crit" => Some(FindingSeverity::Critical),
        _ => None,
    }
}

/// The asset in `assets` that owns this finding (its address appears in the
/// finding's location), if any.
fn asset_for<'a>(location: &str, assets: &'a [AssetContext]) -> Option<&'a AssetContext> {
    let loc = location.to_lowercase();
    assets
        .iter()
        .find(|a| !a.address.is_empty() && loc.contains(&a.address.to_lowercase()))
}

fn selector_matches(sel: &PolicySelector, f: &FindingRecord, assets: &[AssetContext]) -> bool {
    if !sel.asset_types.is_empty() {
        let at = enum_str(&f.asset_type);
        if !sel.asset_types.iter().any(|k| k.eq_ignore_ascii_case(&at)) {
            return false;
        }
    }
    // Environment / kind / tags need an asset join; if one is required but no
    // asset resolves, the finding is out of scope.
    let needs_asset = sel.environment.is_some() || !sel.kinds.is_empty() || !sel.tags.is_empty();
    if needs_asset {
        let Some(asset) = asset_for(&f.location, assets) else {
            return false;
        };
        if let Some(env) = &sel.environment {
            if !glob_match(env, &asset.environment) {
                return false;
            }
        }
        if !sel.kinds.is_empty()
            && !sel
                .kinds
                .iter()
                .any(|k| k.eq_ignore_ascii_case(&asset.kind))
        {
            return false;
        }
        for want in &sel.tags {
            if !asset.tags.iter().any(|t| t.eq_ignore_ascii_case(want)) {
                return false;
            }
        }
    }
    true
}

fn match_matches(m: &PolicyMatch, f: &FindingRecord) -> bool {
    if !m.categories.is_empty() {
        let c = enum_str(&f.category);
        if !m.categories.iter().any(|x| x.eq_ignore_ascii_case(&c)) {
            return false;
        }
    }
    if !m.pqc_status.is_empty() {
        let s = enum_str(&f.pqc_status);
        if !m.pqc_status.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
            return false;
        }
    }
    if let Some(g) = &m.algorithm_glob {
        let algo = f.algorithm.as_deref().unwrap_or("");
        if !glob_match(g, algo) {
            return false;
        }
    }
    if let Some(min) = m.min_severity.as_deref().and_then(parse_severity) {
        if f.severity < min {
            return false;
        }
    }
    true
}

/// Fingerprint identifying "the same problem on the same asset" across scans.
fn fingerprint(f: &FindingRecord) -> String {
    format!(
        "{}|{}|{}",
        f.location,
        enum_str(&f.category),
        f.algorithm.as_deref().unwrap_or("-")
    )
}

/// Evaluate one policy against the inventory at time `now`.
pub fn evaluate_policy(
    policy: &CryptoAgilityPolicy,
    findings: &[FindingRecord],
    assets: &[AssetContext],
    now: DateTime<Utc>,
) -> PolicyResult {
    let mut violations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in findings {
        if !selector_matches(&policy.selector, f, assets) {
            continue;
        }
        if !match_matches(&policy.match_, f) {
            continue;
        }
        let fp = fingerprint(f);
        // Collapse duplicate findings for the same problem within one evaluation.
        if !seen.insert(fp.clone()) {
            continue;
        }
        violations.push(Violation {
            finding_id: f.id.clone(),
            location: f.location.clone(),
            category: enum_str(&f.category),
            pqc_status: enum_str(&f.pqc_status),
            severity: enum_str(&f.severity),
            algorithm: f.algorithm.clone(),
            fingerprint: fp,
        });
    }

    let days_to_deadline = policy.deadline.map(|d| (d - now).num_days());
    let deadline_passed = policy.deadline.map(|d| now > d).unwrap_or(false);
    let status = if violations.is_empty() {
        "compliant"
    } else {
        "violated"
    };

    PolicyResult {
        id: policy.id.clone(),
        name: policy.name.clone(),
        description: policy.description.clone(),
        severity: policy.severity.clone(),
        action: policy.action.clone(),
        enforcement: policy.enforcement.clone(),
        status: status.to_string(),
        violation_count: violations.len(),
        violations,
        deadline: policy.deadline,
        days_to_deadline,
        deadline_passed,
    }
}

/// Evaluate every policy against the inventory.
pub fn evaluate_all(
    policies: &[CryptoAgilityPolicy],
    findings: &[FindingRecord],
    assets: &[AssetContext],
    now: DateTime<Utc>,
) -> Vec<PolicyResult> {
    policies
        .iter()
        .map(|p| evaluate_policy(p, findings, assets, now))
        .collect()
}

/// A sensible default policy set (CNSA 2.0-aligned) used when config declares
/// none, so the engine is useful out of the box.
pub fn default_policies() -> Vec<CryptoAgilityPolicy> {
    let cnsa = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .ok()
        .map(|d| d.with_timezone(&Utc));
    vec![
        CryptoAgilityPolicy {
            id: "no-weak-crypto".into(),
            name: "No weak cryptography".into(),
            description: "Broken or quantum-weak algorithms (3DES, RC4, MD5, SHA-1, RSA-1024, ssh-rsa) must be removed immediately.".into(),
            selector: PolicySelector::default(),
            match_: PolicyMatch {
                pqc_status: vec!["classical_weak".into()],
                ..Default::default()
            },
            severity: "critical".into(),
            deadline: None,
            action: "open_pr".into(),
            enforcement: "monitor".into(),
        },
        CryptoAgilityPolicy {
            id: "pqc-key-exchange".into(),
            name: "Post-quantum key exchange on transport".into(),
            description: "TLS and SSH endpoints must offer a hybrid PQC key exchange before the CNSA 2.0 deadline; classical-only KEX is harvest-now-decrypt-later exposed.".into(),
            selector: PolicySelector {
                asset_types: vec!["tls_connection".into(), "protocol_endpoint".into()],
                ..Default::default()
            },
            match_: PolicyMatch {
                categories: vec!["missing_pqc".into()],
                ..Default::default()
            },
            severity: "high".into(),
            deadline: cnsa,
            action: "open_pr".into(),
            enforcement: "monitor".into(),
        },
        CryptoAgilityPolicy {
            id: "pqc-certificates".into(),
            name: "Post-quantum certificate signatures".into(),
            description: "Certificates must migrate from classical signatures (RSA/ECDSA) to ML-DSA before the CNSA 2.0 deadline.".into(),
            selector: PolicySelector {
                asset_types: vec!["certificate".into()],
                ..Default::default()
            },
            match_: PolicyMatch {
                pqc_status: vec!["classical_secure".into(), "classical_weak".into()],
                ..Default::default()
            },
            severity: "medium".into(),
            deadline: cnsa,
            action: "create_ticket".into(),
            enforcement: "monitor".into(),
        },
        CryptoAgilityPolicy {
            id: "pqc-data-at-rest".into(),
            name: "Quantum-safe key wrapping at rest".into(),
            description: "Production data stores must not wrap data-encryption keys with RSA/ECDH; long-lived data is harvest-now-decrypt-later exposed.".into(),
            selector: PolicySelector {
                asset_types: vec!["data_store".into()],
                environment: Some("prod*".into()),
                ..Default::default()
            },
            match_: PolicyMatch {
                categories: vec!["missing_pqc".into(), "stale_key_rotation".into(), "classical_crypto".into()],
                ..Default::default()
            },
            severity: "critical".into(),
            deadline: cnsa,
            action: "open_pr".into(),
            enforcement: "monitor".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use qw_scanner::{CryptoAssetType, FindingCategory, PqcStatus};

    fn finding(
        id: &str,
        cat: FindingCategory,
        at: CryptoAssetType,
        algo: &str,
        pqc: PqcStatus,
        loc: &str,
        sev: FindingSeverity,
    ) -> FindingRecord {
        FindingRecord {
            id: id.into(),
            scan_id: "s".into(),
            category: cat,
            severity: sev,
            title: "t".into(),
            description: "d".into(),
            asset_type: at,
            algorithm: Some(algo.into()),
            pqc_status: pqc,
            location: loc.into(),
            remediation: None,
            created_at: Utc::now(),
            confidence: Default::default(),
            evidence: Vec::new(),
            status: Default::default(),
            note: None,
        }
    }

    #[test]
    fn glob_matches_expected() {
        assert!(glob_match("rsa*", "RSA-2048"));
        assert!(glob_match("*ecdh*", "ecdh-sha2-nistp256"));
        assert!(glob_match("ssh-rsa", "ssh-rsa"));
        assert!(glob_match("*", "anything"));
        assert!(!glob_match("rsa*", "ecdsa-sha256"));
        assert!(!glob_match("ssh-rsa", "ssh-ed25519"));
    }

    #[test]
    fn match_is_conjunction_of_set_fields() {
        let m = PolicyMatch {
            categories: vec!["missing_pqc".into()],
            algorithm_glob: Some("*ecdh*".into()),
            ..Default::default()
        };
        let hit = finding(
            "a",
            FindingCategory::MissingPqc,
            CryptoAssetType::TlsConnection,
            "ecdh-sha2",
            PqcStatus::ClassicalSecure,
            "h:22",
            FindingSeverity::High,
        );
        let miss_cat = finding(
            "b",
            FindingCategory::WeakAlgorithm,
            CryptoAssetType::TlsConnection,
            "ecdh-sha2",
            PqcStatus::ClassicalWeak,
            "h:22",
            FindingSeverity::High,
        );
        let miss_algo = finding(
            "c",
            FindingCategory::MissingPqc,
            CryptoAssetType::TlsConnection,
            "curve25519",
            PqcStatus::ClassicalSecure,
            "h:22",
            FindingSeverity::High,
        );
        assert!(match_matches(&m, &hit));
        assert!(!match_matches(&m, &miss_cat));
        assert!(!match_matches(&m, &miss_algo));
    }

    #[test]
    fn selector_scopes_by_asset_type_and_env() {
        let sel = PolicySelector {
            asset_types: vec!["data_store".into()],
            environment: Some("prod*".into()),
            ..Default::default()
        };
        let assets = vec![AssetContext {
            address: "orders-db.internal:5432".into(),
            kind: "database".into(),
            environment: "production".into(),
            tags: vec![],
        }];
        let in_scope = finding(
            "a",
            FindingCategory::MissingPqc,
            CryptoAssetType::DataStore,
            "rsa-2048",
            PqcStatus::ClassicalSecure,
            "orders-db.internal:5432",
            FindingSeverity::High,
        );
        let wrong_type = finding(
            "b",
            FindingCategory::MissingPqc,
            CryptoAssetType::TlsConnection,
            "rsa-2048",
            PqcStatus::ClassicalSecure,
            "orders-db.internal:5432",
            FindingSeverity::High,
        );
        assert!(selector_matches(&sel, &in_scope, &assets));
        assert!(!selector_matches(&sel, &wrong_type, &assets));
        // No asset context for env resolution -> out of scope.
        assert!(!selector_matches(&sel, &in_scope, &[]));
    }

    #[test]
    fn evaluate_flags_violations_and_fingerprints() {
        let policies = default_policies();
        let findings = vec![
            finding(
                "f1",
                FindingCategory::WeakAlgorithm,
                CryptoAssetType::ProtocolEndpoint,
                "ssh-rsa",
                PqcStatus::ClassicalWeak,
                "bastion:22",
                FindingSeverity::Medium,
            ),
            finding(
                "f2",
                FindingCategory::MissingPqc,
                CryptoAssetType::TlsConnection,
                "curve25519",
                PqcStatus::ClassicalSecure,
                "api:443",
                FindingSeverity::High,
            ),
        ];
        let now = Utc::now();
        let results = evaluate_all(&policies, &findings, &[], now);
        let weak = results.iter().find(|r| r.id == "no-weak-crypto").unwrap();
        assert_eq!(weak.status, "violated");
        assert_eq!(weak.violation_count, 1);
        assert_eq!(
            weak.violations[0].fingerprint,
            "bastion:22|weak_algorithm|ssh-rsa"
        );
        let kex = results.iter().find(|r| r.id == "pqc-key-exchange").unwrap();
        assert_eq!(kex.status, "violated");
        assert!(kex.days_to_deadline.unwrap() > 0);
        // The data-at-rest policy has no matching findings -> compliant.
        let atrest = results.iter().find(|r| r.id == "pqc-data-at-rest").unwrap();
        assert_eq!(atrest.status, "compliant");
    }
}
