//! Agentless onboarding — "your quantum exposure in 5 minutes".
//!
//! Point QuantaWatch at a few hostnames and get a verdict immediately: no
//! gateway in the data path, no agents, no connectors, no config. This is the
//! top-of-funnel artifact, so it composes what already exists — the TLS
//! scanner, the posture engine, the compliance engine, and the migration
//! planner — into one report.
//!
//! Results are **ephemeral**: nothing is persisted to the tenant's findings, so
//! evaluating a prospect's domains can't pollute real posture data.

use std::time::Instant;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use qw_cbom::{ComplianceEngine, PostureEngine};
use qw_scanner::{Finding, FindingRecord, PqcStatus, ScanTarget};

use crate::state::AppState;

/// Cap targets so the "5 minutes" promise holds and the endpoint can't be used
/// to fan out a large scan.
const MAX_TARGETS: usize = 10;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingRequest {
    /// Hostnames to probe, e.g. ["example.com", "api.example.com:8443"].
    /// Port defaults to 443.
    pub domains: Vec<String>,
}

/// Normalize "example.com" -> "example.com:443"; leave explicit ports alone.
///
/// The scheme must be stripped *before* trimming slashes — doing it the other
/// way turns a bare "https://" into the host "https:", which would then be
/// scanned as if it were real.
fn normalize_target(raw: &str) -> Option<String> {
    let t = raw.trim();
    // Tolerate a pasted URL.
    let t = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    // Drop any path/query, then whitespace.
    let t = t.split(['/', '?']).next().unwrap_or(t).trim();
    if t.is_empty() {
        return None;
    }
    match t.split_once(':') {
        // An explicit port: both host and port must actually be present.
        Some((host, port)) => {
            if host.is_empty() || port.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        None => Some(format!("{t}:443")),
    }
}

/// Quantum-vulnerable = classical asymmetric crypto that a CRQC breaks, or
/// something already weak today.
fn is_quantum_exposed(f: &Finding) -> bool {
    matches!(
        f.pqc_status,
        PqcStatus::ClassicalSecure | PqcStatus::ClassicalWeak
    )
}

fn record_from_finding(f: &Finding) -> FindingRecord {
    FindingRecord {
        id: f.id.clone(),
        scan_id: "onboarding".to_string(),
        category: f.category.clone(),
        severity: f.severity,
        title: f.title.clone(),
        description: f.description.clone(),
        asset_type: f.asset.asset_type.clone(),
        algorithm: f.asset.algorithm.clone(),
        pqc_status: f.pqc_status,
        location: f.asset.location.path.clone(),
        remediation: f.remediation.clone(),
        created_at: Utc::now(),
        confidence: qw_scanner::confidence_of(f),
        evidence: qw_scanner::evidence_of(f, "onboarding"),
        status: Default::default(),
        note: None,
    }
}

/// `POST /api/onboarding/scan` — agentless quantum-exposure report.
pub async fn onboarding_scan(
    State(state): State<AppState>,
    Json(body): Json<OnboardingRequest>,
) -> impl IntoResponse {
    let started = Instant::now();

    let targets: Vec<String> = body
        .domains
        .iter()
        .filter_map(|d| normalize_target(d))
        .collect();
    if targets.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "provide at least one domain, e.g. {\"domains\":[\"example.com\"]}" })),
        )
            .into_response();
    }
    if targets.len() > MAX_TARGETS {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("at most {MAX_TARGETS} domains per onboarding scan"),
                "hint": "run a full scan once onboarded for broader coverage",
            })),
        )
            .into_response();
    }

    // Probe each endpoint. Nothing here is persisted.
    let mut results = Vec::new();
    for address in &targets {
        let target = ScanTarget::tls(address);
        results.extend(state.scanner_registry.scan_all(&target).await);
    }

    let findings: Vec<Finding> = results.iter().flat_map(|r| r.findings.clone()).collect();
    let records: Vec<FindingRecord> = findings.iter().map(record_from_finding).collect();

    let posture = PostureEngine::summarize(&results, &[]);
    let compliance = ComplianceEngine::assess(&records);
    let plans = qw_cbom::plan_all(&records);

    let exposed = findings.iter().filter(|f| is_quantum_exposed(f)).count();
    let weak = findings
        .iter()
        .filter(|f| matches!(f.pqc_status, PqcStatus::ClassicalWeak))
        .count();
    let pqc_ready = findings
        .iter()
        .filter(|f| matches!(f.pqc_status, PqcStatus::PqcReady | PqcStatus::Hybrid))
        .count();

    let verdict = if weak > 0 || posture.overall_score < 50.0 {
        "critical"
    } else if exposed > 0 {
        "at-risk"
    } else {
        "hardened"
    };

    let headline = match verdict {
        "critical" => format!(
            "{weak} endpoint(s) use cryptography that is weak today, before quantum is even a factor."
        ),
        "at-risk" => format!(
            "{exposed} of {} inventoried assets rely on classical public-key cryptography. Traffic \
             captured today can be decrypted retroactively once a cryptographically-relevant \
             quantum computer exists (harvest-now-decrypt-later).",
            findings.len()
        ),
        _ => "No quantum-vulnerable cryptography found on the scanned endpoints.".to_string(),
    };

    // The 3 highest-priority concrete fixes — the "what do I do about it".
    let top_actions: Vec<_> = plans.iter().take(3).collect();

    Json(json!({
        "scannedAt": Utc::now(),
        "durationMs": started.elapsed().as_millis() as u64,
        "targets": targets,
        "exposure": {
            "verdict": verdict,
            "headline": headline,
            "postureScore": (posture.overall_score * 10.0).round() / 10.0,
            "assetsInventoried": findings.len(),
            "quantumVulnerable": exposed,
            "weakToday": weak,
            "pqcReady": pqc_ready,
        },
        "compliance": {
            "cnsa2Pct": (compliance.overall_compliance_pct * 10.0).round() / 10.0,
        },
        "topActions": top_actions,
        "totalActions": plans.len(),
        "nextSteps": [
            "Run the gateway in-path to enforce policy on live agent traffic.",
            "Connect a repo/cloud integration for dependency + key inventory.",
            "Export a signed evidence pack for your auditor.",
        ],
    }))
    .into_response()
}

// ---- Seeded demo estate ----

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SeedDemoRequest {
    /// Seed even if the tenant already has real data (default false).
    #[serde(default)]
    pub force: bool,
}

fn demo_svc(port: u16, service: &str, pqc: &str, detail: &str) -> qw_store::ExposedService {
    qw_store::ExposedService {
        port,
        service: service.to_string(),
        pqc_status: pqc.to_string(),
        detail: detail.to_string(),
        source: "network".to_string(),
        exposed: true,
        protected_listen: None,
        cert_id: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn demo_finding(
    location: &str,
    title: &str,
    desc: &str,
    asset_type: qw_scanner::CryptoAssetType,
    algorithm: Option<&str>,
    pqc: PqcStatus,
    severity: qw_scanner::FindingSeverity,
    category: qw_scanner::FindingCategory,
) -> Finding {
    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        category,
        severity,
        title: title.to_string(),
        description: desc.to_string(),
        asset: qw_scanner::CryptoAsset {
            id: uuid::Uuid::new_v4().to_string(),
            asset_type,
            name: title.to_string(),
            algorithm: algorithm.map(String::from),
            key_length: None,
            protocol_version: None,
            location: qw_scanner::AssetLocation {
                source_type: "demo".to_string(),
                path: location.to_string(),
                line: None,
            },
            discovered_by: "demo".to_string(),
            discovered_at: Utc::now(),
        },
        remediation: None,
        pqc_status: pqc,
        metadata: std::collections::HashMap::from([(
            "source".to_string(),
            "demo-seed".to_string(),
        )]),
    }
}

/// `POST /api/onboarding/seed-demo` — populate a fresh install with a small,
/// clearly-labelled sample estate so the dashboard shows value immediately.
/// Refuses to run against a tenant that already has real data unless `force`.
pub async fn seed_demo(
    State(state): State<AppState>,
    ctx: Option<axum::Extension<crate::auth::AuthContext>>,
    body: Option<Json<SeedDemoRequest>>,
) -> impl IntoResponse {
    use qw_scanner::{CryptoAssetType as AT, FindingCategory as FC, FindingSeverity as FS};
    let tenant = crate::auth::tenant_of(&ctx);
    let force = body.map(|b| b.0.force).unwrap_or(false);

    // Guard: don't pollute a real estate.
    let existing_targets = state.store.list_targets(&tenant).len();
    let existing_findings = state.store.all_findings(&tenant).len();
    if !force && (existing_targets > 0 || existing_findings > 5) {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "This tenant already has data. Pass force=true to seed the demo anyway.",
                "targets": existing_targets,
                "findings": existing_findings,
            })),
        )
            .into_response();
    }

    let now = Utc::now();
    // Three clearly-labelled demo hosts spanning the crypto spectrum.
    let targets = vec![
        qw_store::TargetRow {
            id: uuid::Uuid::new_v4().to_string(),
            name: "demo-web-01".into(),
            host: "demo-web-01.acme.example".into(),
            kind: "server".into(),
            reachability: vec!["tls".into()],
            environment: "production".into(),
            tags: vec!["demo".into()],
            exposed_services: vec![demo_svc(
                443,
                "https",
                "classical_secure",
                "TLS 1.3 with a classical (X25519) key exchange — harvestable today.",
            )],
            containers: vec![],
            host_info: None,
            deep_scanned: false,
            pqc_status: "classical_secure".into(),
            last_scanned: Some(now),
            created_at: now,
        },
        qw_store::TargetRow {
            id: uuid::Uuid::new_v4().to_string(),
            name: "demo-db-01".into(),
            host: "demo-db-01.acme.example".into(),
            kind: "database".into(),
            reachability: vec!["tls".into()],
            environment: "production".into(),
            tags: vec!["demo".into()],
            exposed_services: vec![demo_svc(
                5432,
                "postgresql",
                "classical_weak",
                "PostgreSQL reachable with data unencrypted at rest.",
            )],
            containers: vec![],
            host_info: None,
            deep_scanned: false,
            pqc_status: "classical_weak".into(),
            last_scanned: Some(now),
            created_at: now,
        },
        qw_store::TargetRow {
            id: uuid::Uuid::new_v4().to_string(),
            name: "demo-legacy-01".into(),
            host: "demo-legacy-01.acme.example".into(),
            kind: "server".into(),
            reachability: vec!["ssh".into(), "rdp".into()],
            environment: "staging".into(),
            tags: vec!["demo".into()],
            exposed_services: vec![
                demo_svc(
                    22,
                    "ssh",
                    "classical_weak",
                    "SSH offers a deprecated MAC (hmac-sha1).",
                ),
                demo_svc(
                    3389,
                    "rdp",
                    "classical_secure",
                    "RDP negotiated CredSSP/NLA over classical TLS.",
                ),
            ],
            containers: vec![],
            host_info: None,
            deep_scanned: false,
            pqc_status: "classical_weak".into(),
            last_scanned: Some(now),
            created_at: now,
        },
    ];
    for t in &targets {
        state.store.upsert_target(&tenant, t);
    }

    // A synthetic scan spanning the finding spectrum (confidence + evidence are
    // derived automatically at record time).
    let findings = vec![
        demo_finding(
            "demo-web-01.acme.example:443",
            "TLS 1.3 on demo-web-01",
            "Classical X25519 key exchange — harvest-now-decrypt-later exposed.",
            AT::TlsConnection,
            Some("X25519"),
            PqcStatus::ClassicalSecure,
            FS::Medium,
            FC::MissingPqc,
        ),
        demo_finding(
            "demo-web-01.acme.example:443",
            "Certificate #1 for demo-web-01",
            "Leaf signed with RSA-2048 / SHA-256 — forgeable by a quantum computer.",
            AT::Certificate,
            Some("RSA-SHA256"),
            PqcStatus::ClassicalSecure,
            FS::Medium,
            FC::ClassicalCrypto,
        ),
        demo_finding(
            "demo-db-01.acme.example",
            "demo-db-01 data at rest",
            "Database stores data with no encryption at rest.",
            AT::DataStore,
            Some("none"),
            PqcStatus::ClassicalWeak,
            FS::High,
            FC::MissingPqc,
        ),
        demo_finding(
            "./demo-app/Cargo.toml",
            "Crypto dependency: openssl",
            "Depends on a classical-only crypto library (no PQC).",
            AT::CryptoLibrary,
            Some("openssl"),
            PqcStatus::ClassicalSecure,
            FS::Medium,
            FC::MissingPqc,
        ),
        demo_finding(
            "demo-legacy-01.acme.example:22",
            "SSH MAC on demo-legacy-01",
            "SSH server offers deprecated hmac-sha1 MAC.",
            AT::ProtocolEndpoint,
            Some("hmac-sha1"),
            PqcStatus::ClassicalWeak,
            FS::High,
            FC::WeakAlgorithm,
        ),
        demo_finding(
            "demo-edge-01.acme.example:443",
            "TLS 1.3 on demo-edge-01",
            "Already negotiates X25519MLKEM768 hybrid — post-quantum ready.",
            AT::TlsConnection,
            Some("X25519MLKEM768"),
            PqcStatus::Hybrid,
            FS::Info,
            FC::PqcReady,
        ),
    ];
    let n = findings.len();
    let result = qw_scanner::ScanResult {
        scanner_id: "demo".to_string(),
        target_id: "demo-seed".to_string(),
        started_at: now,
        completed_at: Utc::now(),
        findings,
        status: qw_scanner::ScanStatus::Completed,
        error: None,
    };
    state
        .store
        .record_scan(&tenant, &result, &ScanTarget::network_host("demo-seed"));
    crate::admin::graph::snapshot_and_alert(&state, &tenant).await;

    Json(json!({
        "seeded": true,
        "targets": targets.len(),
        "findings": n,
        "note": "Demo estate seeded. Explore Estate, Attack Paths, and Remediate; items are tagged 'demo'.",
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_bare_hosts_urls_and_ports() {
        assert_eq!(normalize_target("example.com").unwrap(), "example.com:443");
        assert_eq!(
            normalize_target("https://example.com/").unwrap(),
            "example.com:443"
        );
        assert_eq!(
            normalize_target("http://example.com/some/path").unwrap(),
            "example.com:443"
        );
        // An explicit port is preserved.
        assert_eq!(
            normalize_target("api.example.com:8443").unwrap(),
            "api.example.com:8443"
        );
        assert_eq!(
            normalize_target("  example.com  ").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn rejects_empty_targets() {
        assert!(normalize_target("").is_none());
        assert!(normalize_target("   ").is_none());
        // Regression: this used to normalize to the host "https:" and get scanned.
        assert!(normalize_target("https://").is_none());
        assert!(normalize_target("http://").is_none());
        assert!(normalize_target("/").is_none());
    }

    #[test]
    fn rejects_malformed_host_port_pairs() {
        assert!(normalize_target(":443").is_none(), "no host");
        assert!(normalize_target("example.com:").is_none(), "no port");
    }

    #[test]
    fn drops_query_strings() {
        assert_eq!(
            normalize_target("https://example.com/path?x=1").unwrap(),
            "example.com:443"
        );
    }
}
