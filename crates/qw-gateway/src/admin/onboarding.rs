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
        severity: f.severity.clone(),
        title: f.title.clone(),
        description: f.description.clone(),
        asset_type: f.asset.asset_type.clone(),
        algorithm: f.asset.algorithm.clone(),
        pqc_status: f.pqc_status.clone(),
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
