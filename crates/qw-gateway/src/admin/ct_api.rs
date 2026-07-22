//! Certificate-Transparency monitoring endpoint.
//!
//! `POST /api/ct/scan {domain}` queries public CT logs (crt.sh) for every
//! certificate issued for a domain and its subdomains, classifies each one's
//! signature crypto, and records the results as normal findings (with the same
//! confidence + evidence trail as any scan). It reads only public log data — no
//! credentials, no access to the domain's hosts — so it surfaces certificates
//! you may not know about: shadow IT, forgotten subdomains, or mis-issuance.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;

use qw_scanner::{scanners::ct::CtScanner, PqcStatus, ScanTarget, Scanner};

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CtScanRequest {
    domain: String,
    /// How many recent certificates to classify (default 25, capped in-scanner).
    #[serde(default)]
    max_certs: Option<usize>,
}

/// POST /api/ct/scan — monitor a domain's certificate-transparency footprint.
pub async fn ct_scan(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<CtScanRequest>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let domain = body.domain.trim().to_string();
    if domain.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "domain is required" })),
        )
            .into_response();
    }

    let mut scanner = CtScanner::new(body.max_certs.unwrap_or(25), 20);
    // Allow pointing at a proxy / private CT aggregator / test server.
    if let Ok(base) = std::env::var("QW_CT_BASE_URL") {
        scanner = scanner.with_base_url(base);
    }
    let scan_target = ScanTarget::ct_domain(&domain);
    let result = match scanner.scan(&scan_target).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("CT lookup failed: {e}") })),
            )
                .into_response()
        }
    };

    let total = result.findings.len();
    let weak = result
        .findings
        .iter()
        .filter(|f| matches!(f.pqc_status, PqcStatus::ClassicalWeak))
        .count();
    // Distinct issuers seen — a quick "who's issuing for me" signal.
    let mut issuers: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.metadata.get("issuer").cloned())
        .collect();
    issuers.sort();
    issuers.dedup();

    // Fold into the normal findings/graph/posture pipeline.
    state.store.record_scan(&tenant, &result, &scan_target);
    let _ = state
        .audit_logger
        .log(
            "system",
            qw_audit::AuditEvent::ScanCompleted {
                scan_id: result.target_id.clone(),
                scanner_id: "ct".to_string(),
                target: domain.clone(),
                finding_count: total as u32,
                status: format!("{:?}", result.status),
            },
        )
        .await;
    crate::admin::graph::snapshot_and_alert(&state, &tenant).await;

    Json(json!({
        "domain": domain,
        "certificatesFound": total,
        "weak": weak,
        "issuers": issuers,
    }))
    .into_response()
}
