use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use qw_scanner::ScanTarget;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    pub limit: Option<usize>,
}

pub async fn list_scans(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Query(query): Query<ScanQuery>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let limit = query.limit.unwrap_or(50);
    let scans = state.store.list_scans(&tenant, limit);
    Json(json!({
        "scans": scans,
        "total": scans.len(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct TriggerScanRequest {
    pub targets: Vec<ScanTargetInput>,
}

#[derive(Debug, Deserialize)]
pub struct ScanTargetInput {
    pub target_type: String,
    pub address: String,
}

pub async fn trigger_scan(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<TriggerScanRequest>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let mut all_results = Vec::new();

    for input in &body.targets {
        let target = match input.target_type.as_str() {
            "tls" => ScanTarget::tls(&input.address),
            "ssh" => ScanTarget::ssh(&input.address),
            "network" | "host" => ScanTarget::network_host(&input.address),
            "starttls" => ScanTarget::starttls(&input.address, ""),
            "postgres" | "postgresql" => ScanTarget::starttls(&input.address, "postgres"),
            "smtp" => ScanTarget::starttls(&input.address, "smtp"),
            "dependency" => ScanTarget::dependency_file(&input.address),
            "code" => ScanTarget::code_directory(&input.address),
            "certificate" | "cert" => ScanTarget::certificate(&input.address),
            _ => {
                tracing::warn!(target_type = %input.target_type, "Unknown target type");
                continue;
            }
        };

        let results = state.scanner_registry.scan_all(&target).await;

        for result in &results {
            state.store.record_scan(&tenant, result, &target);

            // Audit log
            let _ = state
                .audit_logger
                .log(
                    "system",
                    qw_audit::AuditEvent::ScanCompleted {
                        scan_id: result.target_id.clone(),
                        scanner_id: result.scanner_id.clone(),
                        target: target.address.clone(),
                        finding_count: result.findings.len() as u32,
                        status: format!("{:?}", result.status),
                    },
                )
                .await;
        }

        all_results.extend(results);
    }

    // Recompute posture and append a history snapshot.
    let summary =
        crate::background::recompute_and_snapshot(&state, &tenant, &all_results, "manual").await;
    crate::background::evaluate_findings_alerts(&state, &tenant, &all_results).await;

    Json(json!({
        "scans_completed": all_results.len(),
        "total_findings": all_results.iter().map(|r| r.findings.len()).sum::<usize>(),
        "overall_score": summary.overall_score,
        "results": all_results,
    }))
}

pub async fn get_scan(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    match state.store.get_scan(&tenant, &id) {
        Some(scan) => {
            let findings = state.store.findings_for_scan(&tenant, &id);
            Json(json!({
                "scan": scan,
                "findings": findings,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scan not found"})),
        )
            .into_response(),
    }
}

pub async fn list_all_findings(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let findings = state.store.all_findings(&tenant);
    Json(json!({
        "findings": findings,
        "total": findings.len(),
    }))
}
