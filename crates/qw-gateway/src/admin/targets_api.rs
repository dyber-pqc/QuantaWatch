//! Estate targets — the layer that connects everything.
//!
//! A target is a connected system (a VM, a server over SSH/RDP, a network host).
//! Registering it authorizes QuantaWatch to **sweep** it: a scoped TCP port scan
//! of crypto-relevant ports, then per-port fingerprinting (SSH key exchange, TLS,
//! STARTTLS) — producing one inventory of "what this machine exposes and its
//! post-quantum posture". The sweep's findings also flow into the normal
//! findings/graph/policy pipeline, so a target ties discovery → protect → enforce
//! together.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use qw_scanner::{ScanTarget, Scanner};
use qw_store::{ExposedService, TargetRow};

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

/// Rank PQC posture so we can pick the *worst* exposed service (lower = worse).
fn pqc_rank(s: &str) -> u8 {
    match s {
        "classical_weak" => 0,
        "classical_secure" => 1,
        "unknown" => 2,
        "hybrid" => 3,
        "pqc_ready" => 4,
        _ => 2,
    }
}

fn port_service(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        25 => "smtp",
        443 => "https",
        465 => "smtps",
        587 => "smtp-submission",
        636 => "ldaps",
        853 => "dns-over-tls",
        993 => "imaps",
        995 => "pop3s",
        3389 => "rdp",
        5432 => "postgresql",
        6443 => "kubernetes-api",
        8443 => "https-alt",
        _ => "service",
    }
}

fn port_of(location: &str) -> Option<u16> {
    location.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTarget {
    name: String,
    host: String,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default)]
    reachability: Vec<String>,
    #[serde(default = "default_env")]
    environment: String,
    #[serde(default)]
    tags: Vec<String>,
}

fn default_kind() -> String {
    "server".to_string()
}
fn default_env() -> String {
    "default".to_string()
}

/// POST /api/targets — register a connected system.
pub async fn register(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<RegisterTarget>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    if body.host.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "host is required" }))).into_response();
    }
    let row = TargetRow {
        id: uuid::Uuid::new_v4().to_string(),
        name: if body.name.trim().is_empty() { body.host.clone() } else { body.name },
        host: body.host,
        kind: body.kind,
        reachability: body.reachability,
        environment: body.environment,
        tags: body.tags,
        exposed_services: vec![],
        pqc_status: "unknown".to_string(),
        last_scanned: None,
        created_at: chrono::Utc::now(),
    };
    state.store.upsert_target(&tenant, &row);
    (StatusCode::CREATED, Json(row)).into_response()
}

/// GET /api/targets — the estate, with exposure summaries.
pub async fn list_targets(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let targets = state.store.list_targets(&tenant);
    let exposed: usize = targets.iter().map(|t| t.exposed_services.len()).sum();
    let vulnerable = targets
        .iter()
        .filter(|t| matches!(t.pqc_status.as_str(), "classical_weak" | "classical_secure"))
        .count();
    Json(json!({
        "targets": targets,
        "total": targets.len(),
        "exposedServices": exposed,
        "quantumVulnerable": vulnerable,
    }))
}

/// GET /api/targets/{id}
pub async fn get_target(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    match state.store.get_target(&tenant, &id) {
        Some(t) => Json(t).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": format!("target '{id}' not found") }))).into_response(),
    }
}

/// DELETE /api/targets/{id}
pub async fn delete_target(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    state.store.delete_target(&tenant, &id);
    Json(json!({ "id": id, "deleted": true }))
}

/// POST /api/targets/{id}/scan — sweep the target for exposed services + crypto.
pub async fn scan_target(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let Some(mut target) = state.store.get_target(&tenant, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": format!("target '{id}' not found") }))).into_response();
    };

    // A registered target is authorized, so run the network sweep directly (the
    // registry's network scanner may be disabled by default). It port-scans and
    // hands SSH/TLS/STARTTLS ports to the right fingerprinter.
    let scanner = qw_scanner::scanners::network::NetworkScanner::new(qw_scanner::NetworkScannerConfig {
        enabled: true,
        connect_timeout_ms: 1500,
        ports: qw_scanner::NetworkScannerConfig::default().ports,
        targets: vec![],
    });
    let scan_target = ScanTarget::network_host(&target.host);
    let result = match scanner.scan(&scan_target).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("sweep failed: {e}") })),
            )
                .into_response()
        }
    };

    // Record the scan + findings into the normal pipeline (findings/graph/policies).
    state.store.record_scan(&tenant, &result, &scan_target);
    let _ = state
        .audit_logger
        .log(
            "system",
            qw_audit::AuditEvent::ScanCompleted {
                scan_id: result.target_id.clone(),
                scanner_id: "network".to_string(),
                target: target.host.clone(),
                finding_count: result.findings.len() as u32,
                status: format!("{:?}", result.status),
            },
        )
        .await;

    // Collapse findings into one exposed-service entry per port (worst posture).
    use std::collections::BTreeMap;
    let mut by_port: BTreeMap<u16, ExposedService> = BTreeMap::new();
    for f in &result.findings {
        let Some(port) = port_of(&f.asset.location.path) else {
            continue;
        };
        let status = f.pqc_status.to_string();
        let entry = by_port.entry(port).or_insert_with(|| ExposedService {
            port,
            service: port_service(port).to_string(),
            pqc_status: status.clone(),
            detail: f.description.chars().take(160).collect(),
        });
        // Keep the worst posture seen on this port.
        if pqc_rank(&status) < pqc_rank(&entry.pqc_status) {
            entry.pqc_status = status;
            entry.detail = f.description.chars().take(160).collect();
        }
    }

    let exposed_services: Vec<ExposedService> = by_port.into_values().collect();
    let worst = exposed_services
        .iter()
        .map(|s| s.pqc_status.as_str())
        .min_by_key(|s| pqc_rank(s))
        .unwrap_or("unknown")
        .to_string();

    target.exposed_services = exposed_services;
    target.pqc_status = worst;
    target.last_scanned = Some(chrono::Utc::now());
    state.store.upsert_target(&tenant, &target);

    Json(target).into_response()
}
