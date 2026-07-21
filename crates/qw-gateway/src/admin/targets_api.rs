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

use qw_scanner::{
    AssetLocation, CryptoAsset, CryptoAssetType, Finding, FindingCategory, FindingSeverity,
    PqcStatus, ScanResult, ScanStatus, ScanTarget, Scanner,
};
use qw_store::{ExposedService, HostContainerRow, TargetRow};

use crate::auth::{tenant_of, AuthContext};
use crate::ssh_inventory::{self, SshAuth};
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
        containers: vec![],
        host_info: None,
        deep_scanned: false,
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
            source: "network".to_string(),
            exposed: true,
        });
        // Keep the worst posture seen on this port.
        if pqc_rank(&status) < pqc_rank(&entry.pqc_status) {
            entry.pqc_status = status;
            entry.detail = f.description.chars().take(160).collect();
        }
    }

    // Replace the network-sourced services; keep anything the deep inventory found.
    let network_services: Vec<ExposedService> = by_port.into_values().collect();
    target.exposed_services = merge_services(&target.exposed_services, "network", network_services);
    target.pqc_status = worst_status(&target.exposed_services);
    target.last_scanned = Some(chrono::Utc::now());
    state.store.upsert_target(&tenant, &target);

    Json(target).into_response()
}

/// Merge a fresh batch of services from one source into an existing list,
/// preserving services discovered by *other* sources. Keyed by (source, port).
fn merge_services(
    existing: &[ExposedService],
    source: &str,
    fresh: Vec<ExposedService>,
) -> Vec<ExposedService> {
    let mut out: Vec<ExposedService> =
        existing.iter().filter(|s| s.source != source).cloned().collect();
    out.extend(fresh);
    out.sort_by_key(|s| (s.port, s.source.clone()));
    out
}

fn worst_status(services: &[ExposedService]) -> String {
    services
        .iter()
        .map(|s| s.pqc_status.as_str())
        .min_by_key(|s| pqc_rank(s))
        .unwrap_or("unknown")
        .to_string()
}

/// Protocols that carry data in cleartext by default. Exposing one on a
/// wildcard address means traffic is readable on the wire (classic capture +
/// harvest-now/decrypt-later), so we can classify it without fingerprinting.
fn is_plaintext_protocol(port: u16) -> bool {
    matches!(
        port,
        21 | 23 | 80 | 3306 | 5432 | 5672 | 6379 | 8000 | 8080 | 9042 | 9092 | 9200 | 11211 | 27017
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeepScanRequest {
    #[serde(default)]
    port: Option<u16>,
    username: String,
    /// Password auth (one of password / private_key is required).
    #[serde(default)]
    password: Option<String>,
    /// OpenSSH private key (PEM). Used transiently, never stored.
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
}

/// POST /api/targets/{id}/deep-scan — log in over SSH and inventory from the
/// inside. Credentials are supplied per-request for the operator's own host and
/// used transiently; they are never persisted on the target row.
pub async fn deep_scan(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
    Json(body): Json<DeepScanRequest>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let Some(mut target) = state.store.get_target(&tenant, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": format!("target '{id}' not found") }))).into_response();
    };

    // Resolve credentials (used transiently; not stored).
    let auth = match (body.password.clone(), body.private_key.clone()) {
        (Some(pw), _) if !pw.is_empty() => SshAuth::Password(pw),
        (_, Some(pem)) if !pem.is_empty() => SshAuth::PrivateKey {
            pem,
            passphrase: body.passphrase.clone(),
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "provide a password or a privateKey" })),
            )
                .into_response()
        }
    };
    if body.username.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "username is required" }))).into_response();
    }

    let port = body.port.unwrap_or(22);
    let inv = match ssh_inventory::inventory(&target.host, port, &body.username, auth).await {
        Ok(inv) => inv,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("deep inventory failed: {e}") })),
            )
                .into_response()
        }
    };

    // Turn discovered listening services into exposed-service rows + findings.
    let mut host_services: Vec<ExposedService> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    for svc in &inv.services {
        let plaintext = is_plaintext_protocol(svc.port);
        let (status, severity, detail) = if svc.exposed && plaintext {
            (
                PqcStatus::ClassicalWeak,
                FindingSeverity::High,
                format!(
                    "{} exposed on all interfaces with no transport encryption - cleartext on the wire (harvest-now/decrypt-later).",
                    svc.service
                ),
            )
        } else if svc.exposed {
            (
                PqcStatus::Unknown,
                FindingSeverity::Low,
                format!("{} reachable from the network; crypto not yet fingerprinted.", svc.service),
            )
        } else {
            (
                PqcStatus::Unknown,
                FindingSeverity::Info,
                format!("{} bound to loopback (internal only) - invisible to a network scan.", svc.service),
            )
        };

        host_services.push(ExposedService {
            port: svc.port,
            service: svc.service.clone(),
            pqc_status: status.to_string(),
            detail: detail.clone(),
            source: "host".to_string(),
            exposed: svc.exposed,
        });

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            category: FindingCategory::MissingPqc,
            severity,
            title: format!("{}:{} {}", target.host, svc.port, svc.service),
            description: detail,
            asset: CryptoAsset {
                id: uuid::Uuid::new_v4().to_string(),
                asset_type: CryptoAssetType::ProtocolEndpoint,
                name: format!("{} ({}:{})", svc.service, target.host, svc.port),
                algorithm: None,
                key_length: None,
                protocol_version: None,
                location: AssetLocation {
                    source_type: "host".to_string(),
                    path: format!("{}:{}", target.host, svc.port),
                    line: None,
                },
                discovered_by: "ssh-inventory".to_string(),
                discovered_at: chrono::Utc::now(),
            },
            remediation: Some(
                "Terminate this endpoint behind the QuantaWatch PQC overlay or issue it a hybrid ML-DSA certificate.".to_string(),
            ),
            pqc_status: status,
            metadata: std::collections::HashMap::from([
                ("exposed".to_string(), svc.exposed.to_string()),
                ("source".to_string(), "ssh-inventory".to_string()),
            ]),
        });
    }

    // Record the synthetic scan so findings flow into the graph/posture pipeline.
    let now = chrono::Utc::now();
    let result = ScanResult {
        scanner_id: "ssh-inventory".to_string(),
        target_id: format!("target:{}", target.id),
        started_at: now,
        completed_at: now,
        findings,
        status: ScanStatus::Completed,
        error: None,
    };
    let scan_target = ScanTarget::network_host(&target.host);
    state.store.record_scan(&tenant, &result, &scan_target);
    let _ = state
        .audit_logger
        .log(
            "system",
            qw_audit::AuditEvent::ScanCompleted {
                scan_id: result.target_id.clone(),
                scanner_id: "ssh-inventory".to_string(),
                target: target.host.clone(),
                finding_count: result.findings.len() as u32,
                status: "deep-inventory".to_string(),
            },
        )
        .await;

    // Merge host-sourced services (keep the network sweep's), record containers.
    target.exposed_services = merge_services(&target.exposed_services, "host", host_services);
    target.containers = inv
        .containers
        .into_iter()
        .map(|c| HostContainerRow {
            name: c.name,
            image: c.image,
            ports: c.ports,
        })
        .collect();
    target.host_info = if inv.host_info.trim().is_empty() {
        None
    } else {
        Some(inv.host_info)
    };
    target.deep_scanned = true;
    target.pqc_status = worst_status(&target.exposed_services);
    target.last_scanned = Some(now);
    state.store.upsert_target(&tenant, &target);

    Json(json!({
        "target": target,
        "servicesFound": result.findings.len(),
    }))
    .into_response()
}
