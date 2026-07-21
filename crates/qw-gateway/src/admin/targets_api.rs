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
    // Drop any PQC-overlay routes protecting this target so they don't re-bind.
    for r in state.store.list_all_overlay_routes() {
        if r.target_id.as_deref() == Some(id.as_str()) {
            state.overlay.remove_route(&r.id);
        }
    }
    state.store.delete_overlay_routes_for_target(&tenant, &id);
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
            protected_listen: None,
            cert_id: None,
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

    // Re-fold this host into the attack-path graph (and alert on new paths).
    crate::admin::graph::snapshot_and_alert(&state, &tenant).await;

    Json(target).into_response()
}

/// Merge a fresh batch of services from one source into an existing list,
/// preserving services discovered by *other* sources. Keyed by (source, port).
fn merge_services(
    existing: &[ExposedService],
    source: &str,
    mut fresh: Vec<ExposedService>,
) -> Vec<ExposedService> {
    // Carry any protection markers (overlay/cert applied earlier) forward onto
    // the freshly-scanned rows so a re-scan doesn't drop "already protected".
    for f in fresh.iter_mut() {
        if let Some(prev) = existing.iter().find(|s| s.port == f.port) {
            if f.protected_listen.is_none() {
                f.protected_listen = prev.protected_listen.clone();
            }
            if f.cert_id.is_none() {
                f.cert_id = prev.cert_id.clone();
            }
        }
    }
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
            protected_listen: None,
            cert_id: None,
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

    // Fold the newly-discovered host subgraph into the attack-path graph.
    crate::admin::graph::snapshot_and_alert(&state, &tenant).await;

    Json(json!({
        "target": target,
        "servicesFound": result.findings.len(),
    }))
    .into_response()
}

// ---- One-click remediation: finding -> fix (overlay / PQC cert) ----

fn find_service<'a>(target: &'a TargetRow, port: u16) -> Option<&'a ExposedService> {
    target.exposed_services.iter().find(|s| s.port == port)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectRequest {
    /// "hybrid" (offer PQC, allow classical) | "pqc-only" (drop classical).
    #[serde(default)]
    mode: Option<String>,
    /// Re-encrypt the upstream leg with TLS (for a TLS service) or forward
    /// plaintext to a trusted local upstream.
    #[serde(default)]
    upstream_tls: Option<bool>,
    /// Override the client-facing listen address; defaults to 0.0.0.0:0 (the OS
    /// picks a free port).
    #[serde(default)]
    listen: Option<String>,
}

/// POST /api/targets/{id}/services/{port}/protect — front a discovered service
/// with the hybrid-PQC overlay in one click. Binds a new PQC-terminating
/// listener that forwards to `host:port`; clients then connect to the returned
/// listen address over an X25519MLKEM768 channel.
pub async fn protect_service(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path((id, port)): Path<(String, u16)>,
    body: Option<Json<ProtectRequest>>,
) -> impl IntoResponse {
    let body = body
        .map(|b| b.0)
        .unwrap_or(ProtectRequest { mode: None, upstream_tls: None, listen: None });
    let tenant = tenant_of(&ctx);
    let Some(mut target) = state.store.get_target(&tenant, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": format!("target '{id}' not found") }))).into_response();
    };
    let Some(svc) = find_service(&target, port) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": format!("no service on port {port}") }))).into_response();
    };
    // If the raw service speaks TLS (https/ssh-alt/etc.), re-encrypt upstream by
    // default so the internal leg stays protected too.
    let default_upstream_tls = matches!(svc.service.as_str(), "https" | "https-alt" | "imaps" | "ldaps" | "smtps" | "pop3s" | "dns-over-tls");
    let upstream = format!("{}:{}", target.host, port);
    let mode = body.mode.unwrap_or_else(|| "hybrid".to_string());
    let listen = body.listen.unwrap_or_else(|| "0.0.0.0:0".to_string());
    let route_id = format!("target:{}:{}", target.id, port);

    match state
        .overlay
        .add_route(&route_id, &listen, &upstream, body.upstream_tls.unwrap_or(default_upstream_tls), &mode)
        .await
    {
        Ok(stats) => {
            let listen_addr = stats.listen.clone();
            for s in target.exposed_services.iter_mut() {
                if s.port == port {
                    s.protected_listen = Some(listen_addr.clone());
                }
            }
            state.store.upsert_target(&tenant, &target);
            // Persist the route so it survives a gateway restart.
            state.store.record_overlay_route(
                &tenant,
                &qw_store::OverlayRouteRow {
                    id: route_id.clone(),
                    target_id: Some(target.id.clone()),
                    listen: listen_addr.clone(),
                    upstream: upstream.clone(),
                    upstream_tls: body.upstream_tls.unwrap_or(default_upstream_tls),
                    mode: mode.clone(),
                    created_at: chrono::Utc::now(),
                },
            );
            (
                StatusCode::OK,
                Json(json!({
                    "target": target,
                    "protectedListen": listen_addr,
                    "upstream": upstream,
                    "mode": mode,
                    "hybridGroup": "X25519MLKEM768",
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("could not protect service: {e}") })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCertRequest {
    #[serde(default)]
    validity_days: Option<u32>,
    /// "hybrid" (default) | "classical".
    #[serde(default)]
    key_type: Option<String>,
}

/// POST /api/targets/{id}/services/{port}/issue-cert — mint a hybrid ML-DSA
/// certificate for a discovered service from the internal CA, in one click.
pub async fn issue_service_cert(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path((id, port)): Path<(String, u16)>,
    body: Option<Json<IssueCertRequest>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let body = body.map(|b| b.0).unwrap_or(IssueCertRequest { validity_days: None, key_type: None });
    let Some(mut target) = state.store.get_target(&tenant, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": format!("target '{id}' not found") }))).into_response();
    };
    if find_service(&target, port).is_none() {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": format!("no service on port {port}") }))).into_response();
    }
    let Some(ca) = &state.ca else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "internal PKI/CA is not configured (set pki.enabled)" })),
        )
            .into_response();
    };

    let host = target.host.clone();
    let hybrid = body.key_type.as_deref() != Some("classical");
    let days = body.validity_days.unwrap_or(state.config.pki.default_validity_days);

    match ca.issue(&host, &[host.clone()], days, hybrid) {
        Ok((row, key_pem)) => {
            state.store.record_certificate(&tenant, &row);
            for s in target.exposed_services.iter_mut() {
                if s.port == port {
                    s.cert_id = Some(row.id.clone());
                }
            }
            state.store.upsert_target(&tenant, &target);
            let _ = state
                .audit_logger
                .log(
                    "system",
                    qw_audit::AuditEvent::CertificateIssued {
                        cert_id: row.id.clone(),
                        subject: row.subject.clone(),
                        key_type: row.key_type.clone(),
                        serial: row.serial.clone(),
                        not_after: row.not_after.to_rfc3339(),
                        renewed: false,
                    },
                )
                .await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "target": target,
                    "certificate": {
                        "id": row.id,
                        "subject": row.subject,
                        "sans": row.sans,
                        "serial": row.serial,
                        "keyType": row.key_type,
                        "notAfter": row.not_after,
                        "caFingerprint": row.ca_fingerprint,
                        "pqcStatus": row.pqc_status,
                    },
                    "keyPem": key_pem, // returned once, never stored
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("cert issuance failed: {e}") })),
        )
            .into_response(),
    }
}
