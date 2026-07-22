use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

use qw_integrations::RemediationOpts;
use qw_scanner::{AssetLocation, CryptoAsset, CryptoAssetType, Finding, FindingRecord, PqcStatus, ScanTarget, Scanner};

use crate::auth::{tenant_of, AuthContext};
use crate::config::AssetConfig;
use crate::state::AppState;

/// Trailing `:port` of a location like `host:443`, if present.
fn port_of(location: &str) -> Option<u16> {
    location.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
}

/// Worse posture ranks lower — used to pick the worst finding on a port and to
/// tell whether a re-verify improved things.
fn pqc_rank(s: &PqcStatus) -> u8 {
    match s {
        PqcStatus::ClassicalWeak => 0,
        PqcStatus::ClassicalSecure => 1,
        PqcStatus::Unknown => 2,
        PqcStatus::Hybrid => 3,
        PqcStatus::PqcReady => 4,
    }
}

/// Reduce an address/location to its host: strip scheme, path, and port.
fn host_of(s: &str) -> &str {
    let s = s.rsplit("://").next().unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    s.split(':').next().unwrap_or(s)
}

/// Resolve the business context for a finding by matching its location against
/// the declared assets (exact address, or same host). Unmatched findings get
/// the default (unknown) context rather than being dropped.
fn business_context_for(assets: &[AssetConfig], location: &str) -> qw_cbom::BusinessContext {
    let loc_host = host_of(location);
    for a in assets {
        let a_host = host_of(&a.address);
        let matched = a.address == location || (!a_host.is_empty() && a_host == loc_host);
        if matched {
            return qw_cbom::BusinessContext {
                application: a.application.clone(),
                criticality: a
                    .criticality
                    .as_deref()
                    .map(qw_cbom::Criticality::parse)
                    .unwrap_or(qw_cbom::Criticality::Unknown),
                owner: a.owner.clone(),
                environment: Some(a.environment.clone()),
                data_classification: a.data_classification.clone(),
            };
        }
    }
    qw_cbom::BusinessContext::default()
}

/// Business-prioritized migration work list: every finding's plan, tagged with
/// its business context and scored by crypto urgency × business criticality, so
/// a P1 on the checkout service outranks a P0 on a dev sandbox.
pub async fn get_risk(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let assets = &state.config.assets;

    let mut ranked: Vec<(u32, serde_json::Value)> = state
        .store
        .all_findings(&tenant)
        .iter()
        .filter_map(|f| {
            let plan = qw_cbom::plan_migration(f)?;
            let context = business_context_for(assets, &f.location);
            let score = qw_cbom::business_risk_score(plan.priority, context.criticality);
            Some((
                score,
                json!({
                    "findingId": f.id,
                    "title": plan.title,
                    "priority": plan.priority,
                    "targetAlgorithm": plan.target_algorithm,
                    "location": f.location,
                    "businessContext": context,
                    "businessRiskScore": score,
                }),
            ))
        })
        .collect();

    // Most business-risk first; ties keep discovery order (stable sort).
    ranked.sort_by(|a, b| b.0.cmp(&a.0));
    let actions: Vec<serde_json::Value> = ranked.into_iter().map(|(_, v)| v).collect();

    let mapped = actions
        .iter()
        .filter(|a| a["businessContext"]["application"].is_string())
        .count();
    Json(json!({
        "actions": actions,
        "total": actions.len(),
        "mappedToApplications": mapped,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediateRequest {
    integration_id: String,
    project: Option<String>,
    assignee: Option<String>,
    priority: Option<String>,
}

/// Reconstruct a scanner `Finding` from a stored `FindingRecord` so it can be
/// handed to an integration's `create_remediation`.
pub(crate) fn finding_from_record(r: &FindingRecord) -> Finding {
    Finding {
        id: r.id.clone(),
        category: r.category.clone(),
        severity: r.severity.clone(),
        title: r.title.clone(),
        description: r.description.clone(),
        asset: CryptoAsset {
            id: uuid::Uuid::new_v4().to_string(),
            asset_type: r.asset_type.clone(),
            name: r.title.clone(),
            algorithm: r.algorithm.clone(),
            key_length: None,
            protocol_version: None,
            location: AssetLocation {
                source_type: "finding".to_string(),
                path: r.location.clone(),
                line: None,
            },
            discovered_by: "store".to_string(),
            discovered_at: r.created_at,
        },
        remediation: r.remediation.clone(),
        pqc_status: r.pqc_status.clone(),
        metadata: HashMap::new(),
    }
}

/// Create a remediation ticket for a stored finding via the requested integration.
pub async fn remediate(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(finding_id): Path<String>,
    Json(body): Json<RemediateRequest>,
) -> impl IntoResponse {
    // Filing a ticket/PR is an outbound call. The migration *plan* itself stays
    // available offline via GET /api/findings/{id}/plan.
    if state.config.air_gapped {
        return crate::admin::integrations_api::air_gapped_refusal();
    }
    let tenant = tenant_of(&ctx);
    let record = match state.store.get_finding(&tenant, &finding_id) {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": format!("Finding '{}' not found", finding_id),
                })),
            )
                .into_response();
        }
    };

    let integration = match state.integration_registry.get(&body.integration_id) {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": format!("Integration '{}' not found", body.integration_id),
                })),
            )
                .into_response();
        }
    };

    // Closed-loop: attach the concrete PQC migration plan for THIS finding so
    // the opened PR / ticket carries the specific fix (target algorithm, steps,
    // proposed patch) instead of a generic recommendation.
    let mut finding = finding_from_record(&record);
    if let Some(plan) = qw_cbom::plan_migration(&record) {
        let mut body = qw_cbom::plan_to_markdown(&plan);
        // Lead with the business context so the PR reviewer sees *what this
        // protects* before the crypto detail.
        let context = business_context_for(&state.config.assets, &record.location);
        if context.application.is_some() {
            body = format!("**Affects:** {}\n\n{}", context.summary(), body);
        }
        finding.remediation = Some(body);
    }

    let opts = RemediationOpts {
        project: body.project.clone(),
        assignee: body.assignee.clone(),
        priority: body.priority.clone(),
        ..RemediationOpts::default()
    };

    match integration.create_remediation(&finding, &opts).await {
        Ok(ticket) => {
            state.store.record_remediation(&tenant, &ticket);
            let _ = state
                .audit_logger
                .log(
                    "system",
                    qw_audit::AuditEvent::IntegrationSync {
                        integration_id: body.integration_id.clone(),
                        action: "create_remediation".to_string(),
                        detail: ticket.external_id.clone(),
                    },
                )
                .await;
            Json(ticket).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": e.to_string(),
            })),
        )
            .into_response(),
    }
}

/// Re-verify a finding by actively re-checking its underlying asset, closing the
/// loop after a fix. For a network endpoint (host:port) this re-runs the network
/// scanner and reports whether the live posture improved — updating the stored
/// finding so a resolved item drops out of the work list. Findings that can't be
/// re-checked from here (source code, dependencies, host firmware) return
/// `verifiable:false` with guidance to re-run the relevant scanner.
pub async fn verify_finding(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(finding_id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let Some(mut record) = state.store.get_finding(&tenant, &finding_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("Finding '{finding_id}' not found") })),
        )
            .into_response();
    };

    let location = record.location.clone();
    let port = port_of(&location);
    let host = host_of(&location).to_string();
    let network_checkable = port.is_some()
        && !host.is_empty()
        && matches!(
            record.asset_type,
            CryptoAssetType::TlsConnection
                | CryptoAssetType::ProtocolEndpoint
                | CryptoAssetType::Certificate
        );

    if !network_checkable {
        // e.g. a code finding or firmware component — the gateway can't reach in
        // to re-test it; point at the scan that would refresh it.
        let how = match record.asset_type {
            CryptoAssetType::CryptoLibrary => {
                "Re-scan the code repository / dependencies (Scans → run, or the connector) to confirm this fix."
            }
            _ => "Re-run the host agent or the relevant connector scan to refresh this finding.",
        };
        return Json(json!({
            "verifiable": false,
            "before": record.pqc_status,
            "reason": "This finding isn't an active network endpoint the gateway can re-probe.",
            "guidance": how,
        }))
        .into_response();
    }

    // Actively re-probe the endpoint's host with the network scanner (a declared
    // finding is authorized to re-check). It port-scans and fingerprints
    // TLS/SSH/RDP just like the Estate sweep.
    let scanner = qw_scanner::scanners::network::NetworkScanner::new(
        qw_scanner::NetworkScannerConfig {
            enabled: true,
            connect_timeout_ms: 1500,
            ports: qw_scanner::NetworkScannerConfig::default().ports,
            targets: vec![],
        },
    );
    let result = match scanner.scan(&ScanTarget::network_host(&host)).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("re-check failed: {e}") })),
            )
                .into_response()
        }
    };

    let before = record.pqc_status.clone();
    // Worst fresh posture seen on the same port. `None` means nothing crypto-
    // relevant answered on that port during the re-check — which could be a
    // removed service OR simply an unreachable host. We must NOT treat that as
    // "fixed": a connection failure isn't a resolution, and an overlay fix lives
    // on a *different* port so the original endpoint stays classical anyway.
    let fresh: Option<PqcStatus> = result
        .findings
        .iter()
        .filter(|f| port_of(&f.asset.location.path) == port)
        .map(|f| f.pqc_status.clone())
        .min_by_key(pqc_rank);

    let (after, resolved, improved, detail) = match fresh {
        Some(after) => {
            let resolved = matches!(after, PqcStatus::Hybrid | PqcStatus::PqcReady);
            let improved = pqc_rank(&after) > pqc_rank(&before);
            let detail = if resolved {
                format!("{location} now negotiates a post-quantum (hybrid) channel.")
            } else if improved {
                format!("{location} improved from {before} to {after}, but isn't post-quantum yet.")
            } else {
                format!("{location} still reports {after} — the fix isn't live on this endpoint yet. (An overlay fix runs on a separate port; point clients there.)")
            };
            // Persist the fresh posture so a resolved finding leaves the list.
            record.pqc_status = after.clone();
            state.store.update_finding(&tenant, &record);
            (after, resolved, improved, detail)
        }
        None => (
            before.clone(),
            false,
            false,
            format!(
                "Nothing answered on port {} during the re-check — the service is closed, moved, or unreachable, so the fix couldn't be confirmed live.",
                port.unwrap_or(0)
            ),
        ),
    };

    let _ = state
        .audit_logger
        .log(
            "system",
            qw_audit::AuditEvent::ScanCompleted {
                scan_id: format!("verify:{finding_id}"),
                scanner_id: "verify".to_string(),
                target: location.clone(),
                finding_count: result.findings.len() as u32,
                status: if resolved { "resolved" } else if improved { "improved" } else { "unchanged" }.to_string(),
            },
        )
        .await;

    // Refresh the attack-path graph so a fixed endpoint stops showing as a path.
    if resolved || improved {
        crate::admin::graph::snapshot_and_alert(&state, &tenant).await;
    }

    Json(json!({
        "verifiable": true,
        "resolved": resolved,
        "improved": improved,
        "before": before,
        "after": after,
        "port": port,
        "detail": detail,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingStatusRequest {
    /// "open" | "acknowledged" | "suppressed".
    status: String,
    #[serde(default)]
    note: Option<String>,
}

/// Triage a finding: acknowledge (seen / accepted risk) or suppress (false
/// positive / won't-fix). A suppressed finding leaves the work list and the
/// attack-path graph but is retained for the audit trail; reopen with "open".
pub async fn set_finding_status(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(finding_id): Path<String>,
    Json(body): Json<FindingStatusRequest>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let status = match body.status.as_str() {
        "open" => qw_scanner::FindingStatus::Open,
        "acknowledged" => qw_scanner::FindingStatus::Acknowledged,
        "suppressed" => qw_scanner::FindingStatus::Suppressed,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "status must be open | acknowledged | suppressed" })),
            )
                .into_response()
        }
    };
    match state
        .store
        .set_finding_status(&tenant, &finding_id, status, body.note.clone())
    {
        Some(rec) => {
            // A suppression removes a path/plan; refresh the graph so it drops.
            crate::admin::graph::snapshot_and_alert(&state, &tenant).await;
            Json(json!({ "id": rec.id, "status": rec.status, "note": rec.note })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("Finding '{finding_id}' not found") })),
        )
            .into_response(),
    }
}

/// Return the concrete PQC migration plan for a single finding (without filing
/// anything) — the target algorithm, rationale, steps, and a proposed patch.
pub async fn get_migration_plan(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(finding_id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    match state.store.get_finding(&tenant, &finding_id) {
        Some(record) => match qw_cbom::plan_migration(&record) {
            Some(plan) => {
                let markdown = qw_cbom::plan_to_markdown(&plan);
                Json(json!({ "plan": plan, "markdown": markdown })).into_response()
            }
            None => Json(json!({
                "plan": serde_json::Value::Null,
                "reason": "finding is already PQC-ready or hybrid",
            }))
            .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("Finding '{}' not found", finding_id) })),
        )
            .into_response(),
    }
}

/// Generate migration plans for every open finding in the tenant, most-urgent
/// first, with a priority rollup for the dashboard.
pub async fn list_migration_plans(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let findings = state.store.all_findings(&tenant);
    let plans = qw_cbom::plan_all(&findings);
    let count = |p: qw_cbom::MigrationPriority| plans.iter().filter(|x| x.priority == p).count();
    Json(json!({
        "plans": plans,
        "total": plans.len(),
        "byPriority": {
            "p0": count(qw_cbom::MigrationPriority::P0),
            "p1": count(qw_cbom::MigrationPriority::P1),
            "p2": count(qw_cbom::MigrationPriority::P2),
        },
    }))
}

/// Reconcile the status of every open remediation for `tenant` against its
/// integration (PR merged? ticket resolved?). Returns how many changed.
pub async fn sync_ticket_status(state: &AppState, tenant: &str) -> usize {
    let mut changed = 0;
    for mut ticket in state.store.list_remediations(tenant) {
        if matches!(
            ticket.status,
            qw_integrations::TicketStatus::Resolved | qw_integrations::TicketStatus::Closed
        ) {
            continue; // terminal
        }
        let Some(integration) = state.integration_registry.get(&ticket.integration_id) else {
            continue;
        };
        if let Ok(new_status) = integration.remediation_status(&ticket.external_id).await {
            if new_status != ticket.status && new_status != qw_integrations::TicketStatus::Unknown {
                let was = ticket.status.clone();
                ticket.status = new_status.clone();
                ticket.updated_at = chrono::Utc::now();
                state.store.record_remediation(tenant, &ticket);
                changed += 1;
                if matches!(new_status, qw_integrations::TicketStatus::Resolved) {
                    let mut ev = crate::alerts::AlertEvent::new(
                        "remediation_resolved",
                        crate::alerts::AlertSeverity::Info,
                        "Remediation resolved",
                        format!(
                            "Ticket {} was resolved/merged (was {:?}).",
                            ticket.external_id, was
                        ),
                    );
                    ev.metadata
                        .insert("ticket".into(), ticket.external_id.clone());
                    state.alert_manager.fire(tenant, ev).await;
                }
            }
        }
    }
    if changed > 0 {
        tracing::info!(tenant, changed, "remediation ticket status reconciled");
    }
    changed
}

pub async fn sync_remediations(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let changed = sync_ticket_status(&state, &tenant).await;
    Json(json!({ "changed": changed }))
}

/// List all recorded remediation tickets, newest first.
pub async fn list_remediations(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let remediations = state.store.list_remediations(&tenant);
    let total = remediations.len();
    Json(json!({
        "remediations": remediations,
        "total": total,
    }))
}
