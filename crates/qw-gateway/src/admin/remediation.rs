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
use qw_scanner::{AssetLocation, CryptoAsset, Finding, FindingRecord};

use crate::auth::{tenant_of, AuthContext};
use crate::config::AssetConfig;
use crate::state::AppState;

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
