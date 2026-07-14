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
use crate::state::AppState;

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
fn finding_from_record(r: &FindingRecord) -> Finding {
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

    let finding = finding_from_record(&record);

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
