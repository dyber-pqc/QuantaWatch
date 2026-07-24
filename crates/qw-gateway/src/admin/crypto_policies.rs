//! Crypto-agility policy engine — the "clicks not code" surface.
//!
//! Evaluates the configured (or default) crypto-agility policies against the
//! live inventory, reports each policy's status with **drift** vs the last
//! baseline, and **enforces** a policy by opening a remediation PR/ticket per
//! violating asset through the connectors. Every enforcement is written to the
//! signed audit log.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;

use qw_cbom::{AssetContext, CryptoAgilityPolicy, PolicyResult};
use qw_integrations::RemediationOpts;
use qw_store::PolicySnapshotRow;

use crate::admin::remediation::finding_from_record;
use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

/// The active policy set: config-declared, or a built-in CNSA-2.0 default set.
fn policies_for(state: &AppState) -> Vec<CryptoAgilityPolicy> {
    if state.config.crypto_policies.is_empty() {
        qw_cbom::default_policies()
    } else {
        state.config.crypto_policies.clone()
    }
}

/// Map the store's asset rows into the engine's lightweight context.
fn asset_contexts(state: &AppState, tenant: &str) -> Vec<AssetContext> {
    state
        .store
        .list_assets(tenant)
        .into_iter()
        .map(|a| AssetContext {
            address: a.address,
            kind: a.kind,
            environment: a.environment,
            tags: a.tags,
        })
        .collect()
}

fn evaluate(state: &AppState, tenant: &str) -> Vec<(CryptoAgilityPolicy, PolicyResult)> {
    let policies = policies_for(state);
    let findings = state.store.all_findings(tenant);
    let assets = asset_contexts(state, tenant);
    let now = chrono::Utc::now();
    policies
        .into_iter()
        .map(|p| {
            let r = qw_cbom::evaluate_policy(&p, &findings, &assets, now);
            (p, r)
        })
        .collect()
}

/// Drift of `r` vs the last stored baseline (read-only; does not update it).
fn drift(state: &AppState, tenant: &str, r: &PolicyResult) -> serde_json::Value {
    let current: HashSet<String> = r.fingerprints().into_iter().collect();
    let base = state.store.latest_policy_snapshot(tenant, &r.id);
    let (baseline, base_status): (HashSet<String>, Option<String>) = match base {
        Some(s) => (s.fingerprints.into_iter().collect(), Some(s.status)),
        None => (HashSet::new(), None),
    };
    let new: Vec<&String> = current.difference(&baseline).collect();
    let resolved: Vec<&String> = baseline.difference(&current).collect();
    // A regression: was clean at the last baseline, is violated now.
    let regressed = base_status.as_deref() == Some("compliant") && r.status == "violated";
    json!({
        "new": new,
        "resolved": resolved,
        "regressed": regressed,
        "baselineExists": base_status.is_some(),
    })
}

fn with_drift(state: &AppState, tenant: &str, r: &PolicyResult) -> serde_json::Value {
    let mut v = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
    v["drift"] = drift(state, tenant, r);
    v
}

/// GET /api/crypto-policies — status board with drift.
pub async fn get_policies(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let evald = evaluate(&state, &tenant);
    let mut policies = Vec::new();
    let (mut violated, mut critical) = (0usize, 0usize);
    for (_p, r) in &evald {
        if r.status == "violated" {
            violated += 1;
            if r.severity == "critical" {
                critical += r.violation_count;
            }
        }
        policies.push(with_drift(&state, &tenant, r));
    }
    Json(json!({
        "policies": policies,
        "total": evald.len(),
        "violated": violated,
        "compliant": evald.len() - violated,
        "criticalViolations": critical,
    }))
}

/// GET /api/crypto-policies/{id} — detail with a migration plan per violation.
pub async fn get_policy(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let evald = evaluate(&state, &tenant);
    let Some((_p, r)) = evald.iter().find(|(p, _)| p.id == id) else {
        return not_found(&id);
    };

    let violations: Vec<serde_json::Value> = r
        .violations
        .iter()
        .map(|v| {
            let plan = state
                .store
                .get_finding(&tenant, &v.finding_id)
                .and_then(|rec| qw_cbom::plan_migration(&rec));
            let mut vv = serde_json::to_value(v).unwrap_or_else(|_| json!({}));
            vv["plan"] = plan
                .map(|p| serde_json::to_value(p).unwrap_or(json!(null)))
                .unwrap_or(json!(null));
            vv
        })
        .collect();

    let mut out = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
    out["violations"] = json!(violations);
    out["drift"] = drift(&state, &tenant, r);
    Json(out).into_response()
}

/// POST /api/crypto-policies/evaluate — re-evaluate and update the drift baseline.
pub async fn evaluate_now(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let evald = evaluate(&state, &tenant);
    let mut policies = Vec::new();
    for (_p, r) in &evald {
        // Compute drift vs the OLD baseline, then advance the baseline.
        let entry = with_drift(&state, &tenant, r);
        state.store.record_policy_snapshot(
            &tenant,
            &r.id,
            &PolicySnapshotRow {
                status: r.status.clone(),
                fingerprints: r.fingerprints(),
                updated_at: chrono::Utc::now(),
            },
        );
        policies.push(entry);
    }
    Json(json!({ "policies": policies, "evaluated": evald.len() }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforceRequest {
    integration_id: Option<String>,
    project: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

/// POST /api/crypto-policies/{id}/enforce — act on every violation via the
/// policy's action (open_pr / create_ticket through a connector, or alert).
pub async fn enforce_policy(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
    Json(body): Json<EnforceRequest>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let evald = evaluate(&state, &tenant);
    let Some((policy, r)) = evald.iter().find(|(p, _)| p.id == id) else {
        return not_found(&id);
    };

    if r.violations.is_empty() {
        return Json(json!({
            "policyId": id, "action": policy.action, "enforced": 0,
            "message": "policy is compliant — nothing to enforce",
        }))
        .into_response();
    }

    let action = policy.action.as_str();

    // The "alert" action needs no connector: record it to the signed audit log.
    if action == "alert" {
        for v in &r.violations {
            audit_enforced(&state, policy, &v.location, "alert", "alerted").await;
        }
        return Json(json!({
            "policyId": id, "action": "alert", "enforced": r.violations.len(),
        }))
        .into_response();
    }

    // open_pr / create_ticket: filing is an outbound call.
    if state.config.air_gapped {
        return crate::admin::integrations_api::air_gapped_refusal();
    }
    let Some(integration_id) = body.integration_id.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "integrationId is required for this policy's action" })),
        )
            .into_response();
    };
    let integration = match state.integration_registry.get(&integration_id) {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("integration '{integration_id}' not found") })),
            )
                .into_response()
        }
    };

    let mut tickets = Vec::new();
    let mut errors = Vec::new();
    for v in &r.violations {
        if body.dry_run {
            tickets.push(json!({ "resource": v.location, "wouldOpen": true }));
            continue;
        }
        let Some(rec) = state.store.get_finding(&tenant, &v.finding_id) else {
            continue;
        };
        let mut finding = finding_from_record(&rec);
        if let Some(plan) = qw_cbom::plan_migration(&rec) {
            finding.remediation = Some(qw_cbom::plan_to_markdown(&plan));
        }
        let opts = RemediationOpts {
            project: body.project.clone(),
            ..RemediationOpts::default()
        };
        match integration.create_remediation(&finding, &opts).await {
            Ok(ticket) => {
                state.store.record_remediation(&tenant, &ticket);
                audit_enforced(
                    &state,
                    policy,
                    &v.location,
                    action,
                    &format!("ticket:{}", ticket.external_id),
                )
                .await;
                tickets.push(serde_json::to_value(&ticket).unwrap_or_else(|_| json!({})));
            }
            Err(e) => errors.push(json!({ "resource": v.location, "error": e.to_string() })),
        }
    }

    Json(json!({
        "policyId": id,
        "action": action,
        "enforced": tickets.len(),
        "tickets": tickets,
        "errors": errors,
        "dryRun": body.dry_run,
    }))
    .into_response()
}

async fn audit_enforced(
    state: &AppState,
    policy: &CryptoAgilityPolicy,
    resource: &str,
    action: &str,
    outcome: &str,
) {
    let _ = state
        .audit_logger
        .log(
            "system",
            qw_audit::AuditEvent::AgilityPolicyEnforced {
                policy_id: policy.id.clone(),
                severity: policy.severity.clone(),
                resource: resource.to_string(),
                action: action.to_string(),
                outcome: outcome.to_string(),
            },
        )
        .await;
}

fn not_found(id: &str) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": format!("crypto policy '{id}' not found") })),
    )
        .into_response()
}
