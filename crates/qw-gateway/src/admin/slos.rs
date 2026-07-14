//! Posture SLOs / policy-as-code.
//!
//! Declarative objectives (posture ≥ N, critical paths ≤ N, compliance ≥ N%)
//! evaluated per tenant. `GET /api/slos?gate=1` returns HTTP 422 if a `fail`
//! objective is breached — a one-line CI gate. Breaches also raise alerts.

use std::collections::HashMap;

use axum::{extract::{State, Query}, response::IntoResponse, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use qw_cbom::{ComplianceEngine, PostureEngine};

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SloResult {
    pub name: String,
    pub metric: String,
    pub operator: String,
    pub threshold: f64,
    pub actual: f64,
    pub pass: bool,
    pub action: String,
}

/// Evaluate all SLOs that apply to `tenant`.
pub async fn evaluate(state: &AppState, tenant: &str) -> Vec<SloResult> {
    // Compute the three metrics once.
    let providers: Vec<_> = state.provider_crypto.iter().map(|e| e.value().clone()).collect();
    let posture = {
        let cache = state.posture_cache.read().await;
        cache.as_ref().map(|p| p.overall_score).unwrap_or_else(|| PostureEngine::summarize(&[], &providers).overall_score)
    };
    let graph = crate::admin::graph::build_graph(state, tenant, &HashMap::new());
    let critical_paths = graph.paths.iter().filter(|p| p.severity == "critical").count() as f64;
    let compliance = ComplianceEngine::assess(&state.store.all_findings(tenant)).overall_compliance_pct;

    let metric_value = |m: &str| match m {
        "posture" => posture,
        "critical_paths" => critical_paths,
        "compliance" => compliance,
        _ => 0.0,
    };

    state.config.slos.iter()
        .filter(|s| s.tenant.as_deref().map(|t| t == tenant).unwrap_or(true))
        .map(|s| {
            let actual = metric_value(&s.metric);
            let pass = match s.operator.as_str() {
                "lte" => actual <= s.threshold,
                _ => actual >= s.threshold,
            };
            SloResult {
                name: s.name.clone(), metric: s.metric.clone(), operator: s.operator.clone(),
                threshold: s.threshold, actual: (actual * 10.0).round() / 10.0, pass, action: s.action.clone(),
            }
        })
        .collect()
}

#[derive(Deserialize)]
pub struct SloQuery {
    pub gate: Option<u8>,
}

pub async fn get_slos(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Query(q): Query<SloQuery>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let results = evaluate(&state, &tenant).await;
    let all_pass = results.iter().all(|r| r.pass);
    let gate_breach = results.iter().any(|r| !r.pass && r.action == "fail");

    let body = json!({
        "slos": results,
        "allPass": all_pass,
        "gateBreach": gate_breach,
    });
    // CI gate: fail the request when a `fail` SLO is breached.
    if q.gate.unwrap_or(0) == 1 && gate_breach {
        (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
    } else {
        Json(body).into_response()
    }
}

pub async fn get_slo_history(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let history = state.store.slo_history(&tenant, 100);
    Json(json!({ "history": history, "total": history.len() }))
}

/// Evaluate SLOs after a scan, record a trend snapshot, and raise alerts on breaches.
pub async fn check_and_alert(state: &AppState, tenant: &str) {
    let results = evaluate(state, tenant).await;
    if results.is_empty() {
        return;
    }
    let failing = results.iter().filter(|r| !r.pass).count() as u32;
    let gate_breach = results.iter().any(|r| !r.pass && r.action == "fail");
    state.store.record_slo_snapshot(tenant, &qw_store::SloSnapshot {
        timestamp: chrono::Utc::now(),
        total: results.len() as u32,
        passing: results.len() as u32 - failing,
        failing,
        gate_breach,
    });

    for r in results.into_iter().filter(|r| !r.pass) {
        let sev = if r.action == "fail" { crate::alerts::AlertSeverity::Critical } else { crate::alerts::AlertSeverity::Warning };
        let mut ev = crate::alerts::AlertEvent::new(
            "slo_breach", sev,
            format!("SLO breached: {}", r.name),
            format!("{} {} {} — actual {}.", r.metric, r.operator, r.threshold, r.actual),
        );
        ev.metadata.insert("slo".into(), r.name.clone());
        state.alert_manager.fire(tenant, ev).await;
    }
}
