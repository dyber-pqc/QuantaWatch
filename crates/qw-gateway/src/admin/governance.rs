//! Crypto-agility governance API.
//!
//! Evaluates the tenant's inventory against the configured [`CryptoPolicy`] and
//! returns a PASS / AT-RISK / FAIL verdict plus an agility score.
//! `GET /api/governance?gate=1` returns HTTP 422 on a FAIL so a CI job can block
//! a regression (a newly-introduced forbidden algorithm, or a missed deadline).
//! A snapshot is recorded on each scan so the agility trend is visible over time.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use qw_cbom::Verdict;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

fn report_for(state: &AppState, tenant: &str) -> qw_cbom::GovernanceReport {
    let findings = state.store.all_findings(tenant);
    qw_cbom::evaluate_governance(&state.config.crypto_policy, &findings, chrono::Utc::now())
}

#[derive(Deserialize)]
pub struct GateQuery {
    pub gate: Option<u8>,
}

/// Current governance report. `?gate=1` -> 422 when the verdict is FAIL.
pub async fn get_governance(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Query(q): Query<GateQuery>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let report = report_for(&state, &tenant);
    let failed = report.verdict == Verdict::Fail;
    let body = Json(json!(report));
    if q.gate.unwrap_or(0) == 1 && failed {
        (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
    } else {
        body.into_response()
    }
}

/// Agility-score trend over time (drift detection).
pub async fn get_governance_history(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let history = state.store.governance_history(&tenant, 100);
    Json(json!({ "history": history, "total": history.len() }))
}

/// Record a governance snapshot for `tenant` (called after each scan). No-op
/// when no policy is configured, so it doesn't clutter the trend with defaults.
pub async fn record_snapshot(state: &AppState, tenant: &str) {
    let p = &state.config.crypto_policy;
    if p.forbidden.is_empty() && p.deprecated.is_empty() && p.target.is_empty() {
        return; // no policy declared
    }
    let report = report_for(state, tenant);
    state.store.record_governance_snapshot(
        tenant,
        &qw_store::GovernanceSnapshot {
            timestamp: chrono::Utc::now(),
            agility_score: report.agility_score,
            compliant: report.compliant,
            deprecated: report.deprecated,
            forbidden: report.forbidden,
            verdict: format!("{:?}", report.verdict).to_lowercase(),
        },
    );
}
