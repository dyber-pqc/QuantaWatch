//! Multi-framework compliance controls (HTTP). The control set + evaluation
//! live in the shared `qw_cbom::frameworks` module; this handler snapshots the
//! live config into `Signals`, runs it, and serves the results plus the CI gate.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use qw_cbom::frameworks::{all, summarize, Signals};

use crate::config::GatewayConfig;
use crate::state::AppState;

fn signals_from_config(c: &GatewayConfig) -> Signals {
    let ce = &c.crypto_enforcement;
    let dar = &c.scanner.data_at_rest;
    Signals {
        auth_on: c.auth.enabled,
        lockout: c.auth.max_failed_logins > 0,
        idle_timeout: c.auth.idle_timeout_secs > 0,
        enforce_on: ce.enabled,
        enforce_block: ce.enabled && ce.mode.eq_ignore_ascii_case("enforce"),
        at_rest_on: dar.enabled && !dar.stores.is_empty(),
        key_rotation: dar.max_key_age_days > 0,
        tls_scan: c.scanner.tls.enabled,
        target_pqc: !c.crypto_policy.target.is_empty(),
        forbidden_set: !c.crypto_policy.forbidden.is_empty(),
        alerts_on: c.alerts.enabled,
    }
}

/// GET /api/frameworks — one summary per framework.
pub async fn list_frameworks(State(state): State<AppState>) -> impl IntoResponse {
    let s = signals_from_config(&state.config);
    let frameworks: Vec<_> = all(&s).iter().map(summarize).collect();
    Json(json!({
        "note": "Controls are evaluated live against the running configuration. A PASS means \
                 every required control is enforced by the product, not attested on paper.",
        "frameworks": frameworks,
    }))
}

#[derive(Debug, Deserialize)]
pub struct GateQuery {
    #[serde(default)]
    gate: Option<u8>,
}

/// GET /api/frameworks/{id} — full control detail. `?gate=1` returns HTTP 422
/// when any required control is not enforced, so CI can block a regression.
pub async fn get_framework(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<GateQuery>,
) -> impl IntoResponse {
    let s = signals_from_config(&state.config);
    let Some(f) = all(&s).into_iter().find(|f| f.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown framework: {id}") })),
        )
            .into_response();
    };
    let summary = summarize(&f);
    let pass = summary["verdict"] == "PASS";
    let body = json!({
        "id": f.id,
        "name": f.name,
        "description": f.description,
        "verdict": summary["verdict"],
        "summary": summary["summary"],
        "controls": f.controls,
    });
    let gate = q.gate.unwrap_or(0) == 1;
    if gate && !pass {
        (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
    } else {
        (StatusCode::OK, Json(body)).into_response()
    }
}
