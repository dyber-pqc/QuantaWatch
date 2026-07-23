//! SOC2 controls report (HTTP). The control set + evaluation live in the shared
//! `qw_cbom::soc2` module; this handler snapshots the live config into
//! `Soc2Inputs`, runs it, and serializes the result.

use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use qw_cbom::soc2::{assess, Soc2Inputs};

use crate::config::GatewayConfig;
use crate::state::AppState;

fn inputs_from(cfg: &GatewayConfig) -> Soc2Inputs {
    let auth = &cfg.auth;
    Soc2Inputs {
        auth_enabled: auth.enabled,
        max_failed_logins: auth.max_failed_logins,
        lockout_secs: auth.lockout_secs,
        session_ttl_secs: auth.session_ttl_secs,
        idle_timeout_secs: auth.idle_timeout_secs,
        sso_enabled: auth.oidc.is_some(),
        custom_roles: !auth.roles.is_empty(),
        tls_scanner_enabled: cfg.scanner.tls.enabled,
        alerts_enabled: cfg.alerts.enabled,
        shared_identity: cfg.identity.seed_env.is_some(),
    }
}

/// GET /api/soc2 — the live controls report.
pub async fn get_soc2_report(State(state): State<AppState>) -> impl IntoResponse {
    let report = assess(&inputs_from(&state.config));
    Json(json!({
        "framework": "SOC2 (Trust Services Criteria)",
        "note": "Status is evaluated against the running configuration. \
                 'configurable'/'manual' controls are supported by the product but depend on \
                 how it is deployed or on organizational process.",
        "summary": {
            "total": report.controls.len(),
            "enforced": report.enforced,
            "partial": report.partial,
            "configurable": report.configurable,
            "manual": report.manual,
        },
        "controls": report.controls,
    }))
}
