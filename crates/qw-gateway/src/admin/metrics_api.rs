//! `GET /metrics` — Prometheus exposition for the gateway itself.
//!
//! Combines the cumulative counters/histogram from [`crate::metrics::Metrics`]
//! with gauges sampled live from [`AppState`] (circuit state, active sessions,
//! posture score, finding counts).

use axum::{extract::State, http::header, response::IntoResponse, Extension};
use qw_scanner::FindingSeverity;

use crate::auth::{tenant_of, AuthContext};
use crate::metrics::{gauge, labelled_gauge};
use crate::resilience::CircuitState;
use crate::state::AppState;

pub async fn get_metrics(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let mut out = state.metrics.render();

    // --- Live gauges -------------------------------------------------------

    gauge(
        &mut out,
        "quantawatch_sessions_active",
        "Currently tracked agent sessions.",
        state.sessions.len(),
    );

    // Circuit breaker state per provider: 0=closed, 1=half-open, 2=open.
    // This is the signal that tells an operator an upstream is being shed.
    out.push_str(
        "# HELP quantawatch_circuit_state Upstream circuit state (0=closed, 1=half_open, 2=open).\n\
         # TYPE quantawatch_circuit_state gauge\n",
    );
    for provider in state.providers.names() {
        let value = match state.resilience.breaker(&provider).state() {
            CircuitState::Closed => 0,
            CircuitState::HalfOpen => 1,
            CircuitState::Open => 2,
        };
        labelled_gauge(
            &mut out,
            "quantawatch_circuit_state",
            "provider",
            &provider,
            value,
        );
    }

    // Posture score for the caller's tenant (the headline number).
    let tenant = tenant_of(&ctx);
    if let Some(posture) = state.posture_cache.read().await.as_ref() {
        gauge(
            &mut out,
            "quantawatch_posture_score",
            "Overall PQC posture score (0-100).",
            posture.overall_score,
        );
    }

    // Open findings by severity. FindingSeverity has no Display impl, so map it
    // explicitly rather than relying on serde's quoted representation.
    let sev_name = |s: &FindingSeverity| match s {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    };
    let findings = state.store.all_findings(&tenant);
    out.push_str(
        "# HELP quantawatch_findings Open crypto findings by severity.\n\
         # TYPE quantawatch_findings gauge\n",
    );
    for sev in ["critical", "high", "medium", "low", "info"] {
        let count = findings
            .iter()
            .filter(|f| sev_name(&f.severity) == sev)
            .count();
        labelled_gauge(&mut out, "quantawatch_findings", "severity", sev, count);
    }

    out.push_str(&format!(
        "# HELP quantawatch_build_info Build info (always 1; version is a label).\n\
         # TYPE quantawatch_build_info gauge\n\
         quantawatch_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}
