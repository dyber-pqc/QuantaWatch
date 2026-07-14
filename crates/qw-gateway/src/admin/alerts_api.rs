//! Alerts admin API.

use axum::{extract::{State, Query}, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;

use crate::alerts::{AlertEvent, AlertSeverity};
use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
}

pub async fn list_alerts(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Query(q): Query<AlertsQuery>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let limit = q.limit.unwrap_or(100);
    let alerts = state.alert_manager.recent(&tenant, limit);
    let channels: Vec<_> = state
        .alert_manager
        .channels()
        .into_iter()
        .map(|(id, ty)| json!({ "id": id, "type": ty }))
        .collect();
    let (posture_drop, alert_on_critical, cert_days) = state.alert_manager.config_thresholds();

    Json(json!({
        "alerts": alerts,
        "total": alerts.len(),
        "enabled": state.alert_manager.enabled(),
        "channels": channels,
        "rules": {
            "postureDropThreshold": posture_drop,
            "alertOnCritical": alert_on_critical,
            "certExpiryDays": cert_days,
        },
    }))
}

/// Fire a synthetic alert through the configured channels to verify wiring.
pub async fn test_alert(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let event = AlertEvent::new(
        "test",
        AlertSeverity::Info,
        "Test alert",
        "This is a QuantaWatch test alert confirming your notification channels are wired up.",
    );
    state.alert_manager.fire(&tenant, event).await;
    let latest = state.alert_manager.recent(&tenant, 1);
    let delivered = latest.first().map(|e| e.delivered).unwrap_or(0);
    Json(json!({
        "fired": true,
        "delivered": delivered,
        "enabled": state.alert_manager.enabled(),
    }))
}
