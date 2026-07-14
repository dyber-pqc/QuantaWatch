use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::state::AppState;

pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let provider_names = state.providers.names();

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "providers": provider_names,
        "agents": state.config.agents.keys().collect::<Vec<_>>(),
        "monitor": {
            "blocking_threshold": state.config.monitor.blocking_threshold,
            "scan_responses": state.config.monitor.scan_responses,
            "prompt_injection": state.config.monitor.prompt_injection,
            "data_exfiltration": state.config.monitor.data_exfiltration,
            "pii_detection": state.config.monitor.pii_detection,
        },
        "identity": {
            "fingerprint": state.gateway_identity.fingerprint,
            "session_ttl": state.config.identity.session_ttl,
        },
    }))
}
