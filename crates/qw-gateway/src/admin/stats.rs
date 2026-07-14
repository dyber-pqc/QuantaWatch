use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::state::AppState;

pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let sessions = state.sessions.len();
    let total_requests: u64 = state.sessions.iter().map(|e| e.value().request_count).sum();
    let total_tokens: u64 = state.sessions.iter().map(|e| e.value().total_tokens).sum();

    Json(json!({
        "active_sessions": sessions,
        "total_requests": total_requests,
        "total_tokens": total_tokens,
        "providers": state.providers.names(),
        "gateway_fingerprint": state.gateway_identity.fingerprint,
    }))
}
