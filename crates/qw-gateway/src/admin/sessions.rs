use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::state::AppState;

pub async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let sessions: Vec<_> = state
        .sessions
        .iter()
        .map(|entry| {
            let s = entry.value();
            json!({
                "session_id": s.session_id,
                "agent_name": s.agent_name,
                "provider": s.provider,
                "model": s.model,
                "created_at": s.created_at.to_rfc3339(),
                "request_count": s.request_count,
                "total_tokens": s.total_tokens,
                "client_ip": s.client_ip,
            })
        })
        .collect();

    Json(json!({
        "sessions": sessions,
        "total": sessions.len(),
    }))
}

pub async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.sessions.get(&id) {
        Some(entry) => {
            let s = entry.value();
            Json(json!({
                "session_id": s.session_id,
                "agent_name": s.agent_name,
                "provider": s.provider,
                "model": s.model,
                "created_at": s.created_at.to_rfc3339(),
                "request_count": s.request_count,
                "total_tokens": s.total_tokens,
                "client_ip": s.client_ip,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "session not found"
            })),
        )
            .into_response(),
    }
}
