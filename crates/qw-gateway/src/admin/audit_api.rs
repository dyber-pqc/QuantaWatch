use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::state::AppState;

pub async fn list_audit(State(state): State<AppState>) -> impl IntoResponse {
    let audit_path = std::path::PathBuf::from(&state.config.audit.path).join("audit.jsonl");

    let entries: Vec<serde_json::Value> = match std::fs::read_to_string(&audit_path) {
        Ok(content) => {
            content.lines()
                .rev()
                .take(100) // Last 100 entries
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect()
        }
        Err(_) => vec![],
    };

    Json(json!({
        "entries": entries,
        "total": entries.len(),
    }))
}

pub async fn verify_audit(State(state): State<AppState>) -> impl IntoResponse {
    let audit_path = std::path::PathBuf::from(&state.config.audit.path).join("audit.jsonl");
    let public_key = state.gateway_identity.public_key_bytes();

    match qw_audit::verify_audit_log(&audit_path, &public_key) {
        Ok(result) => Json(json!({
            "valid": result.valid,
            "entries_checked": result.entries_checked,
            "signatures_valid": result.signatures_valid,
            "chain_intact": result.chain_intact,
            "merkle_roots_valid": result.merkle_roots_valid,
            "errors": result.errors,
        })).into_response(),
        Err(e) => Json(json!({
            "valid": false,
            "error": format!("{e}"),
        })).into_response(),
    }
}
