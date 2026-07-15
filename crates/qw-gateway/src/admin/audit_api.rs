use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::siem::{self, SiemFormat};
use crate::state::AppState;

/// Read the tail of the audit log as JSON values, newest last.
fn read_audit_entries(state: &AppState, limit: usize) -> Vec<serde_json::Value> {
    let audit_path = std::path::PathBuf::from(&state.config.audit.path).join("audit.jsonl");
    let Ok(content) = std::fs::read_to_string(&audit_path) else {
        return Vec::new();
    };
    let mut entries: Vec<serde_json::Value> = content
        .lines()
        .rev()
        .take(limit)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    entries.reverse(); // chronological — SIEMs expect ascending sequence
    entries
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportQuery {
    /// `jsonl` (ECS, default) or `cef`.
    pub format: Option<String>,
    pub limit: Option<usize>,
    /// Include the full ML-DSA signature per event (~4.4 KB each). Off by
    /// default so volume-billed SIEM ingest isn't dominated by signatures;
    /// chain-linkage hashes are always included regardless.
    pub signatures: Option<bool>,
}

/// `GET /api/audit/export?format=jsonl|cef&limit=N` — the signed audit log in a
/// SIEM-ingestible format.
///
/// Pull-based by design: the SIEM scrapes us. That works in air-gapped
/// deployments (no egress) and a SIEM outage can't back-pressure the proxy.
pub async fn export_audit(
    State(state): State<AppState>,
    Query(q): Query<ExportQuery>,
) -> impl IntoResponse {
    let format_str = q.format.unwrap_or_else(|| "jsonl".to_string());
    let Some(format) = SiemFormat::parse(&format_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("unsupported format '{format_str}'"),
                "supported": ["jsonl", "cef"],
            })),
        )
            .into_response();
    };

    let entries = read_audit_entries(&state, q.limit.unwrap_or(1000).min(10_000));
    let body = siem::render(
        &entries,
        format,
        env!("CARGO_PKG_VERSION"),
        q.signatures.unwrap_or(false),
    );

    ([(header::CONTENT_TYPE, format.content_type())], body).into_response()
}

pub async fn list_audit(State(state): State<AppState>) -> impl IntoResponse {
    let audit_path = std::path::PathBuf::from(&state.config.audit.path).join("audit.jsonl");

    let entries: Vec<serde_json::Value> = match std::fs::read_to_string(&audit_path) {
        Ok(content) => {
            content
                .lines()
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
        }))
        .into_response(),
        Err(e) => Json(json!({
            "valid": false,
            "error": format!("{e}"),
        }))
        .into_response(),
    }
}
