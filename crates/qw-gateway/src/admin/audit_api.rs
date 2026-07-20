use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use qw_audit::AuditBackend;

use crate::siem::{self, SiemFormat};
use crate::state::AppState;

/// Upper bound on entries pulled for a full-chain verification pass.
const VERIFY_CAP: usize = 1_000_000;

/// Read the tail of the audit log as JSON values, newest last (chronological).
fn read_audit_entries(state: &AppState, limit: usize) -> Vec<serde_json::Value> {
    state
        .store
        .list_entries(limit)
        .iter()
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect()
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

    // `bundle` = raw entries + checkpoints, the format `qw verify` consumes for
    // full sharded verification (per-writer chains + global checkpoint chain).
    if format_str == "bundle" {
        let entries = state
            .store
            .list_entries(q.limit.unwrap_or(10_000).min(1_000_000));
        let checkpoints = state.store.list_checkpoints();
        return Json(json!({ "entries": entries, "checkpoints": checkpoints })).into_response();
    }

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
    let entries = read_audit_entries(&state, 100);
    Json(json!({
        "entries": entries,
        "total": entries.len(),
    }))
}

/// `POST /api/audit/verify` — verify every per-writer chain plus the global
/// checkpoint chain that anchors them.
pub async fn verify_audit(State(state): State<AppState>) -> impl IntoResponse {
    let public_key = state.gateway_identity.public_key_bytes();
    let entries = state.store.list_entries(VERIFY_CAP);
    let checkpoints = state.store.list_checkpoints();

    let result = qw_audit::verify_sharded(&entries, &checkpoints, &public_key);
    Json(json!({
        "valid": result.valid,
        "entries_checked": result.entries_checked,
        "writers_checked": result.writers_checked,
        "checkpoints_checked": result.checkpoints_checked,
        "signatures_valid": result.signatures_valid,
        "chain_intact": result.chain_intact,
        "merkle_roots_valid": result.merkle_roots_valid,
        "errors": result.errors,
    }))
    .into_response()
}
