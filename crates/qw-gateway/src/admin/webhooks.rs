//! Inbound webhook receivers — push-based ticket/PR status updates.
//!
//! GitHub / Jira / Linear POST here when a PR merges or an issue changes, so we
//! reconcile remediation status instantly instead of polling. Unauthenticated
//! (external callers) but the GitHub route verifies the HMAC signature.

use axum::{extract::State, response::IntoResponse, http::{HeaderMap, StatusCode}, Json};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use qw_integrations::TicketStatus;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Find a remediation with `external_id` across all tenants and set its status.
async fn update_ticket(state: &AppState, external_id: &str, status: TicketStatus) -> bool {
    for tenant in crate::background::all_tenants(state) {
        for mut t in state.store.list_remediations(&tenant) {
            if t.external_id == external_id && t.status != status {
                let was = t.status.clone();
                t.status = status.clone();
                t.updated_at = chrono::Utc::now();
                state.store.record_remediation(&tenant, &t);
                if matches!(status, TicketStatus::Resolved) {
                    let mut ev = crate::alerts::AlertEvent::new(
                        "remediation_resolved", crate::alerts::AlertSeverity::Info,
                        "Remediation resolved (webhook)",
                        format!("{} moved {:?} → {:?} via webhook.", external_id, was, status),
                    );
                    ev.metadata.insert("ticket".into(), external_id.to_string());
                    state.alert_manager.fire(&tenant, ev).await;
                }
                return true;
            }
        }
    }
    false
}

fn verify_github_sig(state: &AppState, headers: &HeaderMap, body: &[u8]) -> bool {
    // Candidate secrets: every integration's own secret plus the global one.
    let mut secret_envs: Vec<String> = state.config.integrations.iter()
        .filter_map(|c| c.webhook_secret_env.clone())
        .collect();
    if let Some(g) = &state.config.auth.webhook_secret_env {
        secret_envs.push(g.clone());
    }
    if secret_envs.is_empty() {
        return true; // no secret configured anywhere — accept (dev)
    }
    let Some(sig) = headers.get("x-hub-signature-256").and_then(|v| v.to_str().ok()) else { return false };
    let expected = sig.strip_prefix("sha256=").unwrap_or(sig);

    // Verify against each configured secret; a match on any is sufficient.
    secret_envs.iter().filter_map(|e| std::env::var(e).ok()).any(|secret| {
        match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(mut mac) => { mac.update(body); hex::encode(mac.finalize().into_bytes()) == expected }
            Err(_) => false,
        }
    })
}

pub async fn github(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    if !verify_github_sig(&state, &headers, &body) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "bad signature" }))).into_response();
    }
    let event = headers.get("x-github-event").and_then(|v| v.to_str().ok()).unwrap_or("");
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();

    let mut updated = false;
    if event == "pull_request" && payload["action"].as_str() == Some("closed") {
        let number = payload["number"].as_u64().or_else(|| payload["pull_request"]["number"].as_u64()).unwrap_or(0);
        let merged = payload["pull_request"]["merged"].as_bool().unwrap_or(false);
        let status = if merged { TicketStatus::Resolved } else { TicketStatus::Closed };
        updated = update_ticket(&state, &format!("#{number}"), status).await;
    }
    Json(json!({ "ok": true, "updated": updated })).into_response()
}

pub async fn jira(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let key = payload["issue"]["key"].as_str().unwrap_or_default().to_string();
    let cat = payload["issue"]["fields"]["status"]["statusCategory"]["key"].as_str().unwrap_or("");
    let status = match cat { "done" => TicketStatus::Resolved, "indeterminate" => TicketStatus::InProgress, _ => TicketStatus::Open };
    let updated = if key.is_empty() { false } else { update_ticket(&state, &key, status).await };
    Json(json!({ "ok": true, "updated": updated }))
}

pub async fn linear(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let id = payload["data"]["id"].as_str().unwrap_or_default().to_string();
    let ty = payload["data"]["state"]["type"].as_str().unwrap_or("");
    let status = match ty { "completed" => TicketStatus::Resolved, "canceled" => TicketStatus::Closed, "started" => TicketStatus::InProgress, _ => TicketStatus::Open };
    let updated = if id.is_empty() { false } else { update_ticket(&state, &id, status).await };
    Json(json!({ "ok": true, "updated": updated }))
}
