use axum::{
    extract::{State, Path},
    response::IntoResponse,
    Json,
    http::StatusCode,
};
use serde_json::json;
use std::collections::HashSet;

use crate::state::AppState;

pub async fn list_integrations(State(state): State<AppState>) -> impl IntoResponse {
    let integrations = state.integration_registry.list();
    Json(json!({
        "integrations": integrations,
        "total": integrations.len(),
    }))
}

pub async fn test_integration(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.integration_registry.get(&id) {
        Some(integration) => {
            match integration.test_connection().await {
                Ok(status) => {
                    let _ = state.audit_logger.log(
                        "system",
                        qw_audit::AuditEvent::IntegrationSync {
                            integration_id: id.clone(),
                            action: "test_connection".to_string(),
                            detail: if status.connected { "success".to_string() } else { "failed".to_string() },
                        },
                    ).await;
                    Json(json!(status)).into_response()
                }
                Err(e) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                        "error": e.to_string(),
                    }))).into_response()
                }
            }
        }
        None => {
            (StatusCode::NOT_FOUND, Json(json!({
                "error": format!("Integration '{}' not found", id),
            }))).into_response()
        }
    }
}

pub async fn sync_integration(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.integration_registry.get(&id) {
        Some(integration) => {
            match integration.discover_targets().await {
                Ok(targets) => {
                    let count = targets.len();
                    let _ = state.audit_logger.log(
                        "system",
                        qw_audit::AuditEvent::IntegrationSync {
                            integration_id: id.clone(),
                            action: "discover_targets".to_string(),
                            detail: format!("Discovered {} targets", count),
                        },
                    ).await;
                    Json(json!({
                        "targets_discovered": count,
                        "targets": targets,
                    })).into_response()
                }
                Err(e) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                        "error": e.to_string(),
                    }))).into_response()
                }
            }
        }
        None => {
            (StatusCode::NOT_FOUND, Json(json!({
                "error": format!("Integration '{}' not found", id),
            }))).into_response()
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWebhookRequest {
    /// Public URL the provider should POST to, e.g. https://gw.example.com/api/webhooks/github
    pub callback_url: String,
}

/// Ask the provider to register an inbound webhook pointing at our receiver,
/// signed with the configured webhook secret.
pub async fn register_webhook(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(body): axum::Json<RegisterWebhookRequest>,
) -> impl IntoResponse {
    let Some(integration) = state.integration_registry.get(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "integration not found" }))).into_response();
    };
    // Prefer this integration's own webhook secret, else the global one.
    let secret_env = state.config.integrations.iter()
        .find(|c| c.id == id)
        .and_then(|c| c.webhook_secret_env.clone())
        .or_else(|| state.config.auth.webhook_secret_env.clone());
    let secret = secret_env.and_then(|e| std::env::var(e).ok()).unwrap_or_default();
    match integration.register_webhook(&body.callback_url, &secret).await {
        Ok(msg) => Json(json!({ "ok": true, "detail": msg })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

/// Discover dependency files in the integration's repos, fetch each file's
/// content, scan it inline, persist findings, and recompute posture.
pub async fn scan_integration(
    State(state): State<AppState>,
    ctx: Option<axum::Extension<crate::auth::AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = crate::auth::tenant_of(&ctx);
    let integration = match state.integration_registry.get(&id) {
        Some(i) => i,
        None => {
            return (StatusCode::NOT_FOUND, Json(json!({
                "error": format!("Integration '{}' not found", id),
            }))).into_response();
        }
    };

    let targets = match integration.discover_targets().await {
        Ok(t) => t,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({
                "error": e.to_string(),
            }))).into_response();
        }
    };

    let mut repos: HashSet<String> = HashSet::new();
    let mut files_scanned = 0usize;
    let mut all_results = Vec::new();

    for target in &targets {
        // Track unique repos via repo/project metadata.
        if let Some(repo) = target.metadata.get("repo").or_else(|| target.metadata.get("project")) {
            repos.insert(repo.clone());
        }

        let content = match integration.fetch_content(target).await {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(integration = %id, target = %target.address, error = %e, "fetch_content failed");
                continue;
            }
        };

        let mut target_with_content = target.clone();
        target_with_content.metadata.insert("content".to_string(), content);

        let results = state.scanner_registry.scan_all(&target_with_content).await;
        files_scanned += 1;

        for result in &results {
            state.store.record_scan(&tenant, result, &target_with_content);
        }
        all_results.extend(results);
    }

    let summary = crate::background::recompute_and_snapshot(&state, &tenant, &all_results, "integration-scan").await;

    let findings: usize = all_results.iter().map(|r| r.findings.len()).sum();
    let repos_scanned = repos.len();

    let _ = state.audit_logger.log(
        "system",
        qw_audit::AuditEvent::IntegrationSync {
            integration_id: id.clone(),
            action: "scan".to_string(),
            detail: format!("{} files", files_scanned),
        },
    ).await;

    tracing::info!(
        integration = %id,
        repos = repos_scanned,
        files = files_scanned,
        findings,
        score = summary.overall_score,
        "Integration scan complete"
    );

    Json(json!({
        "reposScanned": repos_scanned,
        "filesScanned": files_scanned,
        "findings": findings,
        "results": all_results,
    })).into_response()
}
