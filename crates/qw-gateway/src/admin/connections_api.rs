//! UI-managed connections to external sources (GitHub, GitLab, Jira, Linear).
//!
//! Unlike the config/env-based integrations wired at startup, a connection is
//! created from the dashboard with its secret entered in the browser. The token
//! is persisted on the gateway to drive scans and is masked by every response —
//! the API only ever reports `hasToken`. Scanning a connection runs the same
//! discover → fetch → scan → recompute pipeline as a config integration, and
//! additionally returns a **migration plan**: the quantum-vulnerable algorithms
//! found, grouped with their PQC replacement and a policy action.

use std::collections::{BTreeMap, HashMap};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use qw_store::ConnectionRow;

use crate::admin::integrations_api::{air_gapped_refusal, run_integration_scan};
use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

const SUPPORTED: [&str; 4] = ["github", "gitlab", "jira", "linear"];

/// Mask the stored secret — never return the token to the browser.
fn masked(c: &ConnectionRow) -> serde_json::Value {
    json!({
        "id": c.id,
        "integrationType": c.integration_type,
        "displayName": c.display_name,
        "baseUrl": c.base_url,
        "org": c.org,
        "project": c.project,
        "repo": c.repo,
        "hasToken": !c.token.is_empty(),
        "createdAt": c.created_at,
        "lastTested": c.last_tested,
        "lastStatus": c.last_status,
        "lastUser": c.last_user,
        "lastScanned": c.last_scanned,
        "findingsCount": c.findings_count,
    })
}

/// Build the in-memory integration config (with the secret) from a stored row.
fn to_config(c: &ConnectionRow) -> qw_integrations::IntegrationConfig {
    let mut settings = HashMap::new();
    if let Some(org) = &c.org {
        settings.insert("org".to_string(), org.clone());
    }
    if let Some(repo) = &c.repo {
        settings.insert("repo".to_string(), repo.clone());
    }
    qw_integrations::IntegrationConfig {
        id: c.id.clone(),
        integration_type: c.integration_type.clone(),
        base_url: c.base_url.clone(),
        api_token_env: String::new(),
        token: Some(c.token.clone()),
        default_project: c.project.clone(),
        webhook_secret_env: None,
        settings,
    }
}

/// GET /api/connections
pub async fn list_connections(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let rows = state.store.list_connections(&tenant);
    let connections: Vec<_> = rows.iter().map(masked).collect();
    Json(json!({
        "connections": connections,
        "total": connections.len(),
        "supportedTypes": SUPPORTED,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateConnection {
    integration_type: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    token: String,
}

/// POST /api/connections — create a connection with a stored secret.
pub async fn create_connection(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<CreateConnection>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let itype = body.integration_type.to_lowercase();
    if !SUPPORTED.contains(&itype.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("unsupported type '{itype}'; one of {SUPPORTED:?}") })),
        )
            .into_response();
    }
    if body.token.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "token is required" })),
        )
            .into_response();
    }
    let opt = |s: Option<String>| s.filter(|v| !v.trim().is_empty());
    let row = ConnectionRow {
        id: uuid::Uuid::new_v4().to_string(),
        display_name: body
            .display_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| itype.clone()),
        integration_type: itype,
        base_url: opt(body.base_url),
        org: opt(body.org),
        project: opt(body.project),
        repo: opt(body.repo),
        token: body.token,
        created_at: chrono::Utc::now(),
        last_tested: None,
        last_status: Some("untested".to_string()),
        last_user: None,
        last_scanned: None,
        findings_count: None,
    };
    state.store.upsert_connection(&tenant, &row);
    (StatusCode::CREATED, Json(masked(&row))).into_response()
}

/// DELETE /api/connections/{id}
pub async fn delete_connection(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    state.store.delete_connection(&tenant, &id);
    Json(json!({ "id": id, "deleted": true }))
}

/// POST /api/connections/{id}/test — verify the stored secret against the API.
pub async fn test_connection(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.config.air_gapped {
        return air_gapped_refusal();
    }
    let tenant = tenant_of(&ctx);
    let Some(mut row) = state.store.get_connection(&tenant, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "connection not found" })),
        )
            .into_response();
    };
    let Some(integration) = qw_integrations::build_one(&to_config(&row)) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "could not construct integration" })),
        )
            .into_response();
    };
    match integration.test_connection().await {
        Ok(status) => {
            row.last_tested = Some(chrono::Utc::now());
            row.last_status = Some(
                if status.connected {
                    "connected"
                } else {
                    "failed"
                }
                .to_string(),
            );
            row.last_user = status.user.clone();
            state.store.upsert_connection(&tenant, &row);
            Json(json!({ "connection": masked(&row), "status": status })).into_response()
        }
        Err(e) => {
            row.last_tested = Some(chrono::Utc::now());
            row.last_status = Some("failed".to_string());
            state.store.upsert_connection(&tenant, &row);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// POST /api/connections/{id}/scan — discover + scan the source's repos for
/// quantum-vulnerable crypto, then return findings + a PQC migration plan.
pub async fn scan_connection(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.config.air_gapped {
        return air_gapped_refusal();
    }
    let tenant = tenant_of(&ctx);
    let Some(mut row) = state.store.get_connection(&tenant, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "connection not found" })),
        )
            .into_response();
    };
    let Some(integration) = qw_integrations::build_one(&to_config(&row)) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "could not construct integration" })),
        )
            .into_response();
    };

    let mut result = match run_integration_scan(&state, &tenant, integration.as_ref(), &id).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    };

    let plan = migration_plan(&result);
    let findings = result.get("findings").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    row.last_scanned = Some(chrono::Utc::now());
    row.findings_count = Some(findings);
    if row.last_status.is_none() || row.last_status.as_deref() == Some("untested") {
        row.last_status = Some("connected".to_string());
    }
    state.store.upsert_connection(&tenant, &row);

    if let Some(obj) = result.as_object_mut() {
        // Drop the heavy raw results from the response; keep the summary + plan.
        obj.remove("results");
        obj.insert("connection".to_string(), masked(&row));
        obj.insert("migrationPlan".to_string(), json!(plan));
    }
    Json(result).into_response()
}

/// The PQC replacement for a classical algorithm found in code/deps.
fn pqc_target(algo: &str) -> &'static str {
    let a = algo.to_lowercase();
    if a.contains("ecdh") || a.contains("x25519") || a.contains("diffie") || a.contains("dh") {
        "ML-KEM-768 (FIPS 203) hybrid key establishment"
    } else if a.contains("ecdsa") || a.contains("ed25519") || a.contains("dsa") {
        "ML-DSA-65 (FIPS 204) signatures"
    } else if a.contains("rsa") {
        "ML-KEM-768 for key transport + ML-DSA-65 for signatures"
    } else if a.contains("secp") || a.contains("prime256") {
        "ML-KEM-768 / ML-DSA-65 (replace the P-256 curve)"
    } else {
        "a NIST PQC algorithm (ML-KEM-768 / ML-DSA-65)"
    }
}

/// Derive a per-algorithm migration plan from the scan's findings — the concrete
/// "policy migration" work list: what to move off, what to move to.
fn migration_plan(result: &serde_json::Value) -> Vec<serde_json::Value> {
    // Group by algorithm across every ScanResult's findings.
    let mut by_algo: BTreeMap<String, (u32, String, BTreeMap<String, ()>)> = BTreeMap::new();
    if let Some(results) = result.get("results").and_then(|v| v.as_array()) {
        for r in results {
            if let Some(findings) = r.get("findings").and_then(|v| v.as_array()) {
                for f in findings {
                    let pqc = f.get("pqc_status").and_then(|v| v.as_str()).unwrap_or("");
                    // Only crypto that needs migrating.
                    if !matches!(pqc, "classical_weak" | "classical_secure" | "unknown") {
                        continue;
                    }
                    let algo = f
                        .get("asset")
                        .and_then(|a| a.get("algorithm"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("classical crypto")
                        .to_string();
                    let sev = f
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("medium")
                        .to_string();
                    let loc = f
                        .get("asset")
                        .and_then(|a| a.get("location"))
                        .and_then(|l| l.get("path"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let entry = by_algo
                        .entry(algo)
                        .or_insert((0, sev.clone(), BTreeMap::new()));
                    entry.0 += 1;
                    // Keep the highest severity seen.
                    if sev_rank(&sev) > sev_rank(&entry.1) {
                        entry.1 = sev;
                    }
                    if !loc.is_empty() {
                        entry.2.insert(loc, ());
                    }
                }
            }
        }
    }
    by_algo
        .into_iter()
        .map(|(algo, (count, severity, locs))| {
            json!({
                "algorithm": algo,
                "occurrences": count,
                "severity": severity,
                "migrateTo": pqc_target(&algo),
                "action": format!("Replace {algo} with {}", pqc_target(&algo)),
                "locations": locs.into_keys().take(20).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}
