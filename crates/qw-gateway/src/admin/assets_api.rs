//! Asset inventory API.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAsset {
    /// Free-form identifier (host, ARN, key id, endpoint…).
    address: String,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default = "default_env")]
    environment: String,
    #[serde(default)]
    tags: Vec<String>,
    /// Optional known posture; defaults to "unknown" until scanned.
    #[serde(default)]
    pqc_status: Option<String>,
    #[serde(default)]
    tls_version: Option<String>,
}

fn default_kind() -> String {
    "endpoint".to_string()
}
fn default_env() -> String {
    "production".to_string()
}

/// POST /api/assets — manually register an infrastructure crypto asset.
pub async fn create_asset(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<NewAsset>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let address = body.address.trim().to_string();
    if address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "address is required" })),
        )
            .into_response();
    }
    let status = body
        .pqc_status
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let asset = qw_store::AssetRow {
        // Stable id from the address so re-adding the same asset updates it.
        id: format!("manual:{address}"),
        kind: body.kind,
        address: address.clone(),
        environment: body.environment,
        tags: {
            let mut t = body.tags;
            if !t.iter().any(|x| x == "manual") {
                t.push("manual".to_string());
            }
            t
        },
        pqc_status: status,
        tls_version: body.tls_version,
        last_scanned: None,
        source: "manual".to_string(),
    };
    state.store.upsert_asset(&tenant, &asset);
    // Fold the new asset into the attack-path graph immediately.
    crate::admin::graph::snapshot_and_alert(&state, &tenant).await;
    (StatusCode::CREATED, Json(asset)).into_response()
}

pub async fn list_assets(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let assets = state.store.list_assets(&tenant);
    let mut by_env: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut vulnerable = 0usize;
    for a in &assets {
        *by_env.entry(a.environment.clone()).or_insert(0) += 1;
        if a.pqc_status == "classical_secure" || a.pqc_status == "classical_weak" {
            vulnerable += 1;
        }
    }
    Json(json!({
        "assets": assets,
        "total": assets.len(),
        "vulnerable": vulnerable,
        "environments": by_env,
        "connectors": state.config.connectors.iter().map(|c| json!({
            "name": c.name, "type": c.connector_type, "environment": c.environment, "endpoints": c.endpoints.len(),
        })).collect::<Vec<_>>(),
    }))
}

/// Re-run agentless discovery + TLS scanning across the asset inventory.
pub async fn sync_assets(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let (total, scanned) = crate::assets::sync_assets(&state, &tenant).await;
    // Recompute posture + attack-path graph over the newly-ingested assets.
    let _ = crate::background::recompute_and_snapshot(&state, &tenant, &[], "asset-sync").await;
    Json(json!({ "total": total, "scanned": scanned }))
}
