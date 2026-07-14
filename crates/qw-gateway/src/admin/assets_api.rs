//! Asset inventory API.

use axum::{extract::State, response::IntoResponse, Extension, Json};
use serde_json::json;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

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
