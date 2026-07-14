use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Extension, Json,
};
use qw_cbom::PostureEngine;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

pub async fn get_posture(State(state): State<AppState>) -> impl IntoResponse {
    let cache = state.posture_cache.read().await;
    if let Some(ref posture) = *cache {
        return Json(json!(posture));
    }
    drop(cache);

    // Compute fresh posture from scan store + provider crypto
    let scan_results = vec![];
    let providers: Vec<_> = state
        .provider_crypto
        .iter()
        .map(|e| e.value().clone())
        .collect();

    let posture = PostureEngine::summarize(&scan_results, &providers);

    // Cache it
    let mut cache = state.posture_cache.write().await;
    *cache = Some(posture.clone());

    Json(json!(posture))
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<usize>,
}

pub async fn get_posture_history(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Query(query): Query<HistoryQuery>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let limit = query.limit.unwrap_or(100);
    let history = state.store.posture_history(&tenant, limit);
    Json(json!({
        "history": history,
        "total": history.len(),
    }))
}
