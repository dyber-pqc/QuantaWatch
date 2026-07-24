//! Cloud discovery connector status.
//!
//! The connectors themselves live in `crate::cloud` (AWS KMS/ACM, Azure Key
//! Vault, GCP KMS, Kubernetes ingress/secrets) and produce classified
//! `AssetRow`s during asset sync. This surface reports what's configured,
//! whether each connector's credentials are present, and how many crypto assets
//! it has discovered — so an operator can see coverage at a glance.

use axum::{extract::State, response::IntoResponse, Extension, Json};
use serde_json::json;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

/// The env vars each API connector needs, for a credentials-present signal.
fn credential_vars(connector_type: &str) -> &'static [&'static str] {
    match connector_type {
        "aws" => &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        "gcp" => &["GCP_ACCESS_TOKEN"],
        "azure" => &["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
        "kubernetes" | "k8s" => &[], // in-cluster SA or endpoints[0] + token_env tag
        _ => &[],
    }
}

fn credentials_present(connector_type: &str) -> bool {
    let vars = credential_vars(connector_type);
    if vars.is_empty() {
        return true; // no static creds required (e.g. k8s in-cluster / generic)
    }
    vars.iter().all(|v| std::env::var(v).is_ok())
}

/// The asset `source` string a connector's discoveries carry.
fn source_for(connector_type: &str) -> &str {
    match connector_type {
        "k8s" => "kubernetes",
        other => other,
    }
}

/// GET /api/connectors — configured connectors + discovery coverage.
pub async fn get_connectors(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let assets = state.store.list_assets(&tenant);

    let connectors: Vec<serde_json::Value> = state
        .config
        .connectors
        .iter()
        .map(|c| {
            let source = source_for(&c.connector_type);
            let discovered: Vec<_> = assets.iter().filter(|a| a.source == source).collect();
            let vulnerable = discovered
                .iter()
                .filter(|a| matches!(a.pqc_status.as_str(), "classical_secure" | "classical_weak"))
                .count();
            let api = crate::cloud::is_api_connector(&c.connector_type);
            json!({
                "name": c.name,
                "type": c.connector_type,
                "environment": c.environment,
                "endpoints": c.endpoints,
                "isApiConnector": api,
                "credentialsPresent": !api || credentials_present(&c.connector_type),
                "requiredCredentials": credential_vars(&c.connector_type),
                "discoveredAssets": discovered.len(),
                "quantumVulnerable": vulnerable,
            })
        })
        .collect();

    // Assets discovered by any cloud/k8s source (i.e. not declared in config).
    let cloud_assets = assets.iter().filter(|a| a.source != "config").count();

    Json(json!({
        "connectors": connectors,
        "total": state.config.connectors.len(),
        "apiConnectors": state.config.connectors.iter().filter(|c| crate::cloud::is_api_connector(&c.connector_type)).count(),
        "discoveredAssets": cloud_assets,
        "airGapped": state.config.air_gapped,
        "note": "Discovery runs at startup and on POST /api/assets/sync; live cloud calls require the listed credentials.",
    }))
}
