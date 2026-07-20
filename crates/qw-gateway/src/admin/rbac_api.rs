//! RBAC introspection: the resolved role -> permission matrix.
//!
//! Read-only view of the access model (built-in bundles + config custom roles)
//! so the dashboard can render "who can do what" without the operator having to
//! read the YAML. Secrets (password/key hashes) are never exposed here.

use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::state::AppState;

const BUILTIN: [&str; 4] = ["viewer", "auditor", "operator", "admin"];

/// GET /api/rbac — resources, actions, and every role's permission patterns.
pub async fn get_rbac(State(state): State<AppState>) -> impl IntoResponse {
    let roles: Vec<_> = state
        .auth_manager
        .rbac_roles()
        .into_iter()
        .map(|(name, permissions)| {
            let builtin = BUILTIN.contains(&name.as_str());
            json!({
                "name": name,
                "builtin": builtin,
                "permissions": permissions,
            })
        })
        .collect();

    Json(json!({
        "resources": crate::rbac::RBAC_RESOURCES,
        "actions": ["read", "write"],
        "roles": roles,
    }))
}
