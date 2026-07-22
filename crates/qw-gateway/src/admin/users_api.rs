//! Runtime user management — add / remove people and change their role from the
//! admin console. Config-declared users stay read-only (they live in the YAML);
//! everyone else is stored in the DB and fully editable here.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use qw_crypto::hash_password;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

/// Roles a user may be assigned (built-ins plus any custom role from the config).
fn known_roles(state: &AppState) -> Vec<String> {
    let mut roles = vec!["admin".to_string(), "operator".to_string(), "viewer".to_string()];
    for name in state.config.auth.roles.keys() {
        if !roles.contains(name) {
            roles.push(name.clone());
        }
    }
    roles
}

/// GET /api/users — config users (read-only) + runtime users (editable).
pub async fn list_users(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let me = ctx.as_ref().map(|c| c.principal.clone()).unwrap_or_default();
    let config_users: Vec<_> = state
        .config
        .auth
        .users
        .iter()
        .map(|u| json!({ "username": u.username, "role": u.role, "org": u.org, "source": "config", "editable": false, "isSelf": u.username == me }))
        .collect();
    let db_users: Vec<_> = state
        .store
        .list_users()
        .iter()
        .map(|u| json!({ "username": u.username, "role": u.role, "org": u.org, "source": "db", "editable": true, "isSelf": u.username == me, "createdAt": u.created_at }))
        .collect();
    let all: Vec<_> = config_users.into_iter().chain(db_users).collect();
    Json(json!({
        "users": all,
        "roles": known_roles(&state),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUser {
    username: String,
    password: String,
    role: String,
    #[serde(default)]
    org: Option<String>,
}

/// POST /api/users — create a runtime user.
pub async fn create_user(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<CreateUser>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let username = body.username.trim().to_string();
    if username.is_empty() || body.password.len() < 8 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "username required and password must be at least 8 characters" }))).into_response();
    }
    if !known_roles(&state).iter().any(|r| r == &body.role) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("unknown role '{}'", body.role), "roles": known_roles(&state) }))).into_response();
    }
    // Don't shadow a config-declared user (config wins at login, so it'd confuse).
    if state.config.auth.users.iter().any(|u| u.username == username) {
        return (StatusCode::CONFLICT, Json(json!({ "error": "a config-defined user already has that name" }))).into_response();
    }
    if state.store.get_user(&username).is_some() {
        return (StatusCode::CONFLICT, Json(json!({ "error": "user already exists" }))).into_response();
    }
    let password_hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("hash failed: {e}") }))).into_response(),
    };
    let user = qw_store::DbUser {
        username: username.clone(),
        role: body.role,
        org: body.org.unwrap_or(tenant),
        password_hash,
        created_at: chrono::Utc::now(),
    };
    state.store.upsert_user(&user);
    (StatusCode::CREATED, Json(json!({ "username": user.username, "role": user.role, "org": user.org, "source": "db" }))).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUser {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// PUT /api/users/{username} — change a runtime user's role and/or password.
pub async fn update_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Json(body): Json<UpdateUser>,
) -> impl IntoResponse {
    let Some(mut user) = state.store.get_user(&username) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "no such runtime user (config users are edited in the YAML)" }))).into_response();
    };
    if let Some(role) = body.role {
        if !known_roles(&state).iter().any(|r| r == &role) {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("unknown role '{role}'") }))).into_response();
        }
        user.role = role;
    }
    if let Some(pw) = body.password {
        if pw.len() < 8 {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "password must be at least 8 characters" }))).into_response();
        }
        match hash_password(&pw) {
            Ok(h) => user.password_hash = h,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("hash failed: {e}") }))).into_response(),
        }
    }
    state.store.upsert_user(&user);
    Json(json!({ "username": user.username, "role": user.role, "updated": true })).into_response()
}

/// DELETE /api/users/{username} — remove a runtime user (revokes their access).
pub async fn delete_user(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if ctx.as_ref().map(|c| c.principal == username).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "you can't delete the account you're signed in as" }))).into_response();
    }
    if state.store.get_user(&username).is_none() {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "no such runtime user (config users are removed from the YAML)" }))).into_response();
    }
    state.store.delete_user(&username);
    // Also drop any live sessions for that user so access is revoked immediately.
    state.store.delete_sessions_for_user(&username);
    Json(json!({ "username": username, "deleted": true })).into_response()
}
