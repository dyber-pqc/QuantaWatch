//! Auth endpoints: login, logout, me.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthContext;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Best-effort client IP from the standard proxy headers (the gateway usually
/// sits behind an ingress/LB). Falls back to "unknown".
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    use crate::auth::LoginOutcome;
    let ip = client_ip(&headers);
    match state.auth_manager.login(&body.username, &body.password) {
        LoginOutcome::Ok { token, role, ttl } => {
            state
                .audit_logger
                .log(
                    &body.username,
                    qw_audit::AuditEvent::LoginSucceeded {
                        principal: body.username.clone(),
                        auth_method: "password".to_string(),
                        client_ip: ip,
                    },
                )
                .await
                .ok();
            (
                StatusCode::OK,
                Json(json!({
                    "token": token,
                    "role": role,
                    "expiresIn": ttl,
                    "username": body.username,
                })),
            )
                .into_response()
        }
        LoginOutcome::LockedOut { retry_after_secs } => {
            state
                .audit_logger
                .log(
                    &body.username,
                    qw_audit::AuditEvent::LoginFailed {
                        username: body.username.clone(),
                        client_ip: ip,
                    },
                )
                .await
                .ok();
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "account temporarily locked",
                    "retryAfterSecs": retry_after_secs,
                })),
            )
                .into_response()
        }
        LoginOutcome::BadCredentials => {
            state
                .audit_logger
                .log(
                    &body.username,
                    qw_audit::AuditEvent::LoginFailed {
                        username: body.username.clone(),
                        client_ip: ip,
                    },
                )
                .await
                .ok();
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            )
                .into_response()
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| {
            headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = bearer(&headers) {
        // Resolve the principal (for the audit record) before invalidating.
        if let Some(ctx) = state.auth_manager.validate(&token) {
            state
                .audit_logger
                .log(
                    &ctx.principal,
                    qw_audit::AuditEvent::Logout {
                        principal: ctx.principal.clone(),
                    },
                )
                .await
                .ok();
        }
        state.auth_manager.logout(&token);
    }
    Json(json!({ "ok": true }))
}

/// Public (unauthenticated) auth config so the login page knows what to render.
pub async fn auth_config(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "authEnabled": state.auth_manager.enabled(),
        "ssoEnabled": state.auth_manager.oidc().is_some(),
        "ssoLoginUrl": "/api/auth/oidc/login",
    }))
}

/// List tenants/orgs the caller may view. Admins see all known orgs (for the
/// org switcher); everyone else sees only their own.
pub async fn list_tenants(
    State(state): State<AppState>,
    ctx: Option<axum::Extension<AuthContext>>,
) -> impl IntoResponse {
    use std::collections::BTreeSet;
    let is_admin = ctx
        .as_ref()
        .map(|c| c.role == crate::auth::Role::Admin)
        .unwrap_or(false);
    let mut set: BTreeSet<String> = BTreeSet::new();
    set.insert("default".to_string());
    if is_admin {
        for t in state.store.tenants() {
            set.insert(t);
        }
        for u in &state.config.auth.users {
            set.insert(u.org.clone());
        }
        for k in &state.config.auth.api_keys {
            set.insert(k.org.clone());
        }
    } else if let Some(axum::Extension(c)) = &ctx {
        set.clear();
        set.insert(c.org.clone());
    }
    Json(json!({ "tenants": set.into_iter().collect::<Vec<_>>(), "canSwitch": is_admin }))
}

/// Returns the current principal, or `authEnabled: false` when auth is off so
/// the dashboard knows not to gate the UI.
pub async fn me(
    State(state): State<AppState>,
    ctx: Option<axum::Extension<AuthContext>>,
) -> impl IntoResponse {
    if !state.auth_manager.enabled() {
        return Json(json!({ "authEnabled": false })).into_response();
    }
    match ctx {
        Some(axum::Extension(ctx)) => Json(json!({
            "authEnabled": true,
            "username": ctx.principal,
            "role": ctx.role_name,
            "permissions": ctx.permissions.sorted(),
            "via": ctx.method,
        }))
        .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response(),
    }
}
