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
        LoginOutcome::TotpRequired { pending } => (
            StatusCode::OK,
            Json(json!({ "status": "totp_required", "pending": pending })),
        )
            .into_response(),
        LoginOutcome::EnrollmentRequired { pending } => (
            StatusCode::OK,
            Json(json!({ "status": "enroll_required", "pending": pending })),
        )
            .into_response(),
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

/// Whether a fresh install still needs first-run setup, plus whether auth is on.
pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "setupRequired": state.auth_manager.setup_required(),
        "authEnabled": state.auth_manager.enabled(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

/// First-run setup: create the initial admin. Only works on an empty install;
/// returns an enrollment pending token so the admin immediately sets up 2FA.
pub async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SetupRequest>,
) -> impl IntoResponse {
    match state
        .auth_manager
        .setup_admin(&body.username, &body.password)
    {
        Ok(pending) => {
            state
                .audit_logger
                .log(
                    &body.username,
                    qw_audit::AuditEvent::LoginSucceeded {
                        principal: body.username.clone(),
                        auth_method: "first-run-setup".to_string(),
                        client_ip: client_ip(&headers),
                    },
                )
                .await
                .ok();
            (
                StatusCode::OK,
                Json(json!({ "status": "enroll_required", "pending": pending })),
            )
                .into_response()
        }
        Err(e) => (StatusCode::CONFLICT, Json(json!({ "error": e }))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct PendingCodeRequest {
    pub pending: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct PendingRequest {
    pub pending: String,
}

/// Step 2 of login: verify a TOTP (or backup) code and issue a session.
pub async fn verify_2fa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PendingCodeRequest>,
) -> impl IntoResponse {
    use crate::auth::LoginOutcome;
    match state
        .auth_manager
        .verify_totp_login(&body.pending, &body.code)
    {
        LoginOutcome::Ok { token, role, ttl } => (
            StatusCode::OK,
            Json(json!({ "token": token, "role": role, "expiresIn": ttl })),
        )
            .into_response(),
        _ => {
            state
                .audit_logger
                .log(
                    "unknown",
                    qw_audit::AuditEvent::LoginFailed {
                        username: "2fa".to_string(),
                        client_ip: client_ip(&headers),
                    },
                )
                .await
                .ok();
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid or expired code" })),
            )
                .into_response()
        }
    }
}

/// Begin 2FA enrollment — returns the secret + otpauth URL to show as a QR.
pub async fn enroll_begin(
    State(state): State<AppState>,
    Json(body): Json<PendingRequest>,
) -> impl IntoResponse {
    match state.auth_manager.begin_enrollment(&body.pending) {
        Some(info) => (
            StatusCode::OK,
            Json(json!({
                "secret": info.secret,
                "otpauthUrl": info.otpauth_url,
                "pending": info.pending,
            })),
        )
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid or expired enrollment session" })),
        )
            .into_response(),
    }
}

/// Confirm 2FA enrollment — verify the first code, enable 2FA, return a session
/// and the one-time backup codes (shown exactly once).
pub async fn enroll_confirm(
    State(state): State<AppState>,
    Json(body): Json<PendingCodeRequest>,
) -> impl IntoResponse {
    match state
        .auth_manager
        .confirm_enrollment(&body.pending, &body.code)
    {
        Some(res) => (
            StatusCode::OK,
            Json(json!({
                "token": res.token,
                "role": res.role,
                "expiresIn": res.ttl,
                "backupCodes": res.backup_codes,
            })),
        )
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid code or enrollment session" })),
        )
            .into_response(),
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
