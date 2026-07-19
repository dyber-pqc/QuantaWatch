//! Authentication, sessions, API keys, and RBAC.
//!
//! Disabled unless `auth.enabled` is set. When on, every admin request must
//! carry either a session bearer token (from `/api/auth/login`) or an API key,
//! and the caller's role must meet the route's required role.

use std::sync::Arc;

use serde::Serialize;

use qw_crypto::{random_token, sha3_256_hex, verify_password};
use qw_store::Store;

use crate::config::AuthConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    /// Read-only auditor: can read everything (incl. evidence packs) but mutate nothing.
    Auditor,
    Operator,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" => Role::Admin,
            "operator" => Role::Operator,
            "auditor" => Role::Auditor,
            _ => Role::Viewer,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Auditor => "auditor",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }
}

/// Injected into request extensions after successful auth.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub principal: String,
    pub role: Role,
    /// Tenant/org used to isolate this caller's data.
    pub org: String,
    /// "session" or "api-key"
    pub method: &'static str,
}

pub struct AuthManager {
    config: AuthConfig,
    /// Sessions and OIDC states live in the shared store, not in process memory,
    /// so a login on one replica is valid on all of them (and survives restart).
    store: Arc<Store>,
}

impl AuthManager {
    pub fn new(config: AuthConfig, store: Arc<Store>) -> Self {
        Self { config, store }
    }

    /// Mint a token, persist the session keyed by the token's SHA3-256 hash
    /// (never the raw token), and return the token + its TTL in seconds.
    fn issue_session(&self, username: &str, role: Role, org: &str) -> (String, u64) {
        let token = random_token(32);
        let ttl = self.config.session_ttl_secs;
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
        self.store.put_auth_session(
            &sha3_256_hex(token.as_bytes()),
            &qw_store::AuthSession {
                username: username.to_string(),
                role: role.label().to_string(),
                org: org.to_string(),
                expires_at,
            },
        );
        (token, ttl)
    }

    /// Issue a session for an externally-authenticated (e.g. OIDC) principal.
    pub fn create_external_session(&self, username: &str, role: Role, org: &str) -> (String, u64) {
        self.issue_session(username, role, org)
    }

    /// Begin an OIDC flow: mint and remember a state nonce (10-min TTL).
    pub fn begin_oidc(&self) -> String {
        let state = random_token(16);
        self.store
            .put_oidc_state(&state, chrono::Utc::now() + chrono::Duration::minutes(10));
        state
    }

    /// Validate and consume an OIDC state nonce.
    pub fn consume_oidc_state(&self, state: &str) -> bool {
        match self.store.consume_oidc_state(state) {
            Some(exp) => exp > chrono::Utc::now(),
            None => false,
        }
    }

    pub fn oidc(&self) -> Option<&crate::config::OidcConfig> {
        self.config.oidc.as_ref()
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Authenticate a username/password and issue a session token.
    pub fn login(&self, username: &str, password: &str) -> Option<(String, Role, u64)> {
        let user = self.config.users.iter().find(|u| u.username == username)?;
        if !verify_password(password, &user.password_hash) {
            return None;
        }
        let role = Role::parse(&user.role);
        let (token, ttl) = self.issue_session(username, role, &user.org);
        Some((token, role, ttl))
    }

    pub fn logout(&self, token: &str) {
        self.store
            .delete_auth_session(&sha3_256_hex(token.as_bytes()));
    }

    /// Resolve a credential (session token or API key) to an AuthContext.
    pub fn validate(&self, credential: &str) -> Option<AuthContext> {
        // Both session tokens and API keys are matched by their SHA3-256 hash.
        let hash = sha3_256_hex(credential.as_bytes());

        // Session token first (looked up in the shared store).
        if let Some(session) = self.store.get_auth_session(&hash) {
            if session.expires_at > chrono::Utc::now() {
                return Some(AuthContext {
                    principal: session.username,
                    role: Role::parse(&session.role),
                    org: session.org,
                    method: "session",
                });
            }
            // Expired — drop it.
            self.store.delete_auth_session(&hash);
            return None;
        }

        // API key (config-defined; key_hash is the SHA3-256 hash of the key).
        if let Some(key) = self.config.api_keys.iter().find(|k| k.key_hash == hash) {
            return Some(AuthContext {
                principal: format!("apikey:{}", key.name),
                role: Role::parse(&key.role),
                org: key.org.clone(),
                method: "api-key",
            });
        }
        None
    }

    /// Best-effort removal of expired sessions/OIDC states (called periodically).
    pub fn purge_expired(&self) {
        self.store.purge_expired_auth(chrono::Utc::now());
    }
}

/// Resolve the tenant for a request from its auth context, else the default tenant.
pub fn tenant_of(ctx: &Option<axum::Extension<AuthContext>>) -> String {
    ctx.as_ref()
        .map(|c| c.org.clone())
        .unwrap_or_else(|| qw_store::DEFAULT_TENANT.to_string())
}

/// The minimum role required for a given request.
pub fn required_role(method: &axum::http::Method, path: &str) -> Role {
    use axum::http::Method;
    // Admin-only surfaces.
    if path.contains("/api/config") {
        return Role::Admin;
    }
    // Identity endpoints only need a valid session/key.
    if path.contains("/api/auth/me") || path.contains("/api/auth/logout") {
        return Role::Viewer;
    }
    match *method {
        Method::GET | Method::HEAD | Method::OPTIONS => Role::Viewer,
        _ => Role::Operator,
    }
}
