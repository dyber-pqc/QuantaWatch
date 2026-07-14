//! Authentication, sessions, API keys, and RBAC.
//!
//! Disabled unless `auth.enabled` is set. When on, every admin request must
//! carry either a session bearer token (from `/api/auth/login`) or an API key,
//! and the caller's role must meet the route's required role.

use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;

use qw_crypto::{random_token, sha3_256_hex, verify_password};

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

#[derive(Clone)]
struct Session {
    username: String,
    role: Role,
    org: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub struct AuthManager {
    config: AuthConfig,
    sessions: Arc<DashMap<String, Session>>,
    /// CSRF state nonces for the OIDC flow → expiry.
    oidc_states: Arc<DashMap<String, chrono::DateTime<chrono::Utc>>>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(DashMap::new()),
            oidc_states: Arc::new(DashMap::new()),
        }
    }

    /// Issue a session for an externally-authenticated (e.g. OIDC) principal.
    pub fn create_external_session(&self, username: &str, role: Role, org: &str) -> (String, u64) {
        let token = random_token(32);
        let ttl = self.config.session_ttl_secs;
        self.sessions.insert(token.clone(), Session {
            username: username.to_string(),
            role,
            org: org.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(ttl as i64),
        });
        (token, ttl)
    }

    /// Begin an OIDC flow: mint and remember a state nonce (10-min TTL).
    pub fn begin_oidc(&self) -> String {
        let state = random_token(16);
        self.oidc_states.insert(state.clone(), chrono::Utc::now() + chrono::Duration::minutes(10));
        state
    }

    /// Validate and consume an OIDC state nonce.
    pub fn consume_oidc_state(&self, state: &str) -> bool {
        match self.oidc_states.remove(state) {
            Some((_, exp)) => exp > chrono::Utc::now(),
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
        let token = random_token(32);
        let ttl = self.config.session_ttl_secs;
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
        self.sessions.insert(
            token.clone(),
            Session {
                username: username.to_string(),
                role,
                org: user.org.clone(),
                expires_at,
            },
        );
        Some((token, role, ttl))
    }

    pub fn logout(&self, token: &str) {
        self.sessions.remove(token);
    }

    /// Resolve a credential (session token or API key) to an AuthContext.
    pub fn validate(&self, credential: &str) -> Option<AuthContext> {
        // Session token first.
        if let Some(session) = self.sessions.get(credential) {
            if session.expires_at > chrono::Utc::now() {
                return Some(AuthContext {
                    principal: session.username.clone(),
                    role: session.role,
                    org: session.org.clone(),
                    method: "session",
                });
            }
            // Expired — drop it.
            drop(session);
            self.sessions.remove(credential);
            return None;
        }

        // API key (matched by SHA3-256 hash).
        let hash = sha3_256_hex(credential.as_bytes());
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
