//! Authentication, sessions, API keys, and RBAC.
//!
//! Disabled unless `auth.enabled` is set. When on, every admin request must
//! carry either a session bearer token (from `/api/auth/login`) or an API key,
//! and the caller's permission set must grant the route's required permission
//! (see [`crate::rbac`]). Failed logins are throttled by a shared-store lockout,
//! and sessions honor both an absolute TTL and an idle timeout.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use qw_crypto::{random_token, sha3_256_hex, verify_password};
use qw_store::Store;

use crate::config::AuthConfig;
use crate::rbac::{self, PermissionSet};

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

/// Result of a username/password login attempt.
pub enum LoginOutcome {
    Ok { token: String, role: Role, ttl: u64 },
    BadCredentials,
    LockedOut { retry_after_secs: u64 },
}

/// Injected into request extensions after successful auth.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub principal: String,
    /// Legacy coarse role (custom roles parse to their nearest built-in).
    pub role: Role,
    /// The raw role name as configured (may be a custom role).
    pub role_name: String,
    /// Resolved permission set for this caller (the RBAC decision surface).
    pub permissions: Arc<PermissionSet>,
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
    /// role name -> resolved permission set (built-ins + config custom roles).
    role_perms: HashMap<String, Arc<PermissionSet>>,
}

impl AuthManager {
    pub fn new(config: AuthConfig, store: Arc<Store>) -> Self {
        let role_perms = rbac::resolve_roles(&config.roles);
        Self {
            config,
            store,
            role_perms,
        }
    }

    /// Resolve a role name to its permission set; unknown roles get nothing
    /// (fail closed).
    fn perms_for(&self, role_name: &str) -> Arc<PermissionSet> {
        self.role_perms
            .get(&role_name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    /// Every configured role with its resolved permission patterns, sorted by
    /// name — powers the RBAC matrix in the dashboard.
    pub fn rbac_roles(&self) -> Vec<(String, Vec<String>)> {
        let mut v: Vec<(String, Vec<String>)> = self
            .role_perms
            .iter()
            .map(|(name, ps)| (name.clone(), ps.sorted()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Mint a token, persist the session keyed by the token's SHA3-256 hash
    /// (never the raw token), and return the token + its TTL in seconds.
    fn issue_session(&self, username: &str, role: Role, org: &str) -> (String, u64) {
        let token = random_token(32);
        let ttl = self.config.session_ttl_secs;
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl as i64);
        self.store.put_auth_session(
            &sha3_256_hex(token.as_bytes()),
            &qw_store::AuthSession {
                username: username.to_string(),
                role: role.label().to_string(),
                org: org.to_string(),
                expires_at,
                last_used: now,
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

    /// Authenticate a username/password and issue a session token. Enforces the
    /// failed-login lockout when `auth.max_failed_logins` is set.
    pub fn login(&self, username: &str, password: &str) -> LoginOutcome {
        let now = chrono::Utc::now();

        // Refuse early if the account is currently locked.
        if self.config.max_failed_logins > 0 {
            if let Some(st) = self.store.get_login_lockout(username) {
                if let Some(until) = st.locked_until {
                    if until > now {
                        let secs = (until - now).num_seconds().max(0) as u64;
                        return LoginOutcome::LockedOut {
                            retry_after_secs: secs,
                        };
                    }
                }
            }
        }

        // Config-declared users first, then runtime-managed (DB) users.
        let (role_name, org) =
            if let Some(u) = self.config.users.iter().find(|u| u.username == username) {
                if verify_password(password, &u.password_hash) {
                    (u.role.clone(), u.org.clone())
                } else {
                    self.record_login_failure(username, now);
                    return LoginOutcome::BadCredentials;
                }
            } else if let Some(u) = self.store.get_user(username) {
                if verify_password(password, &u.password_hash) {
                    (u.role, u.org)
                } else {
                    self.record_login_failure(username, now);
                    return LoginOutcome::BadCredentials;
                }
            } else {
                self.record_login_failure(username, now);
                return LoginOutcome::BadCredentials;
            };

        // Success — clear any accumulated failures.
        self.store.clear_login_lockout(username);
        let role = Role::parse(&role_name);
        let (token, ttl) = self.issue_session(username, role, &org);
        LoginOutcome::Ok { token, role, ttl }
    }

    /// Record a failed login and lock the account once the threshold is reached.
    fn record_login_failure(&self, username: &str, now: chrono::DateTime<chrono::Utc>) {
        if self.config.max_failed_logins == 0 {
            return;
        }
        let mut st = self
            .store
            .get_login_lockout(username)
            .unwrap_or(qw_store::LockoutState {
                failures: 0,
                first_failure_at: now,
                locked_until: None,
            });
        // A lapsed lock (or a fresh streak) resets the counter.
        if st.locked_until.map(|u| u <= now).unwrap_or(false) {
            st = qw_store::LockoutState {
                failures: 0,
                first_failure_at: now,
                locked_until: None,
            };
        }
        st.failures += 1;
        if st.failures >= self.config.max_failed_logins {
            st.locked_until =
                Some(now + chrono::Duration::seconds(self.config.lockout_secs as i64));
        }
        self.store.put_login_lockout(username, &st);
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
            let now = chrono::Utc::now();
            // Absolute TTL.
            if session.expires_at <= now {
                self.store.delete_auth_session(&hash);
                return None;
            }
            // Idle timeout: a session unused for too long is invalidated even
            // within its absolute TTL.
            if self.config.idle_timeout_secs > 0
                && (now - session.last_used)
                    > chrono::Duration::seconds(self.config.idle_timeout_secs as i64)
            {
                self.store.delete_auth_session(&hash);
                return None;
            }
            // Refresh last_used, but throttle the write (>60s drift) so we don't
            // write to the store on every single request.
            if (now - session.last_used) > chrono::Duration::seconds(60) {
                let mut updated = session.clone();
                updated.last_used = now;
                self.store.touch_auth_session(&hash, &updated);
            }
            return Some(AuthContext {
                principal: session.username,
                role: Role::parse(&session.role),
                role_name: session.role.clone(),
                permissions: self.perms_for(&session.role),
                org: session.org,
                method: "session",
            });
        }

        // API key (config-defined; key_hash is the SHA3-256 hash of the key).
        if let Some(key) = self.config.api_keys.iter().find(|k| k.key_hash == hash) {
            return Some(AuthContext {
                principal: format!("apikey:{}", key.name),
                role: Role::parse(&key.role),
                role_name: key.role.clone(),
                permissions: self.perms_for(&key.role),
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
