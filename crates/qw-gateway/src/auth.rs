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

use qw_crypto::{hash_password, random_token, sha3_256_hex, verify_password};
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
    Ok {
        token: String,
        role: Role,
        ttl: u64,
    },
    /// Password was correct and the user has 2FA — a code is required next.
    /// `pending` is a short-lived token to present to `verify_totp_login`.
    TotpRequired {
        pending: String,
    },
    /// Password was correct but the user has no 2FA yet — they must enroll
    /// before a session is issued (2FA is mandatory).
    EnrollmentRequired {
        pending: String,
    },
    BadCredentials,
    LockedOut {
        retry_after_secs: u64,
    },
}

/// Handed to the client to render a TOTP QR / manual-entry secret during
/// enrollment.
pub struct EnrollInfo {
    pub secret: String,
    pub otpauth_url: String,
    /// Fresh pending token to present to `confirm_enrollment`.
    pub pending: String,
}

/// Result of confirming 2FA enrollment: a real session plus the one-time backup
/// codes (shown to the user exactly once).
pub struct EnrollResult {
    pub token: String,
    pub role: Role,
    pub ttl: u64,
    pub backup_codes: Vec<String>,
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

        // Password OK — clear any accumulated failures.
        self.store.clear_login_lockout(username);

        // Config-declared users are a break-glass path with no DB-stored 2FA
        // (the config is read-only). They get a session directly; the mandatory
        // 2FA policy applies to runtime (DB) users, which is the normal path.
        if self.config.users.iter().any(|u| u.username == username) {
            let role = Role::parse(&role_name);
            let (token, ttl) = self.issue_session(username, role, &org);
            return LoginOutcome::Ok { token, role, ttl };
        }

        // DB users: enforce 2FA. Enrolled -> require a code; not yet -> enroll.
        let enrolled = self
            .store
            .get_user(username)
            .map(|u| u.totp_enabled)
            .unwrap_or(false);
        if enrolled {
            LoginOutcome::TotpRequired {
                pending: self.issue_pending(username, "verify"),
            }
        } else {
            LoginOutcome::EnrollmentRequired {
                pending: self.issue_pending(username, "enroll"),
            }
        }
    }

    /// Mint a short-lived pending token for a two-step login (2FA verify) or
    /// first-login/setup enrollment. Persisted by its SHA3-256 hash.
    fn issue_pending(&self, username: &str, kind: &str) -> String {
        let token = random_token(32);
        self.store.put_mfa_pending(
            &sha3_256_hex(token.as_bytes()),
            &qw_store::MfaPending {
                username: username.to_string(),
                kind: kind.to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
            },
        );
        token
    }

    /// True when no users exist at all (config or DB) — a fresh install that must
    /// run first-time setup before it can be used.
    pub fn setup_required(&self) -> bool {
        self.config.users.is_empty() && self.store.list_users().is_empty()
    }

    /// First-run setup: create the initial admin. Refuses once any user exists
    /// (so this can't be used to add an admin to a live system). Returns an
    /// enrollment pending token — the admin must set up 2FA to finish.
    pub fn setup_admin(&self, username: &str, password: &str) -> Result<String, String> {
        if !self.setup_required() {
            return Err("setup already completed".to_string());
        }
        let username = username.trim();
        if username.is_empty() {
            return Err("username is required".to_string());
        }
        if password.chars().count() < 12 {
            return Err("password must be at least 12 characters".to_string());
        }
        let password_hash = hash_password(password).map_err(|e| format!("hash: {e}"))?;
        let user = qw_store::DbUser {
            username: username.to_string(),
            role: "admin".to_string(),
            org: qw_store::DEFAULT_TENANT.to_string(),
            password_hash,
            created_at: chrono::Utc::now(),
            totp_secret: None,
            totp_enabled: false,
            backup_code_hashes: Vec::new(),
        };
        self.store.upsert_user(&user);
        Ok(self.issue_pending(username, "enroll"))
    }

    /// Step 2 of login for an enrolled user: verify a TOTP code (or a one-time
    /// backup code) against the pending challenge and issue a session.
    pub fn verify_totp_login(&self, pending_token: &str, code: &str) -> LoginOutcome {
        let Some(p) = self
            .store
            .consume_mfa_pending(&sha3_256_hex(pending_token.as_bytes()))
            .filter(|p| p.kind == "verify")
        else {
            return LoginOutcome::BadCredentials;
        };
        let Some(mut user) = self.store.get_user(&p.username) else {
            return LoginOutcome::BadCredentials;
        };
        let secret = user.totp_secret.clone().unwrap_or_default();
        let ok = crate::mfa::verify_totp(&secret, &p.username, code)
            || self.consume_backup_code(&mut user, code);
        if !ok {
            self.record_login_failure(&p.username, chrono::Utc::now());
            return LoginOutcome::BadCredentials;
        }
        let role = Role::parse(&user.role);
        let (token, ttl) = self.issue_session(&p.username, role, &user.org);
        LoginOutcome::Ok { token, role, ttl }
    }

    /// If `code` matches one of the user's backup codes, consume it (single-use)
    /// and return true.
    fn consume_backup_code(&self, user: &mut qw_store::DbUser, code: &str) -> bool {
        let h = crate::mfa::hash_backup_code(code);
        if let Some(pos) = user.backup_code_hashes.iter().position(|x| *x == h) {
            user.backup_code_hashes.remove(pos);
            self.store.upsert_user(user);
            true
        } else {
            false
        }
    }

    /// Begin 2FA enrollment: validate the enroll pending, persist a (disabled)
    /// TOTP secret on the user, and hand back the secret + otpauth URL plus a
    /// fresh pending token for `confirm_enrollment`. Re-uses an existing unenabled
    /// secret so retries keep the same QR.
    pub fn begin_enrollment(&self, pending_token: &str) -> Option<EnrollInfo> {
        let p = self
            .store
            .consume_mfa_pending(&sha3_256_hex(pending_token.as_bytes()))
            .filter(|p| p.kind == "enroll")?;
        let mut user = self.store.get_user(&p.username)?;
        let secret = user
            .totp_secret
            .clone()
            .filter(|_| !user.totp_enabled)
            .unwrap_or_else(crate::mfa::generate_secret);
        let otpauth_url = crate::mfa::otpauth_url(&secret, &p.username).ok()?;
        user.totp_secret = Some(secret.clone());
        user.totp_enabled = false;
        self.store.upsert_user(&user);
        Some(EnrollInfo {
            secret,
            otpauth_url,
            pending: self.issue_pending(&p.username, "enroll"),
        })
    }

    /// Confirm enrollment: verify the first code against the pending secret, then
    /// enable 2FA, mint one-time backup codes, and issue a session.
    pub fn confirm_enrollment(&self, pending_token: &str, code: &str) -> Option<EnrollResult> {
        let p = self
            .store
            .consume_mfa_pending(&sha3_256_hex(pending_token.as_bytes()))
            .filter(|p| p.kind == "enroll")?;
        let mut user = self.store.get_user(&p.username)?;
        let secret = user.totp_secret.clone()?;
        if !crate::mfa::verify_totp(&secret, &p.username, code) {
            return None;
        }
        let (plain, hashes) = crate::mfa::generate_backup_codes();
        user.totp_enabled = true;
        user.backup_code_hashes = hashes;
        self.store.upsert_user(&user);
        let role = Role::parse(&user.role);
        let (token, ttl) = self.issue_session(&p.username, role, &user.org);
        Some(EnrollResult {
            token,
            role,
            ttl,
            backup_codes: plain,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;

    fn mgr() -> AuthManager {
        let store = Arc::new(qw_store::Store::open_in_memory().unwrap());
        let config = AuthConfig {
            enabled: true,
            ..Default::default()
        };
        AuthManager::new(config, store)
    }

    fn totp_pending(m: &AuthManager, user: &str, pw: &str) -> String {
        match m.login(user, pw) {
            LoginOutcome::TotpRequired { pending } => pending,
            _ => panic!("expected TotpRequired"),
        }
    }

    #[test]
    fn setup_enroll_login_verify_and_backup_codes() {
        let m = mgr();
        assert!(m.setup_required(), "fresh install needs setup");

        // First-run setup creates the admin; returns an enrollment challenge.
        let pending = m.setup_admin("admin", "correct horse battery").unwrap();
        assert!(
            !m.setup_required(),
            "setup no longer required once a user exists"
        );
        // Setup is locked after the first user — no adding admins to a live system.
        assert!(m.setup_admin("intruder", "another password!!").is_err());

        // Enroll: obtain a secret, produce a valid code, confirm 2FA on.
        let info = m.begin_enrollment(&pending).expect("begin enrollment");
        let code = crate::mfa::current_code(&info.secret, "admin");
        let res = m
            .confirm_enrollment(&info.pending, &code)
            .expect("confirm enrollment");
        assert!(!res.token.is_empty());
        assert_eq!(res.backup_codes.len(), crate::mfa::BACKUP_CODE_COUNT);
        let backup0 = res.backup_codes[0].clone();

        // Password alone no longer yields a session — 2FA is required.
        let p1 = totp_pending(&m, "admin", "correct horse battery");
        assert!(matches!(
            m.login("admin", "wrong"),
            LoginOutcome::BadCredentials
        ));

        // A valid TOTP code upgrades the pending challenge to a session.
        let code2 = crate::mfa::current_code(&info.secret, "admin");
        assert!(matches!(
            m.verify_totp_login(&p1, &code2),
            LoginOutcome::Ok { .. }
        ));

        // A backup code also works — exactly once.
        let p2 = totp_pending(&m, "admin", "correct horse battery");
        assert!(matches!(
            m.verify_totp_login(&p2, &backup0),
            LoginOutcome::Ok { .. }
        ));
        let p3 = totp_pending(&m, "admin", "correct horse battery");
        assert!(
            matches!(
                m.verify_totp_login(&p3, &backup0),
                LoginOutcome::BadCredentials
            ),
            "a backup code must not be reusable"
        );
    }

    #[test]
    fn pending_token_is_single_use_and_typed() {
        let m = mgr();
        let pending = m.setup_admin("admin", "correct horse battery").unwrap();
        // An enroll pending can't be used at the verify step.
        assert!(matches!(
            m.verify_totp_login(&pending, "000000"),
            LoginOutcome::BadCredentials
        ));
        // ...and it was consumed, so a subsequent begin_enrollment fails.
        assert!(m.begin_enrollment(&pending).is_none());
    }
}
