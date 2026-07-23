//! SOC2 Trust Services Criteria controls, evaluated against a QuantaWatch
//! deployment. Shared by the gateway (live config) and the desktop app so both
//! render the same control set. Callers pass a [`Soc2Inputs`] snapshot of what
//! is actually enabled; the status reflects reality, not an aspirational list.

use serde::Serialize;

/// Whether a control is actively enforced, partly enforced / configurable, or
/// depends on organizational process outside the product.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Enforced,
    Partial,
    Configurable,
    Manual,
}

#[derive(Debug, Clone, Serialize)]
pub struct Control {
    /// SOC2 Common Criteria reference, e.g. "CC6.1".
    pub criteria: &'static str,
    pub title: &'static str,
    pub status: ControlStatus,
    pub evidence: String,
    pub verify_at: &'static str,
}

/// A snapshot of the deployment's enforced settings.
pub struct Soc2Inputs {
    pub auth_enabled: bool,
    pub max_failed_logins: u32,
    pub lockout_secs: u64,
    pub session_ttl_secs: u64,
    pub idle_timeout_secs: u64,
    pub sso_enabled: bool,
    pub custom_roles: bool,
    pub tls_scanner_enabled: bool,
    pub alerts_enabled: bool,
    pub shared_identity: bool,
}

/// The controls plus a status tally.
pub struct Soc2Report {
    pub controls: Vec<Control>,
    pub enforced: usize,
    pub partial: usize,
    pub configurable: usize,
    pub manual: usize,
}

fn enforced(b: bool) -> ControlStatus {
    if b {
        ControlStatus::Enforced
    } else {
        ControlStatus::Configurable
    }
}

/// Build the control set from a deployment snapshot.
pub fn controls(i: &Soc2Inputs) -> Vec<Control> {
    let auth_on = i.auth_enabled;
    let lockout_on = i.max_failed_logins > 0;
    let idle_on = i.idle_timeout_secs > 0;
    let sso_on = i.sso_enabled;
    let custom_roles = i.custom_roles;
    let tls_on = i.tls_scanner_enabled;
    let alerts_on = i.alerts_enabled;
    let ha_on = i.shared_identity;

    vec![
        // ---- CC6: Logical & physical access ----
        Control {
            criteria: "CC6.1",
            title: "Logical access control (RBAC)",
            status: enforced(auth_on),
            evidence: format!(
                "Permission-based RBAC: each route requires a `resource:action` permission; \
                 built-in viewer/auditor/operator/admin roles{}. auth.enabled={}",
                if custom_roles {
                    " plus custom least-privilege roles"
                } else {
                    ""
                },
                auth_on
            ),
            verify_at: "GET /api/auth/me (permissions), config auth.roles",
        },
        Control {
            criteria: "CC6.1",
            title: "Password strength policy",
            status: ControlStatus::Enforced,
            evidence: "Argon2id password hashing; `qw hash-password` enforces a minimum \
                       length (default 12) unless --allow-weak."
                .to_string(),
            verify_at: "qw hash-password, config auth.min_password_length",
        },
        Control {
            criteria: "CC6.1",
            title: "Brute-force protection (account lockout)",
            status: enforced(lockout_on),
            evidence: format!(
                "Failed-login lockout after {} attempts for {}s, stored in the shared \
                 store so it holds across all replicas.",
                i.max_failed_logins, i.lockout_secs
            ),
            verify_at: "config i.max_failed_logins / lockout_secs; login_failed audit events",
        },
        Control {
            criteria: "CC6.1",
            title: "Single sign-on / MFA delegation",
            status: if sso_on {
                ControlStatus::Enforced
            } else {
                ControlStatus::Configurable
            },
            evidence: format!(
                "OIDC SSO (Okta/Entra/Auth0/Google); MFA is enforced by the IdP. configured={sso_on}"
            ),
            verify_at: "config auth.oidc; GET /api/auth/oidc/login",
        },
        Control {
            criteria: "CC6.3",
            title: "Least privilege & role separation",
            status: enforced(auth_on),
            evidence: "Distinct read/write permissions per resource; operators cannot read or \
                       write config; custom roles can be scoped to an explicit permission set."
                .to_string(),
            verify_at: "crate rbac.rs; config auth.roles",
        },
        Control {
            criteria: "CC6.6",
            title: "Encryption of data in transit",
            status: enforced(tls_on),
            evidence: "Upstream provider links use TLS; the crypto scanner fingerprints TLS \
                       versions/ciphers and flags quantum-vulnerable transport."
                .to_string(),
            verify_at: "GET /api/posture; config scanner.tls",
        },
        Control {
            criteria: "CC6.7",
            title: "Session management (TTL + idle timeout)",
            status: if idle_on {
                ControlStatus::Enforced
            } else {
                ControlStatus::Partial
            },
            evidence: format!(
                "Absolute session TTL {}s; idle timeout {}. Tokens are stored only as SHA3-256 \
                 hashes.",
                i.session_ttl_secs,
                if idle_on {
                    format!("{}s", i.idle_timeout_secs)
                } else {
                    "disabled".to_string()
                }
            ),
            verify_at: "config i.session_ttl_secs / idle_timeout_secs",
        },
        // ---- CC7: System monitoring ----
        Control {
            criteria: "CC7.2",
            title: "Access monitoring / logging",
            status: enforced(auth_on),
            evidence: "Login success/failure, logout, and RBAC access-denied events are written \
                       to the tamper-evident audit log with principal, IP, and outcome."
                .to_string(),
            verify_at: "GET /api/audit (login_succeeded, login_failed, access_denied)",
        },
        Control {
            criteria: "CC7.2",
            title: "Threat detection in the data path",
            status: ControlStatus::Enforced,
            evidence: "In-path monitor inspects every LLM request/response for prompt injection, \
                       data exfiltration, and PII, blocking at the configured severity."
                .to_string(),
            verify_at: "config monitor; threat_blocked / policy_violation audit events",
        },
        Control {
            criteria: "CC7.3",
            title: "Alerting on security events",
            status: enforced(alerts_on),
            evidence: format!(
                "Continuous-attestation alerting to Slack/webhook on posture drops and \
                 critical findings. enabled={alerts_on}"
            ),
            verify_at: "config alerts; POST /api/alerts/test",
        },
        Control {
            criteria: "CC7.1",
            title: "Configuration drift detection",
            status: ControlStatus::Enforced,
            evidence: "Crypto-agility governance gate and deterministic self-CBOM detect drift \
                       from the target posture; CI can block on regression."
                .to_string(),
            verify_at: "GET /api/governance?gate=1; GET /api/slos?gate=1",
        },
        // ---- CC8: Change management ----
        Control {
            criteria: "CC8.1",
            title: "Change tracking (admin actions)",
            status: enforced(auth_on),
            evidence: "Every successful mutating admin action is recorded as an admin_action \
                       audit event (principal, method, path, permission). Runtime config is \
                       declarative (GitOps) — changes are tracked in version control."
                .to_string(),
            verify_at: "GET /api/audit (admin_action)",
        },
        Control {
            criteria: "CC8.1",
            title: "Audit-trail integrity",
            status: ControlStatus::Enforced,
            evidence: "Audit entries form a SHA3-256 hash chain batched into Merkle roots and \
                       signed with the gateway's ML-DSA-65 (FIPS 204) identity; the sharded \
                       multi-writer log stays verifiable across active/active replicas."
                .to_string(),
            verify_at: "POST /api/audit/verify; GET /api/audit/export",
        },
        // ---- A1: Availability ----
        Control {
            criteria: "A1.2",
            title: "High availability / no single point of failure",
            status: if ha_on {
                ControlStatus::Enforced
            } else {
                ControlStatus::Configurable
            },
            evidence: format!(
                "Shared signing identity (KMS/Secret seed), shared Postgres store, \
                 stateless sessions, and a sharded multi-writer audit log allow active/active \
                 replicas. shared_identity={ha_on}"
            ),
            verify_at: "config identity.seed_env, scanner.store_path (postgres://)",
        },
        // ---- Process controls the product supports but does not enforce ----
        Control {
            criteria: "CC6.2",
            title: "User provisioning / de-provisioning",
            status: ControlStatus::Manual,
            evidence: "Users and API keys are declared in config (GitOps-reviewed). Joiner/mover/\
                       leaver is an organizational process."
                .to_string(),
            verify_at: "config auth.users / auth.api_keys (version control)",
        },
    ]
}

/// Full report: controls + a tally by status.
pub fn assess(i: &Soc2Inputs) -> Soc2Report {
    let controls = controls(i);
    let count = |m: fn(&ControlStatus) -> bool| controls.iter().filter(|c| m(&c.status)).count();
    Soc2Report {
        enforced: count(|s| matches!(s, ControlStatus::Enforced)),
        partial: count(|s| matches!(s, ControlStatus::Partial)),
        configurable: count(|s| matches!(s, ControlStatus::Configurable)),
        manual: count(|s| matches!(s, ControlStatus::Manual)),
        controls,
    }
}
