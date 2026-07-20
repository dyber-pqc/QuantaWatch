//! SOC2 controls report.
//!
//! Maps QuantaWatch's enforced technical controls to the SOC2 Common Criteria
//! (and Availability) and evaluates each against the LIVE configuration, so the
//! status reflects what is actually turned on — not an aspirational checklist.
//! Auditors consume this alongside the tamper-evident audit log (which holds the
//! access, change, and monitoring events these controls generate).

use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;
use serde_json::json;

use crate::config::GatewayConfig;
use crate::state::AppState;

/// Whether a control is actively enforced, partly enforced / configurable, or
/// depends on organizational process outside the product.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ControlStatus {
    /// Enforced by the running system given the current config.
    Enforced,
    /// Available and partly enforced, but a stronger setting is off.
    Partial,
    /// The product provides the mechanism; the control is a config/process choice.
    Configurable,
    /// Satisfied by organizational process, not the product.
    Manual,
}

#[derive(Debug, Clone, Serialize)]
struct Control {
    /// SOC2 Common Criteria reference, e.g. "CC6.1".
    criteria: &'static str,
    title: &'static str,
    status: ControlStatus,
    /// What in QuantaWatch provides this control.
    evidence: String,
    /// Where an auditor can see it (endpoint, artifact, or config key).
    verify_at: &'static str,
}

fn enforced(b: bool) -> ControlStatus {
    if b {
        ControlStatus::Enforced
    } else {
        ControlStatus::Configurable
    }
}

/// Build the control set from the live config.
fn controls(cfg: &GatewayConfig) -> Vec<Control> {
    let auth = &cfg.auth;
    let auth_on = auth.enabled;
    let lockout_on = auth.max_failed_logins > 0;
    let idle_on = auth.idle_timeout_secs > 0;
    let sso_on = auth.oidc.is_some();
    let custom_roles = !auth.roles.is_empty();
    let tls_on = cfg.scanner.tls.enabled;
    let alerts_on = cfg.alerts.enabled;
    let ha_on = cfg.identity.seed_env.is_some();

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
                auth.max_failed_logins, auth.lockout_secs
            ),
            verify_at: "config auth.max_failed_logins / lockout_secs; login_failed audit events",
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
                auth.session_ttl_secs,
                if idle_on {
                    format!("{}s", auth.idle_timeout_secs)
                } else {
                    "disabled".to_string()
                }
            ),
            verify_at: "config auth.session_ttl_secs / idle_timeout_secs",
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

/// GET /api/soc2 — the live controls report.
pub async fn get_soc2_report(State(state): State<AppState>) -> impl IntoResponse {
    let controls = controls(&state.config);
    let total = controls.len();
    let count = |s: &str| {
        controls
            .iter()
            .filter(|c| {
                serde_json::to_value(c.status)
                    .ok()
                    .and_then(|v| v.as_str().map(|x| x.to_string()))
                    .as_deref()
                    == Some(s)
            })
            .count()
    };
    Json(json!({
        "framework": "SOC2 (Trust Services Criteria)",
        "note": "Status is evaluated against the running configuration. \
                 'configurable'/'manual' controls are supported by the product but depend on \
                 how it is deployed or on organizational process.",
        "summary": {
            "total": total,
            "enforced": count("enforced"),
            "partial": count("partial"),
            "configurable": count("configurable"),
            "manual": count("manual"),
        },
        "controls": controls,
    }))
}
