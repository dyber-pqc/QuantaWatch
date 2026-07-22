//! Runtime settings + admin center.
//!
//! Admin-tunable knobs that persist per tenant and take effect without a
//! restart — the scanning limits and guardrails a large organisation needs
//! (pause automated scanning, disable specific scanners, cap concurrency,
//! restrict what may be scanned, control outbound lookups). GET also returns
//! read-only "admin center" context (identity, tenants, access) for the page.

use axum::{extract::State, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

/// Admin-tunable runtime settings. `default` keeps it forward-compatible as
/// fields are added.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RuntimeSettings {
    /// Master switch: pause all automated/scheduled scanning.
    pub scanning_paused: bool,
    /// Scanner ids that are turned off (e.g. ["ct", "rdp"]).
    pub disabled_scanners: Vec<String>,
    /// Cap on concurrent scan work (0 = unlimited).
    pub max_scan_concurrency: u32,
    /// If non-empty, only hosts/domains matching one of these substrings may be
    /// actively scanned — a guardrail so a large estate can't be swept wholesale.
    pub scan_allowlist: Vec<String>,
    /// Days to retain findings before pruning (0 = keep forever).
    pub finding_retention_days: u32,
    /// Require explicit approval before an active (intrusive) scan runs.
    pub require_approval_for_active_scans: bool,
    /// Allow outbound lookups to third parties (crt.sh CT logs, connector APIs).
    pub external_lookups_enabled: bool,
    /// Kubernetes admission: when true, DENY workloads with quantum-vulnerable
    /// crypto; when false (default) admit them but return a warning (monitor).
    pub k8s_admission_enforce: bool,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            scanning_paused: false,
            disabled_scanners: Vec::new(),
            max_scan_concurrency: 8,
            scan_allowlist: Vec::new(),
            finding_retention_days: 0,
            require_approval_for_active_scans: false,
            external_lookups_enabled: true,
            k8s_admission_enforce: false,
        }
    }
}

/// Load a tenant's settings (defaults if never set).
pub fn load(state: &AppState, tenant: &str) -> RuntimeSettings {
    state
        .store
        .get_settings(tenant)
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

/// True if a scanner id is disabled for the tenant.
pub fn scanner_disabled(state: &AppState, tenant: &str, scanner_id: &str) -> bool {
    load(state, tenant)
        .disabled_scanners
        .iter()
        .any(|s| s.eq_ignore_ascii_case(scanner_id))
}

/// Known scanner ids the admin can toggle.
const KNOWN_SCANNERS: &[(&str, &str)] = &[
    ("tls", "TLS endpoints"),
    ("certificate", "X.509 certificates"),
    ("ssh", "SSH servers"),
    ("rdp", "RDP security layer"),
    ("starttls", "STARTTLS (SMTP/IMAP/PostgreSQL)"),
    ("network", "Network port sweep"),
    ("dependency", "Dependency manifests"),
    ("code", "Source code"),
    ("data_at_rest", "Data at rest"),
    ("ct", "Certificate transparency"),
];

/// GET /api/settings — current settings + admin-center context.
pub async fn get_settings(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let settings = load(&state, &tenant);

    let (principal, role) = ctx
        .as_ref()
        .map(|c| (c.principal.clone(), c.role_name.clone()))
        .unwrap_or_else(|| ("admin".into(), "admin".into()));

    let cfg = &state.config;
    let users: Vec<serde_json::Value> = cfg
        .auth
        .users
        .iter()
        .map(|u| json!({ "username": u.username, "role": u.role, "org": u.org }))
        .collect();
    let api_keys: Vec<serde_json::Value> = cfg
        .auth
        .api_keys
        .iter()
        .map(|k| json!({ "name": k.name, "role": k.role, "org": k.org }))
        .collect();
    let scanners: Vec<serde_json::Value> = KNOWN_SCANNERS
        .iter()
        .map(|(id, label)| {
            json!({
                "id": id,
                "label": label,
                "enabled": !settings.disabled_scanners.iter().any(|s| s.eq_ignore_ascii_case(id)),
            })
        })
        .collect();

    Json(json!({
        "settings": settings,
        "adminCenter": {
            "identity": principal,
            "role": role,
            "tenant": tenant,
            "authEnabled": state.auth_manager.enabled(),
            "users": users,
            "apiKeys": api_keys,
            "scanners": scanners,
            "airGapped": cfg.air_gapped,
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct UpdateSettings {
    #[serde(flatten)]
    settings: RuntimeSettings,
}

/// PUT /api/settings — persist admin-tunable settings for the tenant.
pub async fn put_settings(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<UpdateSettings>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let mut s = body.settings;
    // Clamp to sane bounds.
    s.max_scan_concurrency = s.max_scan_concurrency.min(256);
    s.finding_retention_days = s.finding_retention_days.min(3650);
    s.disabled_scanners
        .retain(|d| KNOWN_SCANNERS.iter().any(|(id, _)| id.eq_ignore_ascii_case(d)));

    let json = serde_json::to_string(&s).unwrap_or_default();
    state.store.put_settings(&tenant, &json);
    // The auth layer records this as an AdminAction (config:write) automatically.
    Json(json!({ "saved": true, "settings": s })).into_response()
}
