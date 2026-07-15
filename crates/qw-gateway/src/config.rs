use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_gateway")]
    pub gateway: ServerConfig,
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub monitor: MonitorConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub agents: HashMap<String, AgentConfig>,
    #[serde(default)]
    pub scanner: qw_scanner::ScannerConfig,
    #[serde(default)]
    pub integrations: Vec<qw_integrations::IntegrationConfig>,
    #[serde(default)]
    pub schedule: ScheduleConfig,
    /// Per-tenant scan schedules (interval + extra targets), overriding the global one.
    #[serde(default)]
    pub tenant_schedules: Vec<TenantScheduleConfig>,
    /// Posture SLOs / policy-as-code (gate CI, alert on breach).
    #[serde(default)]
    pub slos: Vec<SloConfig>,
    #[serde(default)]
    pub alerts: AlertConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    /// In-path proxy resilience (timeouts, retries, circuit breaking).
    #[serde(default)]
    pub resilience: ResilienceConfig,
    /// Declared external crypto assets (TLS endpoints, ingresses, etc.).
    #[serde(default)]
    pub assets: Vec<AssetConfig>,
    /// Agentless connectors that discover assets from cloud/K8s environments.
    #[serde(default)]
    pub connectors: Vec<ConnectorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetConfig {
    pub id: String,
    /// tls_endpoint | k8s_ingress | load_balancer | kms_key | certificate
    #[serde(default = "default_asset_kind")]
    pub kind: String,
    pub address: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// An agentless connector. Real cloud/K8s connectors would call the platform API;
/// here `endpoints` carries the discovered hosts (from a kubeconfig/cloud sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    pub name: String,
    /// kubernetes | aws | azure | gcp | generic
    pub connector_type: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_asset_kind() -> String {
    "tls_endpoint".to_string()
}
fn default_environment() -> String {
    "default".to_string()
}

/// Data-path resilience for the in-path proxy: how the gateway behaves when an
/// upstream LLM provider is slow, flaky, or down. The gateway sits on the
/// critical path of every request, so these knobs decide whether a degraded
/// upstream degrades the customer's product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceConfig {
    /// TCP connect timeout for upstream requests.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Total per-request timeout (connect + response). Bounds worst-case latency.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// Max retry attempts on a transport-level failure (never reached upstream).
    /// Non-idempotent completions are only retried when the request provably
    /// never hit the server (connect errors), so a retry can't double-charge.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Base backoff between retries (doubled each attempt).
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    /// Also retry on request timeout. Off by default: a timeout may mean the
    /// upstream did process the request, so retrying risks a duplicate call.
    #[serde(default)]
    pub retry_on_timeout: bool,
    /// Consecutive failures before a provider's circuit opens.
    #[serde(default = "default_circuit_threshold")]
    pub circuit_failure_threshold: u32,
    /// How long a circuit stays open before a half-open probe is allowed.
    #[serde(default = "default_circuit_cooldown")]
    pub circuit_cooldown_secs: u64,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            connect_timeout_secs: default_connect_timeout(),
            request_timeout_secs: default_request_timeout(),
            max_retries: default_max_retries(),
            retry_backoff_ms: default_retry_backoff_ms(),
            retry_on_timeout: false,
            circuit_failure_threshold: default_circuit_threshold(),
            circuit_cooldown_secs: default_circuit_cooldown(),
        }
    }
}

fn default_connect_timeout() -> u64 {
    10
}
fn default_request_timeout() -> u64 {
    120
}
fn default_max_retries() -> u32 {
    2
}
fn default_retry_backoff_ms() -> u64 {
    200
}
fn default_circuit_threshold() -> u32 {
    5
}
fn default_circuit_cooldown() -> u64 {
    30
}

/// Authentication & RBAC. Disabled by default for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_auth_session_ttl")]
    pub session_ttl_secs: u64,
    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
    /// Optional SSO / OpenID Connect provider (Okta, Entra ID, Auth0, Google…).
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    /// Inbound webhook secret (ENV var name) — GitHub HMAC / shared token.
    #[serde(default)]
    pub webhook_secret_env: Option<String>,
    /// Scheduled signed evidence-pack delivery to an external sink (S3/email/webhook).
    #[serde(default)]
    pub evidence_delivery: Option<EvidenceDeliveryConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceDeliveryConfig {
    #[serde(default = "default_delivery_interval")]
    pub interval_secs: u64,
    /// ENV var holding the sink URL (S3 presigned PUT, webhook, or email bridge).
    pub sink_url_env: String,
    /// Tenants to deliver for; empty = default only.
    #[serde(default)]
    pub tenants: Vec<String>,
}

fn default_delivery_interval() -> u64 {
    86_400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// e.g. https://your-org.okta.com or https://login.microsoftonline.com/<tenant>/v2.0
    pub issuer: String,
    pub client_id: String,
    /// ENV var holding the client secret.
    pub client_secret_env: String,
    /// The gateway callback, e.g. https://gw.example.com/api/auth/oidc/callback
    pub redirect_uri: String,
    /// Where to send the browser after login (the dashboard), token appended as ?sso=.
    #[serde(default = "default_app_url")]
    pub app_url: String,
    /// Claim carrying group memberships (default "groups").
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Group that grants admin / operator.
    #[serde(default)]
    pub admin_group: Option<String>,
    #[serde(default)]
    pub operator_group: Option<String>,
    /// Claim mapped to the tenant/org (e.g. "org" or a group). Falls back to default_org.
    #[serde(default)]
    pub org_claim: Option<String>,
    #[serde(default = "default_org")]
    pub default_org: String,
}

fn default_app_url() -> String {
    "/".to_string()
}
fn default_groups_claim() -> String {
    "groups".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub username: String,
    /// Argon2id PHC hash (generate with `qw hash-password`).
    pub password_hash: String,
    #[serde(default = "default_role")]
    pub role: String,
    /// Tenant/org this user's data is isolated to.
    #[serde(default = "default_org")]
    pub org: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    pub name: String,
    /// SHA3-256 hex of the API key (generate with `qw hash-password --api-key`).
    pub key_hash: String,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default = "default_org")]
    pub org: String,
}

fn default_auth_session_ttl() -> u64 {
    28_800
}
fn default_role() -> String {
    "viewer".to_string()
}
fn default_org() -> String {
    "default".to_string()
}

/// Background scheduled-scanning configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScheduleConfig {
    /// Interval in seconds between automatic re-scans. 0 disables scheduled scanning.
    #[serde(default)]
    pub scan_interval_secs: u64,
}

/// A posture SLO (service-level objective) — policy-as-code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloConfig {
    pub name: String,
    /// posture | critical_paths | compliance
    pub metric: String,
    /// gte | lte
    #[serde(default = "default_operator")]
    pub operator: String,
    pub threshold: f64,
    /// Applies to this org only; None = all tenants.
    #[serde(default)]
    pub tenant: Option<String>,
    /// alert | fail (fail gates CI via HTTP 422 on /api/slos?gate=1)
    #[serde(default = "default_slo_action")]
    pub action: String,
}

fn default_operator() -> String {
    "gte".to_string()
}
fn default_slo_action() -> String {
    "alert".to_string()
}

/// A per-tenant scan schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantScheduleConfig {
    pub org: String,
    #[serde(default)]
    pub scan_interval_secs: u64,
    /// Extra TLS endpoints scanned for this tenant only.
    #[serde(default)]
    pub targets: Vec<String>,
}

/// Alerting configuration — notifier channels and rule thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub channels: Vec<AlertChannelConfig>,
    /// Fire a posture_drop alert when the overall score falls by at least this many points.
    #[serde(default = "default_posture_drop")]
    pub posture_drop_threshold: f64,
    #[serde(default = "default_true")]
    pub alert_on_critical: bool,
    #[serde(default = "default_cert_days")]
    pub cert_expiry_days: u32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            channels: Vec::new(),
            posture_drop_threshold: default_posture_drop(),
            alert_on_critical: true,
            cert_expiry_days: default_cert_days(),
        }
    }
}

/// A notifier channel (generic webhook or Slack incoming webhook).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannelConfig {
    pub id: String,
    /// "webhook" | "slack"
    #[serde(default = "default_channel_type")]
    pub channel_type: String,
    pub url: String,
    /// Minimum severity to deliver: "info" | "warning" | "critical".
    #[serde(default)]
    pub min_severity: Option<String>,
}

fn default_posture_drop() -> f64 {
    5.0
}
fn default_cert_days() -> u32 {
    30
}
fn default_channel_type() -> String {
    "webhook".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
}

fn default_gateway() -> ServerConfig {
    ServerConfig {
        listen: default_listen(),
        admin_listen: default_admin_listen(),
    }
}

fn default_listen() -> String {
    "0.0.0.0:9090".to_string()
}
fn default_admin_listen() -> String {
    "0.0.0.0:9091".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub upstream: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub api_key_header: Option<String>,
}

fn default_protocol() -> String {
    "openai-compat".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    #[serde(default = "default_policy_path")]
    pub path: String,
    #[serde(default = "default_deny")]
    pub default: String,
}

fn default_policy_path() -> String {
    "./quantawatch.yaml".to_string()
}
fn default_deny() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_audit_path")]
    pub path: String,
    #[serde(default = "default_merkle_batch")]
    pub merkle_batch_size: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
            merkle_batch_size: default_merkle_batch(),
        }
    }
}

fn default_audit_path() -> String {
    "./audit".to_string()
}
fn default_merkle_batch() -> usize {
    64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    #[serde(default = "default_blocking_threshold")]
    pub blocking_threshold: String,
    #[serde(default = "default_true")]
    pub scan_responses: bool,
    #[serde(default = "default_true")]
    pub prompt_injection: bool,
    #[serde(default = "default_true")]
    pub data_exfiltration: bool,
    #[serde(default = "default_true")]
    pub pii_detection: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            blocking_threshold: default_blocking_threshold(),
            scan_responses: true,
            prompt_injection: true,
            data_exfiltration: true,
            pii_detection: true,
        }
    }
}

fn default_blocking_threshold() -> String {
    "high".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    #[serde(default = "default_session_ttl")]
    pub session_ttl: i64,
    #[serde(default = "default_key_dir")]
    pub key_dir: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            session_ttl: default_session_ttl(),
            key_dir: default_key_dir(),
        }
    }
}

fn default_session_ttl() -> i64 {
    3600
}
fn default_key_dir() -> String {
    "./keys".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub blocked_tools: Vec<String>,
    #[serde(default)]
    pub blocked_actions: Vec<String>,
    #[serde(default)]
    pub data_policy: Option<String>,
    #[serde(default)]
    pub max_tokens_per_session: Option<u64>,
    #[serde(default)]
    pub max_requests_per_minute: Option<u32>,
    #[serde(default)]
    pub offline: bool,
}

impl GatewayConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                tracing::warn!(path = %path, "Config file not found, using defaults");
                return Ok(Self::default());
            }
        };
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        let mut providers = HashMap::new();
        providers.insert(
            "anthropic".to_string(),
            ProviderConfig {
                upstream: "https://api.anthropic.com".to_string(),
                protocol: "anthropic".to_string(),
                api_key_env: Some("ANTHROPIC_API_KEY".to_string()),
                api_key_header: Some("x-api-key".to_string()),
            },
        );
        providers.insert(
            "openai".to_string(),
            ProviderConfig {
                upstream: "https://api.openai.com".to_string(),
                protocol: "openai".to_string(),
                api_key_env: Some("OPENAI_API_KEY".to_string()),
                api_key_header: Some("Authorization".to_string()),
            },
        );
        providers.insert(
            "ollama".to_string(),
            ProviderConfig {
                upstream: "http://localhost:11434".to_string(),
                protocol: "ollama".to_string(),
                api_key_env: None,
                api_key_header: None,
            },
        );

        Self {
            gateway: default_gateway(),
            providers,
            policy: PolicyConfig::default(),
            audit: AuditConfig::default(),
            monitor: MonitorConfig::default(),
            identity: IdentityConfig::default(),
            agents: HashMap::new(),
            scanner: qw_scanner::ScannerConfig::default(),
            integrations: Vec::new(),
            schedule: ScheduleConfig::default(),
            tenant_schedules: Vec::new(),
            slos: Vec::new(),
            alerts: AlertConfig::default(),
            auth: AuthConfig::default(),
            resilience: ResilienceConfig::default(),
            assets: Vec::new(),
            connectors: Vec::new(),
        }
    }
}
