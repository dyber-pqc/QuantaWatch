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
    /// Crypto-agility governance policy (target state + deadline). Evaluated at
    /// `GET /api/governance`; `?gate=1` fails CI on a policy violation.
    #[serde(default)]
    pub crypto_policy: qw_cbom::CryptoPolicy,
    /// Actionable crypto-agility policies (selector + match + action + deadline).
    /// Evaluated at `GET /api/crypto-policies`; enforced via connectors. Empty =
    /// a built-in CNSA-2.0-aligned default set.
    #[serde(default)]
    pub crypto_policies: Vec<qw_cbom::CryptoAgilityPolicy>,
    /// PQC-terminating proxy overlay: front legacy upstreams with a hybrid-PQC
    /// TLS listener so the client leg is quantum-safe without touching the
    /// upstream. Off by default.
    #[serde(default)]
    pub overlay: OverlayConfig,
    /// Internal PQC certificate authority: issue hybrid (classical X.509 +
    /// ML-DSA-65 binding) certs and auto-rotate them before expiry.
    #[serde(default)]
    pub pki: PkiConfig,
    /// CBOM attestation root of trust.
    #[serde(default)]
    pub attestation: AttestationConfig,
    /// Air-gapped mode: refuse ALL outbound network calls except the configured
    /// LLM provider upstreams (which in an air-gapped site are themselves
    /// internal). Disables alert webhooks, evidence-pack delivery, cloud
    /// connector discovery, and outbound integration calls (GitHub/Jira/...).
    /// Alerts and findings are still recorded locally and remain visible in the
    /// UI and via the pull-based SIEM export — nothing leaves the enclave.
    #[serde(default)]
    pub air_gapped: bool,
    /// Declared external crypto assets (TLS endpoints, ingresses, etc.).
    #[serde(default)]
    pub assets: Vec<AssetConfig>,
    /// Agentless connectors that discover assets from cloud/K8s environments.
    #[serde(default)]
    pub connectors: Vec<ConnectorConfig>,
    /// In-path PQC enforcement: hold agent→provider flows to a crypto standard.
    #[serde(default)]
    pub crypto_enforcement: CryptoEnforcementConfig,
    /// Per-client rate limiting for the public listeners (on by default).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

/// Per-client (per-IP) token-bucket rate limiting. Protects the in-path proxy
/// from floods and slows credential brute-forcing on the login endpoint. The
/// general API and the login/SSO endpoints get independent buckets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Sustained general-API budget per client IP, per minute.
    #[serde(default = "default_rl_rpm")]
    pub requests_per_minute: u32,
    /// General-API burst ceiling — set high enough for a dashboard page-load
    /// fan-out (many API calls at once) not to trip the limit.
    #[serde(default = "default_rl_burst")]
    pub burst: u32,
    /// Sustained login/SSO budget per client IP, per minute (much tighter).
    #[serde(default = "default_rl_login_rpm")]
    pub login_per_minute: u32,
    /// Login/SSO burst ceiling.
    #[serde(default = "default_rl_login_burst")]
    pub login_burst: u32,
    /// Trust `X-Forwarded-For` / `X-Real-IP` for the client identity. Enable
    /// ONLY when a trusted reverse proxy sets these — otherwise a client can
    /// spoof its rate-limit key.
    #[serde(default)]
    pub trust_forwarded_for: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: default_rl_rpm(),
            burst: default_rl_burst(),
            login_per_minute: default_rl_login_rpm(),
            login_burst: default_rl_login_burst(),
            trust_forwarded_for: false,
        }
    }
}

fn default_rl_rpm() -> u32 {
    1200
}
fn default_rl_burst() -> u32 {
    240
}
fn default_rl_login_rpm() -> u32 {
    30
}
fn default_rl_login_burst() -> u32 {
    10
}

/// In-path crypto enforcement policy. The gateway evaluates each request's
/// upstream channel PQC posture and either flags (monitor) or blocks (enforce)
/// flows whose channel is below the required standard. This is the moat a
/// passive, agentless scanner cannot follow — enforcement in the live data path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEnforcementConfig {
    #[serde(default)]
    pub enabled: bool,
    /// "monitor" (flag + header, allow) or "enforce" (block below the bar).
    #[serde(default = "default_enf_mode")]
    pub mode: String,
    /// Minimum acceptable channel posture: "pqc" | "hybrid" | "classical_secure".
    #[serde(default = "default_enf_require")]
    pub require: String,
    /// Providers exempt from enforcement (accepted as-is for now).
    #[serde(default)]
    pub exempt_providers: Vec<String>,
    /// In enforce mode, block providers whose channel hasn't been scanned yet.
    #[serde(default)]
    pub block_unknown: bool,
}

impl Default for CryptoEnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_enf_mode(),
            require: default_enf_require(),
            exempt_providers: vec![],
            block_unknown: false,
        }
    }
}

fn default_enf_mode() -> String {
    "monitor".to_string()
}
fn default_enf_require() -> String {
    "hybrid".to_string()
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
    /// Business context — what this asset means to the organization. Lets
    /// findings be ranked by business impact ("a quantum-vulnerable cert on
    /// checkout") rather than by algorithm severity alone.
    #[serde(default)]
    pub application: Option<String>,
    /// critical | high | medium | low. Absent -> unknown (ranked as medium).
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub data_classification: Option<String>,
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

/// CBOM attestation root of trust. `software` (default) self-signs with the
/// gateway identity; `synthetic-tpm` demonstrates a hardware-style AK→CA
/// certificate chain; `tpm2`/`nitro`/`sev-snp`/`tdx` are reserved for real
/// hardware backends (fall back to software until wired).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    #[serde(default = "default_attestation_provider")]
    pub provider: String,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            provider: default_attestation_provider(),
        }
    }
}

fn default_attestation_provider() -> String {
    "software".to_string()
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
    /// Custom RBAC roles: role name -> permission patterns (`resource:action`,
    /// `*` wildcards allowed). Layered on top of the built-in viewer/auditor/
    /// operator/admin roles; a custom role may reuse a built-in name to override.
    #[serde(default)]
    pub roles: std::collections::HashMap<String, Vec<String>>,
    /// Lock an account after this many consecutive failed logins (0 = disabled).
    #[serde(default = "default_max_failed_logins")]
    pub max_failed_logins: u32,
    /// How long a lockout lasts, in seconds.
    #[serde(default = "default_lockout_secs")]
    pub lockout_secs: u64,
    /// Minimum length enforced when hashing a password via `qw hash-password`.
    #[serde(default = "default_min_password_len")]
    pub min_password_length: usize,
    /// Idle-session timeout in seconds: a session unused for this long is
    /// invalidated even if within its absolute TTL (0 = disabled).
    #[serde(default)]
    pub idle_timeout_secs: u64,
}

fn default_max_failed_logins() -> u32 {
    5
}
fn default_lockout_secs() -> u64 {
    900
}
fn default_min_password_len() -> usize {
    12
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
    /// Directory of the built dashboard (Vite `dist`). When set and present, the
    /// admin listener serves the SPA at `/` so the UI needs no separate server.
    /// Defaults to `<exe dir>/dashboard` if that exists.
    #[serde(default)]
    pub dashboard_dir: Option<String>,
    /// Optional HTTPS termination for both listeners. When set, the proxy and
    /// admin listeners serve TLS (rustls / aws-lc-rs) instead of plain HTTP.
    /// Leave unset only when TLS is terminated by a trusted reverse proxy in
    /// front of the gateway.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// PEM certificate + private key for the gateway's HTTPS listeners.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM certificate chain (leaf first).
    pub cert_file: String,
    /// Path to the PEM private key (PKCS#8 or RSA).
    pub key_file: String,
}

fn default_gateway() -> ServerConfig {
    ServerConfig {
        listen: default_listen(),
        admin_listen: default_admin_listen(),
        dashboard_dir: None,
        tls: None,
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
    /// Stable, per-replica id for this gateway's audit chain (sharded model).
    /// Must be unique across replicas and stable across restarts of the same
    /// one. Empty = resolve from `QW_AUDIT_WRITER_ID`, else `HOSTNAME`, else
    /// `node-0`.
    #[serde(default)]
    pub writer_id: String,
    /// How often to commit a global audit checkpoint (Merkle root over all
    /// writers' tips). 0 disables periodic checkpoints.
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval_secs: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
            merkle_batch_size: default_merkle_batch(),
            writer_id: String::new(),
            checkpoint_interval_secs: default_checkpoint_interval(),
        }
    }
}

fn default_audit_path() -> String {
    "./audit".to_string()
}
fn default_merkle_batch() -> usize {
    64
}
fn default_checkpoint_interval() -> u64 {
    300
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
    /// ENV var holding the gateway's signing identity as a hex-encoded 32-byte
    /// seed. Point this at a Kubernetes Secret / KMS-injected value so every
    /// replica derives the SAME identity — required to run more than one
    /// gateway, and to keep the audit chain verifiable across restarts.
    /// Falls back to `key_dir` when unset.
    #[serde(default)]
    pub seed_env: Option<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            session_ttl: default_session_ttl(),
            key_dir: default_key_dir(),
            seed_env: None,
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

/// Argon2id hashes shipped in the demo/example configs (all seeded users share
/// one). Binding a public interface with any of these is refused — see
/// [`GatewayConfig::assert_deployment_safe`].
const KNOWN_DEMO_PASSWORD_HASHES: &[&str] = &[
    "$argon2id$v=19$m=19456,t=2,p=1$y+c9QhEj8VLbf+QRdDuw3Q$PpaXX3epVs7e5MkGrlflmwECJkCQzljfqvQ+WH9HKu8",
];

/// True if `addr` (host:port) binds anything other than the loopback interface,
/// i.e. it may be reachable from another host. `0.0.0.0` / `::` count as public.
fn is_public_bind(addr: &str) -> bool {
    // Strip the port; handle bracketed IPv6 (`[::1]:9091`).
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr).trim();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    !(host == "127.0.0.1" || host.starts_with("127.") || host == "localhost" || host == "::1")
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

    /// Fail closed before a public bind with insecure credentials. Refuses to
    /// start when a non-loopback listener is combined with authentication that
    /// is disabled, uses a known demo password hash, or reuses one hash across
    /// users (the copy-pasted-demo-credentials signature). Loopback-only
    /// deployments (the local demo) are always allowed. Set
    /// `QW_ALLOW_DEMO_CREDENTIALS=1` to override for a deliberate lab exposure.
    pub fn assert_deployment_safe(&self) -> Result<()> {
        let public =
            is_public_bind(&self.gateway.listen) || is_public_bind(&self.gateway.admin_listen);
        if !public {
            return Ok(());
        }
        if std::env::var("QW_ALLOW_DEMO_CREDENTIALS").is_ok() {
            tracing::warn!(
                "QW_ALLOW_DEMO_CREDENTIALS is set: skipping the insecure-credential check on a \
                 public listener. Do NOT use this in production."
            );
            return Ok(());
        }

        if !self.auth.enabled {
            anyhow::bail!(
                "refusing to bind a non-loopback interface ({} / {}) with authentication \
                 DISABLED. Enable `auth` with real users, bind to 127.0.0.1 behind a trusted \
                 proxy, or set QW_ALLOW_DEMO_CREDENTIALS=1 to override.",
                self.gateway.listen,
                self.gateway.admin_listen
            );
        }

        let mut seen = std::collections::HashSet::new();
        for u in &self.auth.users {
            if KNOWN_DEMO_PASSWORD_HASHES.contains(&u.password_hash.as_str()) {
                anyhow::bail!(
                    "refusing to bind a public interface: user '{}' uses a well-known DEMO \
                     password hash. Set a real password with `qw hash-password` (per user), or \
                     set QW_ALLOW_DEMO_CREDENTIALS=1 to override.",
                    u.username
                );
            }
            if !seen.insert(u.password_hash.as_str()) {
                anyhow::bail!(
                    "refusing to bind a public interface: multiple users share the same \
                     password hash (copied demo credentials). Give each user a unique password \
                     with `qw hash-password`, or set QW_ALLOW_DEMO_CREDENTIALS=1 to override."
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod deployment_safety_tests {
    use super::*;

    fn user(name: &str, hash: &str) -> UserConfig {
        UserConfig {
            username: name.to_string(),
            password_hash: hash.to_string(),
            role: "admin".to_string(),
            org: "default".to_string(),
        }
    }

    fn cfg(listen: &str, users: Vec<UserConfig>) -> GatewayConfig {
        let mut c = GatewayConfig::default();
        c.gateway.listen = listen.to_string();
        c.gateway.admin_listen = "127.0.0.1:9091".to_string();
        c.auth.enabled = true;
        c.auth.users = users;
        c
    }

    #[test]
    fn loopback_demo_is_allowed() {
        let c = cfg(
            "127.0.0.1:9090",
            vec![user("admin", KNOWN_DEMO_PASSWORD_HASHES[0])],
        );
        assert!(c.assert_deployment_safe().is_ok());
    }

    #[test]
    fn public_bind_with_demo_hash_is_refused() {
        let c = cfg(
            "0.0.0.0:9090",
            vec![user("admin", KNOWN_DEMO_PASSWORD_HASHES[0])],
        );
        assert!(c.assert_deployment_safe().is_err());
    }

    #[test]
    fn public_bind_with_shared_hash_is_refused() {
        let c = cfg(
            "0.0.0.0:9090",
            vec![user("a", "$argon2id$unique-real-1"), user("b", "$argon2id$unique-real-1")],
        );
        assert!(c.assert_deployment_safe().is_err());
    }

    #[test]
    fn public_bind_with_unique_real_hashes_is_allowed() {
        let c = cfg(
            "0.0.0.0:9090",
            vec![user("a", "$argon2id$unique-real-1"), user("b", "$argon2id$unique-real-2")],
        );
        assert!(c.assert_deployment_safe().is_ok());
    }

    #[test]
    fn public_bind_with_auth_disabled_is_refused() {
        let mut c = cfg("0.0.0.0:9090", vec![]);
        c.auth.enabled = false;
        assert!(c.assert_deployment_safe().is_err());
    }

    /// The shipped production template must stay in sync with the config schema
    /// and satisfy the deployment-safety guard (unique non-demo credential,
    /// auth on) even though it binds a public interface.
    #[test]
    fn prod_template_parses_and_is_deployment_safe() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/quantawatch.prod.yaml"
        );
        let yaml = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        let cfg: GatewayConfig =
            serde_yaml::from_str(&yaml).expect("prod template must match the config schema");
        assert!(cfg.gateway.tls.is_some(), "prod template should enable TLS");
        assert!(cfg.auth.enabled, "prod template must enable auth");
        assert!(cfg.rate_limit.enabled, "prod template must enable rate limiting");
        assert!(
            cfg.assert_deployment_safe().is_ok(),
            "prod template must pass the deployment-safety guard"
        );
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
            crypto_policy: qw_cbom::CryptoPolicy::default(),
            crypto_policies: Vec::new(),
            overlay: OverlayConfig::default(),
            pki: PkiConfig::default(),
            attestation: AttestationConfig::default(),
            air_gapped: false,
            assets: Vec::new(),
            connectors: Vec::new(),
            crypto_enforcement: CryptoEnforcementConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// PQC-terminating proxy overlay. Each route serves a hybrid-PQC TLS listener
/// (X25519MLKEM768) to clients and forwards to a legacy upstream — so the
/// client-facing leg is quantum-safe even when the upstream can't be changed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverlayConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub routes: Vec<OverlayRoute>,
    /// PEM certificate + key for the client-facing TLS. If absent, a self-signed
    /// cert is generated at startup (fine for internal/dev overlays).
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayRoute {
    pub id: String,
    /// Client-facing listen address; QuantaWatch serves hybrid-PQC TLS here.
    pub listen: String,
    /// The legacy upstream to forward decrypted traffic to (host:port).
    pub upstream: String,
    /// Re-encrypt the upstream leg with TLS (true) or forward in plaintext to a
    /// trusted local upstream (false).
    #[serde(default)]
    pub upstream_tls: bool,
    /// Client-leg posture: "hybrid" (offer PQC, allow classical) or "pqc-only"
    /// (drop connections that didn't negotiate the hybrid group).
    #[serde(default = "default_overlay_mode")]
    pub mode: String,
}

fn default_overlay_mode() -> String {
    "hybrid".to_string()
}

/// Internal PQC certificate authority. Issues hybrid certificates — a classical
/// Ed25519 X.509 leaf (usable in TLS today) plus an ML-DSA-65 signature binding
/// (post-quantum authentication) — and auto-rotates them before expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The CA's common name.
    #[serde(default = "default_ca_cn")]
    pub common_name: String,
    /// Default certificate lifetime in days.
    #[serde(default = "default_cert_validity_days")]
    pub default_validity_days: u32,
    /// Auto-renew a certificate when it is within this many days of expiry.
    #[serde(default = "default_auto_renew_days")]
    pub auto_renew_days: u32,
}

impl Default for PkiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            common_name: default_ca_cn(),
            default_validity_days: default_cert_validity_days(),
            auto_renew_days: default_auto_renew_days(),
        }
    }
}

fn default_ca_cn() -> String {
    "QuantaWatch PQC CA".to_string()
}
fn default_cert_validity_days() -> u32 {
    90
}
fn default_auto_renew_days() -> u32 {
    14
}
