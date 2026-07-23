use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use qw_audit::AuditLogger;
use qw_cbom::{PostureSummary, ProviderCryptoInfo};
use qw_crypto::GatewayIdentity;
use qw_integrations::IntegrationRegistry;
use qw_monitor::SecurityMonitor;
use qw_policy::PolicyEngine;
use qw_scanner::ScannerRegistry;
use qw_store::Store;

use crate::config::GatewayConfig;
use crate::providers::{self, ProviderRegistry};

#[derive(Clone)]
pub struct AppState {
    pub gateway_identity: Arc<GatewayIdentity>,
    pub policy_engine: Arc<RwLock<PolicyEngine>>,
    pub security_monitor: Arc<SecurityMonitor>,
    pub audit_logger: Arc<AuditLogger>,
    pub providers: Arc<ProviderRegistry>,
    pub http_client: reqwest::Client,
    pub config: Arc<GatewayConfig>,
    pub sessions: Arc<DashMap<String, SessionInfo>>,
    pub scanner_registry: Arc<ScannerRegistry>,
    pub integration_registry: Arc<IntegrationRegistry>,
    pub store: Arc<Store>,
    pub posture_cache: Arc<RwLock<Option<PostureSummary>>>,
    pub provider_crypto: Arc<DashMap<String, ProviderCryptoInfo>>,
    pub alert_manager: Arc<crate::alerts::AlertManager>,
    pub auth_manager: Arc<crate::auth::AuthManager>,
    pub resilience: Arc<crate::resilience::Resilience>,
    pub attestor: Arc<dyn crate::attest::Attestor>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub overlay: Arc<crate::overlay::OverlayState>,
    /// Internal PQC certificate authority (None when pki.enabled = false).
    pub ca: Option<Arc<crate::pki::CertAuthority>>,
    /// Shared secret host agents present (X-QW-Agent-Token) to post endpoint
    /// reports. Persisted under key_dir so it is stable across restarts.
    pub agent_enroll_token: Arc<String>,
    /// Per-client rate limiter guarding the public listeners.
    pub rate_limiter: Arc<crate::ratelimit::RateLimiter>,
}

/// Public session info stored in the DashMap (without secret keys).
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub agent_name: String,
    pub provider: String,
    pub model: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub request_count: u64,
    pub total_tokens: u64,
    pub client_ip: String,
}

impl AppState {
    pub async fn new(config: GatewayConfig) -> Result<Self> {
        // Initialize gateway identity (PQC keys)
        // Prefer an externally-managed seed (K8s Secret / KMS) so replicas share
        // one signing identity; otherwise persist/load it from key_dir.
        let key_dir = std::path::PathBuf::from(&config.identity.key_dir);
        let gateway_identity = Arc::new(match &config.identity.seed_env {
            Some(env_var) => GatewayIdentity::load_from_env_or_dir(env_var, &key_dir)?,
            None => GatewayIdentity::load_or_generate(&key_dir)?,
        });

        // Select the CBOM attestation root of trust from config.
        let attestor =
            crate::attest::build_attestor(&config.attestation.provider, gateway_identity.clone());

        // Initialize policy engine from config
        let policy_yaml = build_policy_yaml(&config);
        let policy_engine = PolicyEngine::from_yaml(&policy_yaml).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to load policies, using empty policy");
            PolicyEngine::from_yaml("agents: {}").unwrap()
        });

        // Initialize security monitor
        let blocking_threshold = match config.monitor.blocking_threshold.as_str() {
            "low" => qw_monitor::Severity::Low,
            "medium" => qw_monitor::Severity::Medium,
            "high" => qw_monitor::Severity::High,
            "critical" => qw_monitor::Severity::Critical,
            _ => qw_monitor::Severity::High,
        };
        let security_monitor = Arc::new(SecurityMonitor::new(blocking_threshold));

        // Initialize provider registry
        let provider_registry = Arc::new(providers::build_registry(&config));

        // HTTP client for upstream requests, bounded by the resilience config so
        // a slow upstream can't hang callers indefinitely.
        let http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(
                config.resilience.connect_timeout_secs,
            ))
            .timeout(std::time::Duration::from_secs(
                config.resilience.request_timeout_secs,
            ))
            .build()?;

        // Per-provider circuit breakers + retry policy for the in-path proxy.
        let resilience = Arc::new(crate::resilience::Resilience::new(
            config.resilience.clone(),
        ));

        // Initialize scanner registry
        let scanner_registry = Arc::new(qw_scanner::build_scanner_registry(&config.scanner));

        // Initialize integration registry
        let integration_registry = Arc::new(qw_integrations::build_integration_registry(
            &config.integrations,
        ));

        // Initialize the SQLite-backed, tenant-scoped store.
        // A `postgres://` store_path selects the shared Postgres backend (HA,
        // multi-replica); anything else is a local SQLite file directory.
        // Expand `${VAR}` from the environment so a DB password (e.g. for
        // FortressQL) can live in a Secret/env var, not inline in the config.
        let store_path = expand_env_vars(&config.scanner.store_path);
        let store_raw =
            if store_path.starts_with("postgres://") || store_path.starts_with("postgresql://") {
                tracing::info!("store backend: Postgres (shared, HA-capable)");
                Store::open_postgres(&store_path)?
            } else {
                let scan_dir = std::path::PathBuf::from(&store_path);
                Store::open(&scan_dir.join("quantawatch.db"))?
            };

        // Secrets-at-rest: encrypt stored integration tokens with a key derived
        // from `QW_SECRET_KEY`. Without a key we fall back to plaintext storage
        // (dev/back-compat) but warn loudly once auth is enabled — a production
        // deployment must set this.
        let secret_cipher = match std::env::var("QW_SECRET_KEY") {
            Ok(k) if !k.trim().is_empty() => match qw_crypto::SecretCipher::from_key_material(&k) {
                Ok(c) => {
                    tracing::info!(
                        "secrets-at-rest: integration tokens encrypted (ChaCha20-Poly1305)"
                    );
                    Some(c)
                }
                Err(e) => {
                    tracing::error!(error = %e, "QW_SECRET_KEY is invalid; secrets will be stored UNENCRYPTED");
                    None
                }
            },
            _ => {
                if config.auth.enabled {
                    tracing::warn!(
                        "QW_SECRET_KEY is not set: integration tokens are stored UNENCRYPTED at \
                         rest. Set QW_SECRET_KEY to a strong random value before production use."
                    );
                }
                None
            }
        };
        let store = Arc::new(store_raw.with_secret_cipher(secret_cipher));

        // Initialize the audit logger. Entries are sharded per replica and live
        // in the shared store, so multiple replicas write to one verifiable
        // audit trail (anchored by periodic global checkpoints).
        let writer_id = resolve_writer_id(&config.audit.writer_id);
        tracing::info!(writer_id = %writer_id, "audit chain writer id");
        let audit_logger = Arc::new(AuditLogger::new(
            store.clone(),
            gateway_identity.clone(),
            config.audit.merkle_batch_size,
            writer_id,
            std::time::Duration::from_secs(config.audit.checkpoint_interval_secs),
        ));

        // Initialize alert manager (persists to the store)
        let alert_manager = Arc::new(crate::alerts::AlertManager::new(
            config.alerts.clone(),
            http_client.clone(),
            store.clone(),
            config.air_gapped,
        ));

        if config.air_gapped {
            tracing::warn!(
                "AIR-GAPPED MODE: outbound alert delivery, evidence-pack delivery, cloud \
                 connector discovery, and integration calls are disabled. Alerts and findings \
                 are still recorded locally; export the audit log via GET /api/audit/export."
            );
            if config.auth.oidc.is_some() {
                tracing::warn!(
                    "air_gapped is set but an OIDC provider is configured; SSO discovery/JWKS \
                     requires egress and will fail unless the issuer is reachable internally."
                );
            }
        }

        // Initialize auth manager (sessions persist in the shared store, so a
        // login is valid across replicas and survives restart).
        let auth_manager = Arc::new(crate::auth::AuthManager::new(
            config.auth.clone(),
            store.clone(),
        ));

        // PQC-terminating overlay: bind hybrid-PQC TLS listeners in front of any
        // configured legacy upstreams. A bad route logs and is skipped rather
        // than failing gateway startup.
        let overlay = crate::overlay::spawn(&config.overlay, audit_logger.clone())
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "overlay failed to start; continuing without it");
                Arc::new(crate::overlay::OverlayState::disabled(audit_logger.clone()))
            });

        // Internal PQC certificate authority. The classical CA persists under
        // key_dir; the ML-DSA binding uses the (persisted) gateway identity.
        let ca = if config.pki.enabled {
            let key_dir = std::path::PathBuf::from(&config.identity.key_dir);
            match crate::pki::CertAuthority::load_or_create(
                &config.pki.common_name,
                &key_dir,
                gateway_identity.clone(),
            ) {
                Ok(ca) => {
                    tracing::info!(cn = %config.pki.common_name, "PQC CA ready");
                    Some(Arc::new(ca))
                }
                Err(e) => {
                    tracing::error!(error = %e, "PQC CA failed to initialize; disabling");
                    None
                }
            }
        } else {
            None
        };

        // Re-bind PQC-overlay routes that were protected before a restart, so
        // one-click protection is durable. A route that fails to re-bind (e.g.
        // its port is taken) is logged and skipped rather than failing startup.
        for route in store.list_all_overlay_routes() {
            match overlay
                .add_route(&route.id, &route.listen, &route.upstream, route.upstream_tls, &route.mode)
                .await
            {
                Ok(_) => tracing::info!(route = %route.id, listen = %route.listen, upstream = %route.upstream, "overlay: re-bound persisted route"),
                Err(e) => tracing::warn!(route = %route.id, listen = %route.listen, error = %e, "overlay: failed to re-bind persisted route"),
            }
        }

        // Host-agent enrollment token: stable secret persisted under key_dir.
        let agent_enroll_token = Arc::new(load_or_create_agent_token(&key_dir));

        let rate_limiter = Arc::new(crate::ratelimit::RateLimiter::new(&config.rate_limit));

        Ok(Self {
            gateway_identity,
            agent_enroll_token,
            rate_limiter,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            security_monitor,
            audit_logger,
            providers: provider_registry,
            http_client,
            config: Arc::new(config),
            sessions: Arc::new(DashMap::new()),
            scanner_registry,
            integration_registry,
            store,
            posture_cache: Arc::new(RwLock::new(None)),
            provider_crypto: Arc::new(DashMap::new()),
            alert_manager,
            auth_manager,
            resilience,
            attestor,
            metrics: Arc::new(crate::metrics::Metrics::new()),
            overlay,
            ca,
        })
    }
}

/// Load the host-agent enrollment token from key_dir, generating and persisting
/// one on first run. A stable shared secret agents present to post reports.
fn load_or_create_agent_token(key_dir: &std::path::Path) -> String {
    let path = key_dir.join("agent_enrollment.token");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    let token = format!(
        "qwa_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let _ = std::fs::create_dir_all(key_dir);
    let _ = std::fs::write(&path, &token);
    token
}

/// Expand `${VAR}` references in a config string from the environment. Lets a
/// secret — most importantly a Postgres/FortressQL password — stay in a
/// Kubernetes Secret (exposed as an env var) instead of being written inline in
/// the mounted config. Unknown vars expand to empty (with a warning); a `${`
/// without a closing `}` is left literal.
fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        tracing::warn!(var, "config references an unset env var; expanding to empty")
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str("${");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Resolve this replica's audit writer id (sharded audit chain). Must be unique
/// per replica and stable across restarts of the same one. Explicit config wins,
/// else `QW_AUDIT_WRITER_ID`, else the hostname, else `node-0` (single node).
fn resolve_writer_id(configured: &str) -> String {
    if !configured.trim().is_empty() {
        return configured.trim().to_string();
    }
    for var in ["QW_AUDIT_WRITER_ID", "HOSTNAME", "COMPUTERNAME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                return v.trim().to_string();
            }
        }
    }
    "node-0".to_string()
}

/// Build YAML policy string from the gateway config's agents section.
fn build_policy_yaml(config: &GatewayConfig) -> String {
    if config.agents.is_empty() {
        return "default: allow\nagents: {}".to_string();
    }

    let mut yaml = format!("default: {}\nagents:\n", config.policy.default);
    for (name, agent) in &config.agents {
        yaml.push_str(&format!("  {name}:\n"));
        yaml.push_str(&format!("    description: \"{}\"\n", agent.description));

        if !agent.allowed_models.is_empty() {
            yaml.push_str("    allowed_models:\n");
            for m in &agent.allowed_models {
                yaml.push_str(&format!("      - \"{m}\"\n"));
            }
        }
        if !agent.allowed_tools.is_empty() {
            yaml.push_str("    allowed_tools:\n");
            for t in &agent.allowed_tools {
                yaml.push_str(&format!("      - \"{t}\"\n"));
            }
        }
        if !agent.blocked_tools.is_empty() {
            yaml.push_str("    blocked_tools:\n");
            for t in &agent.blocked_tools {
                yaml.push_str(&format!("      - \"{t}\"\n"));
            }
        }
        if agent.offline {
            yaml.push_str("    offline: true\n");
        }
    }
    yaml
}

#[cfg(test)]
mod tests {
    use super::expand_env_vars;

    #[test]
    fn expands_known_and_unknown_vars() {
        // Uniquely-named var to avoid clashing with other tests in the process.
        std::env::set_var("QW_TEST_DB_PW", "s3cr3t");
        let url = "postgres://qw:${QW_TEST_DB_PW}@db:5432/qw?sslmode=require";
        assert_eq!(
            expand_env_vars(url),
            "postgres://qw:s3cr3t@db:5432/qw?sslmode=require"
        );
        std::env::remove_var("QW_TEST_DB_PW");

        // Unset var expands to empty (never leaves the literal ${...}).
        std::env::remove_var("QW_TEST_ABSENT");
        assert_eq!(expand_env_vars("a${QW_TEST_ABSENT}b"), "ab");

        // No placeholders -> unchanged; a dangling ${ is left literal.
        assert_eq!(expand_env_vars("/app/data"), "/app/data");
        assert_eq!(expand_env_vars("x${unclosed"), "x${unclosed");
    }
}
