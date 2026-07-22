//! SQLite-backed, tenant-scoped persistence for QuantaWatch.
//!
//! Replaces the per-crate JSONL stores. Every row carries a `tenant` column for
//! multi-tenant isolation plus the full record serialized as JSON, which gives
//! exact round-trip without mapping every enum to a column.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use r2d2_postgres::PostgresConnectionManager;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tokio_postgres_rustls::MakeRustlsConnect;

use qw_audit::{AuditBackend, AuditCheckpoint, AuditEntry, WriterTip};
use qw_cbom::PostureSnapshot;
use qw_crypto::sha3_256_hex;
use qw_integrations::RemediationTicket;
use qw_scanner::{
    confidence_of, evidence_of, FindingRecord, FindingStatus, ScanRecord, ScanResult, ScanTarget,
};

pub const DEFAULT_TENANT: &str = "default";

// ---- Alert types (live here so persistence owns them) ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn from_label(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => AlertSeverity::Critical,
            "warning" => AlertSeverity::Warning,
            _ => AlertSeverity::Info,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub kind: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub delivered: u32,
}

impl AlertEvent {
    pub fn new(
        kind: &str,
        severity: AlertSeverity,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            kind: kind.to_string(),
            severity,
            title: title.into(),
            message: message.into(),
            metadata: HashMap::new(),
            delivered: 0,
        }
    }
}

/// Persisted agent session (the gateway maps its in-memory SessionInfo to this).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRow {
    pub session_id: String,
    pub agent_name: String,
    pub provider: String,
    pub model: String,
    pub created_at: DateTime<Utc>,
    pub request_count: u64,
    pub total_tokens: u64,
    pub client_ip: String,
}

/// A persisted admin auth session (a bearer token's principal), stored so a
/// login on one gateway replica is valid on all of them. Keyed in the DB by the
/// SHA3-256 hash of the token — the raw token is never persisted, so a database
/// read can't hand an attacker a live session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthSession {
    pub username: String,
    /// Role label ("viewer" | "auditor" | "operator" | "admin"); the gateway
    /// owns the Role enum, so the store keeps it as a string.
    pub role: String,
    pub org: String,
    pub expires_at: DateTime<Utc>,
    /// Last time this session was used, for idle-timeout enforcement. Defaults to
    /// now for sessions persisted before this field existed.
    #[serde(default = "Utc::now")]
    pub last_used: DateTime<Utc>,
}

/// Per-username failed-login state for lockout. Stored in the shared store so the
/// lockout holds across every replica, not just the one that saw the failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockoutState {
    pub failures: u32,
    pub first_failure_at: DateTime<Utc>,
    pub locked_until: Option<DateTime<Utc>>,
}

/// An observed agent→provider data flow, aggregated from live proxy traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowRow {
    pub agent: String,
    pub provider: String,
    pub requests: u64,
    /// Requests where the monitor flagged sensitive content (PII/exfiltration).
    pub sensitive: u64,
    /// Requests where the monitor flagged a threat.
    pub threats: u64,
    pub last_seen: DateTime<Utc>,
}

/// An external infrastructure crypto asset discovered by a connector or declared
/// in config (TLS endpoint, K8s ingress, load balancer, KMS key, certificate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetRow {
    pub id: String,
    pub kind: String,
    pub address: String,
    pub environment: String,
    pub tags: Vec<String>,
    pub pqc_status: String,
    pub tls_version: Option<String>,
    pub last_scanned: Option<DateTime<Utc>>,
    /// "config" | "kubernetes" | "aws" | …
    pub source: String,
}

/// A point-in-time snapshot of SLO evaluation (for breach trends).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SloSnapshot {
    pub timestamp: DateTime<Utc>,
    pub total: u32,
    pub passing: u32,
    pub failing: u32,
    pub gate_breach: bool,
}

/// A point-in-time snapshot of crypto-agility governance (for drift trends).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceSnapshot {
    pub timestamp: DateTime<Utc>,
    pub agility_score: f64,
    pub compliant: u32,
    pub deprecated: u32,
    pub forbidden: u32,
    pub verdict: String,
}

/// The last evaluation of one crypto-agility policy, for drift detection: the
/// set of violation fingerprints and the status at that time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySnapshotRow {
    pub status: String,
    pub fingerprints: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

/// One network service exposed by a target, with its crypto posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedService {
    pub port: u16,
    pub service: String,
    pub pqc_status: String,
    pub detail: String,
    /// How this service was found: "network" (external sweep) or "host"
    /// (authenticated deep inventory over SSH).
    #[serde(default = "default_source")]
    pub source: String,
    /// True = reachable from the network (wildcard/external bind); false =
    /// loopback-only, discoverable only by logging in. Network-swept services
    /// are always exposed; deep-inventory adds the internal ones.
    #[serde(default = "default_true")]
    pub exposed: bool,
    /// Set once this service is fronted by the PQC overlay: the hybrid-PQC
    /// listen address clients should connect to instead of the raw service.
    #[serde(default)]
    pub protected_listen: Option<String>,
    /// Set once a hybrid ML-DSA certificate has been issued for this service.
    #[serde(default)]
    pub cert_id: Option<String>,
}

fn default_source() -> String {
    "network".to_string()
}
fn default_true() -> bool {
    true
}

/// A container discovered by the authenticated deep inventory (docker ps).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostContainerRow {
    pub name: String,
    pub image: String,
    pub ports: String,
}

/// One classified crypto component reported by a host agent (a boot-chain,
/// firmware, or endpoint crypto element).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointComponent {
    /// secure_boot | tpm | measured_boot | disk_encryption | ssh_host_key |
    /// crypto_library | certificate
    pub category: String,
    pub name: String,
    pub detail: String,
    #[serde(default)]
    pub algorithm: Option<String>,
    pub pqc_status: String,
    /// info | low | medium | high | critical
    pub severity: String,
}

/// A host reported by an installed QuantaWatch agent — including the firmware /
/// boot-chain crypto (TPM, Secure Boot, measured boot, disk encryption) that no
/// network or SSH scan can see.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointRow {
    pub id: String,
    pub hostname: String,
    pub os: String,
    /// linux | windows | macos | other
    pub os_kind: String,
    #[serde(default)]
    pub agent_version: Option<String>,
    pub enrolled_at: DateTime<Utc>,
    pub last_report: DateTime<Utc>,
    /// Worst PQC posture across the endpoint's components.
    pub pqc_status: String,
    pub findings_count: u32,
    /// Classified components for the UI.
    pub components: Vec<EndpointComponent>,
    /// The raw inventory the agent posted (for drill-down).
    #[serde(default)]
    pub inventory: serde_json::Value,
}

/// A PQC-overlay route protected at runtime (via one-click "protect"),
/// persisted so it can be re-bound after a gateway restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayRouteRow {
    /// Route id, e.g. "target:{targetId}:{port}".
    pub id: String,
    /// The Estate target this route fronts, if any (for cleanup on delete).
    #[serde(default)]
    pub target_id: Option<String>,
    /// The actual bound client-facing listen address (host:port).
    pub listen: String,
    /// The legacy upstream (host:port) traffic is forwarded to.
    pub upstream: String,
    #[serde(default)]
    pub upstream_tls: bool,
    /// "hybrid" | "pqc-only".
    pub mode: String,
    pub created_at: DateTime<Utc>,
}

/// A UI-managed connection to an external source (GitHub, GitLab, Jira, Linear)
/// with a stored secret. The row (including `token`) is persisted on the gateway
/// to drive scans; the API layer masks the token before returning it to the
/// browser — never serialize a ConnectionRow straight into an HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRow {
    pub id: String,
    /// github | gitlab | jira | linear
    pub integration_type: String,
    pub display_name: String,
    #[serde(default)]
    pub base_url: Option<String>,
    /// GitHub org / GitLab group to enumerate (optional).
    #[serde(default)]
    pub org: Option<String>,
    /// Jira/Linear project or GitHub owner/repo for remediation (optional).
    #[serde(default)]
    pub project: Option<String>,
    /// owner/repo where auto-remediation PRs are opened (GitHub).
    #[serde(default)]
    pub repo: Option<String>,
    /// The secret. Persisted to drive scans; masked by the API before returning.
    #[serde(default)]
    pub token: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub last_tested: Option<DateTime<Utc>>,
    /// "connected" | "failed" | "untested"
    #[serde(default)]
    pub last_status: Option<String>,
    #[serde(default)]
    pub last_user: Option<String>,
    #[serde(default)]
    pub last_scanned: Option<DateTime<Utc>>,
    #[serde(default)]
    pub findings_count: Option<u32>,
}

/// A connected system in the estate — a VM, a server (SSH/RDP), a network host.
/// Registering it authorizes QuantaWatch to sweep it: port-scan + fingerprint
/// every exposed service's crypto into `exposed_services`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetRow {
    pub id: String,
    pub name: String,
    pub host: String,
    /// vm | server | network_device | container | endpoint | database
    pub kind: String,
    /// Declared reachability: ssh | rdp | tls | network.
    pub reachability: Vec<String>,
    pub environment: String,
    pub tags: Vec<String>,
    pub exposed_services: Vec<ExposedService>,
    /// Containers found by authenticated deep inventory (empty until deep-scanned).
    #[serde(default)]
    pub containers: Vec<HostContainerRow>,
    /// Host facts from deep inventory (hostname + kernel), if connected.
    #[serde(default)]
    pub host_info: Option<String>,
    /// True once an authenticated SSH deep inventory has run against this host.
    #[serde(default)]
    pub deep_scanned: bool,
    /// Worst PQC posture across exposed services.
    pub pqc_status: String,
    pub last_scanned: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A certificate issued by the internal PQC CA. The private key is NOT stored
/// (returned once at issuance); this is the durable, auditable record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRow {
    pub id: String,
    pub subject: String,
    pub sans: Vec<String>,
    pub serial: String,
    /// "hybrid" (classical X.509 + ML-DSA binding) or "classical".
    pub key_type: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// The classical (Ed25519) X.509 leaf, PEM.
    pub cert_pem: String,
    /// The CA's ML-DSA-65 verifying key (base64), for the PQC binding.
    #[serde(default)]
    pub mldsa_public_key: Option<String>,
    /// The CA's ML-DSA-65 signature over the leaf cert DER (base64).
    #[serde(default)]
    pub mldsa_signature: Option<String>,
    pub ca_fingerprint: String,
    /// "hybrid" | "classical" (mirrors PqcStatus semantics for the inventory).
    pub pqc_status: String,
    /// "active" | "revoked".
    pub status: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A point-in-time snapshot of the attack-path graph (for drift detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphSnapshot {
    pub timestamp: DateTime<Utc>,
    pub total: u32,
    pub critical: u32,
    pub high: u32,
    pub hndl: u32,
    pub path_ids: Vec<String>,
}

// ---- Store ----

type PgPool = r2d2::Pool<PostgresConnectionManager<MakeRustlsConnect>>;

/// TLS verifier that encrypts the connection but does NOT validate the server
/// certificate chain — matching libpq's `sslmode=require` semantics (protect the
/// wire, no CA/hostname check). This is what makes the PQC-hybrid key exchange
/// (e.g. FortressQL's X25519MLKEM768) usable against an internal DB with a
/// self-signed or non-webpki cert. The handshake signature is still checked
/// against the presented cert, so the session isn't blindly forgeable.
/// Full CA verification (`sslmode=verify-full`) is a separate, stricter mode we
/// don't yet offer over this client (see `open_postgres`).
#[derive(Debug)]
struct EncryptOnlyVerifier(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for EncryptOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build a PQC-capable rustls TLS connector for Postgres/FortressQL. The
/// aws-lc-rs provider advertises hybrid ML-KEM groups (X25519MLKEM768) by
/// default, so a FortressQL server negotiates the post-quantum key exchange;
/// a classical Postgres server falls back to X25519. Encrypt-only (no CA
/// verification) — see `EncryptOnlyVerifier`.
fn build_pg_tls() -> MakeRustlsConnect {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions are valid")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EncryptOnlyVerifier(provider)))
        .with_no_client_auth();
    MakeRustlsConnect::new(config)
}

/// A unit of Postgres work, run on the executor thread against the pool.
type PgJob = Box<dyn FnOnce(&PgPool) + Send>;

/// Runs every Postgres operation on one dedicated OS thread.
///
/// The synchronous `postgres` + `r2d2` client drives its own tokio runtime via
/// `block_on`, which panics ("Cannot start a runtime from within a runtime") if
/// invoked from a thread already inside the gateway's async runtime — i.e.
/// `AppState::new` and every axum handler that touches the store. This thread
/// has no ambient runtime, so the client is safe here; callers submit a closure
/// and block on its result, exactly as the SQLite backend blocks on its `Mutex`.
struct PgExecutor {
    tx: std::sync::mpsc::Sender<PgJob>,
}

impl PgExecutor {
    /// Run `f` on the executor thread and return its result (blocks the caller).
    fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&PgPool) -> T + Send + 'static,
    {
        let (rtx, rrx) = std::sync::mpsc::sync_channel::<T>(1);
        // If the executor thread is gone, the Postgres backend is unrecoverable;
        // fail loud, matching the SQLite path's `lock().unwrap()`.
        self.tx
            .send(Box::new(move |pool| {
                let _ = rtx.send(f(pool));
            }))
            .expect("postgres executor thread has stopped");
        rrx.recv().expect("postgres executor dropped the result")
    }
}

/// Storage backend. SQLite (single-node, file or in-memory) or Postgres (shared
/// across replicas for HA). Both keep the same JSON-blob-per-row model, so the
/// public API is identical; only the SQL dialect differs.
enum Backend {
    Sqlite(Mutex<Connection>),
    Pg(PgExecutor),
}

#[derive(Clone)]
pub struct Store {
    backend: Arc<Backend>,
}

/// Translate SQLite placeholders (`?1`) to Postgres (`$1`). Our SQL only uses
/// `?1..?6`; LIMIT values are inlined, never bound, so no others appear.
fn pg_ph(sql: &str) -> String {
    let mut s = sql.to_string();
    for i in 1..=6 {
        s = s.replace(&format!("?{i}"), &format!("${i}"));
    }
    s
}

/// A stable, deterministic finding id derived from the asset (location) and the
/// check (title), so the same finding keeps one row across re-scans.
fn stable_finding_id(location: &str, title: &str) -> String {
    sha3_256_hex(format!("{location}|{title}").as_bytes())
}

/// Postgres schema. Same shape as SQLite; `BIGSERIAL` replaces
/// `INTEGER PRIMARY KEY AUTOINCREMENT` for the append-only sequence.
const PG_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, completed_at TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS findings (id TEXT, tenant TEXT NOT NULL, scan_id TEXT, created_at TEXT, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant, id);
    CREATE TABLE IF NOT EXISTS posture (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS remediations (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGINT);
    CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGINT);
    CREATE TABLE IF NOT EXISTS sessions (session_id TEXT, tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL, PRIMARY KEY (tenant, session_id));
    CREATE TABLE IF NOT EXISTS flows (tenant TEXT NOT NULL, agent TEXT NOT NULL, provider TEXT NOT NULL, requests BIGINT NOT NULL DEFAULT 0, sensitive BIGINT NOT NULL DEFAULT 0, threats BIGINT NOT NULL DEFAULT 0, last_seen TEXT, PRIMARY KEY (tenant, agent, provider));
    CREATE TABLE IF NOT EXISTS graph_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS assets (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
    CREATE TABLE IF NOT EXISTS slo_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS governance_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS policy_snapshots (tenant TEXT NOT NULL, policy_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, policy_id));
    CREATE TABLE IF NOT EXISTS certificates (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
    CREATE TABLE IF NOT EXISTS targets (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
    CREATE TABLE IF NOT EXISTS connections (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
    CREATE TABLE IF NOT EXISTS overlay_routes (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
    CREATE TABLE IF NOT EXISTS endpoints (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
    CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS login_lockouts (username TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS oidc_states (state TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_entries (gseq BIGSERIAL PRIMARY KEY, writer_id TEXT NOT NULL, seq BIGINT NOT NULL, content_hash TEXT NOT NULL, data TEXT NOT NULL, UNIQUE (writer_id, seq));
    CREATE TABLE IF NOT EXISTS audit_checkpoints (checkpoint_seq BIGINT PRIMARY KEY, content_hash TEXT NOT NULL, data TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_audit_writer ON audit_entries(writer_id, seq);
    CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant);
    CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant);
    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
";

impl Store {
    fn sqlite(conn: Connection) -> Self {
        Self {
            backend: Arc::new(Backend::Sqlite(Mutex::new(conn))),
        }
    }

    /// Open a Postgres-backed store from a `postgres://` / `postgresql://` URL.
    ///
    /// The connection uses a PQC-capable rustls TLS connector, so pointing this
    /// at a FortressQL instance with `sslmode=require` negotiates a post-quantum
    /// hybrid key exchange (X25519MLKEM768). `sslmode=disable` stays plaintext;
    /// `sslmode=prefer` (the default) encrypts opportunistically and falls back
    /// to plaintext if the server has no TLS. Encrypt-only: CA verification
    /// (`sslmode=verify-ca` / `verify-full`) isn't supported by this client yet.
    pub fn open_postgres(url: &str) -> anyhow::Result<Self> {
        if url.contains("sslmode=verify-ca") || url.contains("sslmode=verify-full") {
            anyhow::bail!(
                "sslmode=verify-ca/verify-full is not yet supported by this client; use \
                 sslmode=require for encrypted (PQC-capable) transport"
            );
        }
        let config: postgres::Config = url
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid postgres url: {e}"))?;
        let connector = build_pg_tls();

        // The sync postgres client nests a tokio runtime, so it must never run on
        // an async worker thread. Own the pool on a dedicated thread and drive all
        // work there; block here only until startup (connect + schema) is done so
        // connection errors still surface synchronously from open_postgres.
        let (job_tx, job_rx) = std::sync::mpsc::channel::<PgJob>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<anyhow::Result<()>>();

        std::thread::Builder::new()
            .name("qw-pg-store".to_string())
            .spawn(move || {
                let init = (|| -> anyhow::Result<PgPool> {
                    // Connect directly once to surface a clear error (r2d2 hides
                    // the cause) and apply the schema.
                    config
                        .clone()
                        .connect(connector.clone())
                        .map_err(|e| {
                            let msg = e
                                .as_db_error()
                                .map(|d| d.message().to_string())
                                .unwrap_or_else(|| e.to_string());
                            anyhow::anyhow!("postgres connect failed: {msg}")
                        })?
                        .batch_execute(PG_SCHEMA)?;
                    let manager = PostgresConnectionManager::new(config, connector);
                    let pool = r2d2::Pool::builder()
                        .max_size(16)
                        .connection_timeout(std::time::Duration::from_secs(10))
                        .build(manager)?;
                    Ok(pool)
                })();

                match init {
                    Ok(pool) => {
                        if ready_tx.send(Ok(())).is_err() {
                            return; // caller gave up before we were ready
                        }
                        drop(ready_tx);
                        while let Ok(job) = job_rx.recv() {
                            job(&pool);
                        }
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            })
            .map_err(|e| anyhow::anyhow!("failed to spawn postgres executor: {e}"))?;

        ready_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("postgres executor exited before signalling readiness"))??;

        Ok(Self {
            backend: Arc::new(Backend::Pg(PgExecutor { tx: job_tx })),
        })
    }

    /// Open a store from a config value: a `postgres://` URL selects Postgres,
    /// anything else is treated as a SQLite file path.
    pub fn open_url(target: &str) -> anyhow::Result<Self> {
        if target.starts_with("postgres://") || target.starts_with("postgresql://") {
            Self::open_postgres(target)
        } else {
            Self::open(Path::new(target))
        }
    }

    // ---- backend dispatch helpers -------------------------------------------

    /// Execute a write. `sqlite_sql` uses `?N`; the Postgres form is derived by
    /// `pg_ph` unless the caller passes an explicit upsert via `exec_pg`.
    fn exec(&self, sqlite_sql: &str, params: &[&str]) {
        self.exec_pg(sqlite_sql, &pg_ph(sqlite_sql), params);
    }

    /// Execute a write with distinct SQLite/Postgres SQL (for upserts, whose
    /// `ON CONFLICT` clause differs from SQLite's `INSERT OR REPLACE`).
    fn exec_pg(&self, sqlite_sql: &str, pg_sql: &str, params: &[&str]) {
        match &*self.backend {
            Backend::Sqlite(m) => {
                let conn = m.lock().unwrap();
                let p: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                let _ = conn.execute(sqlite_sql, &p[..]);
            }
            Backend::Pg(ex) => {
                let sql = pg_sql.to_string();
                let owned: Vec<String> = params.iter().map(|s| s.to_string()).collect();
                ex.run(move |pool| {
                    if let Ok(mut c) = pool.get() {
                        let p: Vec<&(dyn postgres::types::ToSql + Sync)> = owned
                            .iter()
                            .map(|s| s as &(dyn postgres::types::ToSql + Sync))
                            .collect();
                        if let Err(e) = c.execute(&sql, &p[..]) {
                            tracing::warn!(error = %e, "postgres write failed");
                        }
                    }
                });
            }
        }
    }

    /// Query the first TEXT column of every row. LIMIT is inlined by the caller.
    fn query_col(&self, sqlite_sql: &str, params: &[&str]) -> Vec<String> {
        match &*self.backend {
            Backend::Sqlite(m) => {
                let conn = m.lock().unwrap();
                let Ok(mut stmt) = conn.prepare(sqlite_sql) else {
                    return Vec::new();
                };
                let p: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                let Ok(rows) = stmt.query_map(&p[..], |r| r.get::<_, String>(0)) else {
                    return Vec::new();
                };
                rows.filter_map(|r| r.ok()).collect()
            }
            Backend::Pg(ex) => {
                let sql = pg_ph(sqlite_sql);
                let owned: Vec<String> = params.iter().map(|s| s.to_string()).collect();
                ex.run(move |pool| {
                    let Ok(mut c) = pool.get() else {
                        return Vec::new();
                    };
                    let p: Vec<&(dyn postgres::types::ToSql + Sync)> = owned
                        .iter()
                        .map(|s| s as &(dyn postgres::types::ToSql + Sync))
                        .collect();
                    match c.query(&sql, &p[..]) {
                        Ok(rows) => rows.iter().map(|row| row.get::<_, String>(0)).collect(),
                        Err(e) => {
                            tracing::warn!(error = %e, "postgres query failed");
                            Vec::new()
                        }
                    }
                })
            }
        }
    }

    /// Query + deserialize each row's JSON blob.
    fn list_de<T: for<'de> Deserialize<'de>>(&self, sqlite_sql: &str, params: &[&str]) -> Vec<T> {
        self.query_col(sqlite_sql, params)
            .iter()
            .filter_map(|j| serde_json::from_str(j).ok())
            .collect()
    }

    /// Query + deserialize the first matching row.
    fn one_de<T: for<'de> Deserialize<'de>>(&self, sqlite_sql: &str, params: &[&str]) -> Option<T> {
        self.query_col(sqlite_sql, params)
            .into_iter()
            .next()
            .and_then(|j| serde_json::from_str(&j).ok())
    }

    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, completed_at TEXT, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT, tenant TEXT NOT NULL, scan_id TEXT, created_at TEXT, data TEXT NOT NULL,
                seq INTEGER PRIMARY KEY AUTOINCREMENT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant, id);
            CREATE TABLE IF NOT EXISTS posture (
                tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT
            );
            CREATE TABLE IF NOT EXISTS remediations (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL,
                seq INTEGER
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL,
                seq INTEGER
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT, tenant TEXT NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY (tenant, session_id)
            );
            CREATE TABLE IF NOT EXISTS flows (
                tenant TEXT NOT NULL, agent TEXT NOT NULL, provider TEXT NOT NULL,
                requests INTEGER NOT NULL DEFAULT 0, sensitive INTEGER NOT NULL DEFAULT 0,
                threats INTEGER NOT NULL DEFAULT 0, last_seen TEXT,
                PRIMARY KEY (tenant, agent, provider)
            );
            CREATE TABLE IF NOT EXISTS graph_snapshots (
                tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT
            );
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY (tenant, id)
            );
            CREATE TABLE IF NOT EXISTS slo_snapshots (
                tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT
            );
            CREATE TABLE IF NOT EXISTS governance_snapshots (
                tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT
            );
            CREATE TABLE IF NOT EXISTS policy_snapshots (
                tenant TEXT NOT NULL, policy_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, policy_id)
            );
            CREATE TABLE IF NOT EXISTS certificates (
                id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id)
            );
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id)
            );
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id)
            );
            CREATE TABLE IF NOT EXISTS overlay_routes (
                id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id)
            );
            CREATE TABLE IF NOT EXISTS endpoints (
                id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id)
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_lockouts (
                username TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oidc_states (
                state TEXT PRIMARY KEY, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_entries (
                gseq INTEGER PRIMARY KEY AUTOINCREMENT, writer_id TEXT NOT NULL, seq INTEGER NOT NULL,
                content_hash TEXT NOT NULL, data TEXT NOT NULL, UNIQUE (writer_id, seq)
            );
            CREATE TABLE IF NOT EXISTS audit_checkpoints (
                checkpoint_seq INTEGER PRIMARY KEY, content_hash TEXT NOT NULL, data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_writer ON audit_entries(writer_id, seq);
            CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant);
            CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_posture_tenant ON posture(tenant);
            CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant);
            CREATE INDEX IF NOT EXISTS idx_remediations_tenant ON remediations(tenant);
            "#,
        )?;
        Ok(Self::sqlite(conn))
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            r#"
            CREATE TABLE scans (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, completed_at TEXT, data TEXT NOT NULL);
            CREATE TABLE findings (id TEXT, tenant TEXT NOT NULL, scan_id TEXT, created_at TEXT, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant, id);
            CREATE TABLE posture (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE remediations (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER);
            CREATE TABLE alerts (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER);
            CREATE TABLE sessions (session_id TEXT, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, session_id));
            CREATE TABLE flows (tenant TEXT NOT NULL, agent TEXT NOT NULL, provider TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0, sensitive INTEGER NOT NULL DEFAULT 0, threats INTEGER NOT NULL DEFAULT 0, last_seen TEXT, PRIMARY KEY (tenant, agent, provider));
            CREATE TABLE graph_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE assets (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE slo_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE governance_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE policy_snapshots (tenant TEXT NOT NULL, policy_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, policy_id));
            CREATE TABLE certificates (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE targets (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE connections (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE overlay_routes (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE endpoints (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE auth_sessions (token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at TEXT NOT NULL);
            CREATE TABLE login_lockouts (username TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE oidc_states (state TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
            CREATE TABLE audit_entries (gseq INTEGER PRIMARY KEY AUTOINCREMENT, writer_id TEXT NOT NULL, seq INTEGER NOT NULL, content_hash TEXT NOT NULL, data TEXT NOT NULL, UNIQUE (writer_id, seq));
            CREATE TABLE audit_checkpoints (checkpoint_seq INTEGER PRIMARY KEY, content_hash TEXT NOT NULL, data TEXT NOT NULL);
            "#,
        )?;
        Ok(Self::sqlite(conn))
    }

    // ---- Scans / findings ----

    pub fn record_scan(&self, tenant: &str, result: &ScanResult, target: &ScanTarget) {
        let content = serde_json::to_vec(&result.findings).unwrap_or_default();
        let record = ScanRecord {
            id: uuid::Uuid::new_v4().to_string(),
            scanner_id: result.scanner_id.clone(),
            target_id: result.target_id.clone(),
            target_address: target.address.clone(),
            status: result.status.clone(),
            finding_count: result.findings.len() as u32,
            started_at: result.started_at,
            completed_at: result.completed_at,
            content_hash: sha3_256_hex(&content),
        };
        let scan_id = record.id.clone();

        let scan_json = serde_json::to_string(&record).unwrap_or_default();
        let completed = record.completed_at.to_rfc3339();
        self.exec_pg(
            "INSERT OR REPLACE INTO scans (id, tenant, completed_at, data) VALUES (?1, ?2, ?3, ?4)",
            "INSERT INTO scans (id, tenant, completed_at, data) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET tenant = EXCLUDED.tenant, completed_at = EXCLUDED.completed_at, data = EXCLUDED.data",
            &[record.id.as_str(), tenant, completed.as_str(), scan_json.as_str()],
        );
        for finding in &result.findings {
            // Stable identity so re-scanning the same asset/check REPLACES its
            // finding instead of appending a near-duplicate every scan. Keyed by
            // (location, title) — the asset and the check — not by status, so a
            // changed posture updates the same row.
            let stable_id =
                stable_finding_id(&finding.asset.location.path, &finding.title);
            // Preserve triage (acknowledged/suppressed + note) across re-scans —
            // an upsert would otherwise reset a suppressed finding to Open.
            let (status, note) = self
                .get_finding(tenant, &stable_id)
                .map(|p| (p.status, p.note))
                .unwrap_or((FindingStatus::Open, None));
            let fr = FindingRecord {
                id: stable_id.clone(),
                scan_id: scan_id.clone(),
                category: finding.category.clone(),
                severity: finding.severity.clone(),
                title: finding.title.clone(),
                description: finding.description.clone(),
                asset_type: finding.asset.asset_type.clone(),
                algorithm: finding.asset.algorithm.clone(),
                pqc_status: finding.pqc_status.clone(),
                location: finding.asset.location.path.clone(),
                remediation: finding.remediation.clone(),
                created_at: Utc::now(),
                confidence: confidence_of(finding),
                evidence: evidence_of(finding, &result.scanner_id),
                status,
                note,
            };
            let fjson = serde_json::to_string(&fr).unwrap_or_default();
            let created = fr.created_at.to_rfc3339();
            self.exec_pg(
                "INSERT OR REPLACE INTO findings (id, tenant, scan_id, created_at, data) VALUES (?1, ?2, ?3, ?4, ?5)",
                "INSERT INTO findings (id, tenant, scan_id, created_at, data) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant, id) DO UPDATE SET scan_id = EXCLUDED.scan_id, created_at = EXCLUDED.created_at, data = EXCLUDED.data",
                &[fr.id.as_str(), tenant, fr.scan_id.as_str(), created.as_str(), fjson.as_str()],
            );
        }
    }

    pub fn list_scans(&self, tenant: &str, limit: usize) -> Vec<ScanRecord> {
        self.list_de(
            &format!(
                "SELECT data FROM scans WHERE tenant = ?1 ORDER BY completed_at DESC LIMIT {limit}"
            ),
            &[tenant],
        )
    }

    pub fn get_scan(&self, tenant: &str, id: &str) -> Option<ScanRecord> {
        self.one_de(
            "SELECT data FROM scans WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        )
    }

    pub fn findings_for_scan(&self, tenant: &str, scan_id: &str) -> Vec<FindingRecord> {
        self.list_de(
            "SELECT data FROM findings WHERE tenant = ?1 AND scan_id = ?2 ORDER BY seq",
            &[tenant, scan_id],
        )
    }

    pub fn all_findings(&self, tenant: &str) -> Vec<FindingRecord> {
        self.list_de(
            "SELECT data FROM findings WHERE tenant = ?1 ORDER BY seq",
            &[tenant],
        )
    }

    pub fn get_finding(&self, tenant: &str, id: &str) -> Option<FindingRecord> {
        self.one_de(
            "SELECT data FROM findings WHERE tenant = ?1 AND id = ?2 LIMIT 1",
            &[tenant, id],
        )
    }

    /// Update a stored finding in place (e.g. after a re-verify changes its PQC
    /// status). Keyed by the finding's own id, which is unique per instance.
    pub fn update_finding(&self, tenant: &str, record: &FindingRecord) {
        let fjson = serde_json::to_string(record).unwrap_or_default();
        self.exec(
            "UPDATE findings SET data = ?1 WHERE tenant = ?2 AND id = ?3",
            &[fjson.as_str(), tenant, record.id.as_str()],
        );
    }

    /// Set a finding's triage status (open / acknowledged / suppressed) + note.
    /// Returns the updated record, or None if the finding doesn't exist.
    pub fn set_finding_status(
        &self,
        tenant: &str,
        id: &str,
        status: FindingStatus,
        note: Option<String>,
    ) -> Option<FindingRecord> {
        let mut rec = self.get_finding(tenant, id)?;
        rec.status = status;
        rec.note = note;
        self.update_finding(tenant, &rec);
        Some(rec)
    }

    /// One-time migration: collapse the historical append-only duplicates (the
    /// same finding recorded once per scan) down to a single row per
    /// (location, title), re-keyed by the stable finding id, then enforce
    /// uniqueness so future scans upsert instead of piling up. Idempotent —
    /// after the first run there is nothing left to collapse. Returns the number
    /// of duplicate rows removed.
    pub fn dedupe_findings(&self) -> usize {
        let tenants = self.query_col("SELECT DISTINCT tenant FROM findings", &[]);
        let mut removed = 0usize;
        for tenant in tenants {
            let all = self.all_findings(&tenant); // ascending seq: oldest first
            let before = all.len();
            // Keep the newest (last-seen) record per stable key.
            let mut keep: std::collections::BTreeMap<String, FindingRecord> =
                std::collections::BTreeMap::new();
            for mut f in all {
                let sid = stable_finding_id(&f.location, &f.title);
                f.id = sid.clone();
                keep.insert(sid, f);
            }
            if keep.len() == before {
                continue; // already deduped for this tenant
            }
            self.exec("DELETE FROM findings WHERE tenant = ?1", &[tenant.as_str()]);
            for f in keep.values() {
                let fjson = serde_json::to_string(f).unwrap_or_default();
                let created = f.created_at.to_rfc3339();
                self.exec(
                    "INSERT INTO findings (id, tenant, scan_id, created_at, data) VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[f.id.as_str(), tenant.as_str(), f.scan_id.as_str(), created.as_str(), fjson.as_str()],
                );
            }
            removed += before - keep.len();
        }
        // Enforce uniqueness so record_scan's upsert has a conflict target.
        self.exec(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant, id)",
            &[],
        );
        if removed > 0 {
            tracing::info!(removed, "collapsed duplicate findings");
        }
        removed
    }

    // ---- Posture history ----

    pub fn record_posture(&self, tenant: &str, snap: &PostureSnapshot) {
        // Skip if identical to the most recent snapshot for this tenant.
        let last: Option<PostureSnapshot> = self.one_de(
            "SELECT data FROM posture WHERE tenant = ?1 ORDER BY seq DESC LIMIT 1",
            &[tenant],
        );
        if let Some(prev) = last {
            if (prev.overall_score - snap.overall_score).abs() < f64::EPSILON
                && prev.total_assets == snap.total_assets
            {
                return;
            }
        }
        let json = serde_json::to_string(snap).unwrap_or_default();
        self.exec(
            "INSERT INTO posture (tenant, data) VALUES (?1, ?2)",
            &[tenant, json.as_str()],
        );
    }

    pub fn posture_history(&self, tenant: &str, limit: usize) -> Vec<PostureSnapshot> {
        let mut v: Vec<PostureSnapshot> = self.list_de(
            &format!("SELECT data FROM posture WHERE tenant = ?1 ORDER BY seq DESC LIMIT {limit}"),
            &[tenant],
        );
        v.reverse(); // chronological
        v
    }

    pub fn latest_posture(&self, tenant: &str) -> Option<PostureSnapshot> {
        self.one_de(
            "SELECT data FROM posture WHERE tenant = ?1 ORDER BY seq DESC LIMIT 1",
            &[tenant],
        )
    }

    // ---- Remediations ----

    pub fn record_remediation(&self, tenant: &str, ticket: &RemediationTicket) {
        let json = serde_json::to_string(ticket).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO remediations (id, tenant, data, seq) VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(seq),0)+1 FROM remediations))",
            "INSERT INTO remediations (id, tenant, data, seq) VALUES ($1, $2, $3, (SELECT COALESCE(MAX(seq),0)+1 FROM remediations)) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, seq = EXCLUDED.seq",
            &[ticket.id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn list_remediations(&self, tenant: &str) -> Vec<RemediationTicket> {
        self.list_de(
            "SELECT data FROM remediations WHERE tenant = ?1 ORDER BY seq DESC LIMIT 1000",
            &[tenant],
        )
    }

    // ---- Alerts ----

    pub fn record_alert(&self, tenant: &str, alert: &AlertEvent) {
        let json = serde_json::to_string(alert).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO alerts (id, tenant, data, seq) VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(seq),0)+1 FROM alerts))",
            "INSERT INTO alerts (id, tenant, data, seq) VALUES ($1, $2, $3, (SELECT COALESCE(MAX(seq),0)+1 FROM alerts)) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, seq = EXCLUDED.seq",
            &[alert.id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn recent_alerts(&self, tenant: &str, limit: usize) -> Vec<AlertEvent> {
        self.list_de(
            &format!("SELECT data FROM alerts WHERE tenant = ?1 ORDER BY seq DESC LIMIT {limit}"),
            &[tenant],
        )
    }

    // ---- Sessions ----

    pub fn upsert_session(&self, tenant: &str, s: &SessionRow) {
        let json = serde_json::to_string(s).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO sessions (session_id, tenant, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO sessions (session_id, tenant, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, session_id) DO UPDATE SET data = EXCLUDED.data",
            &[s.session_id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn list_sessions(&self, tenant: &str, limit: usize) -> Vec<SessionRow> {
        self.list_de(
            &format!("SELECT data FROM sessions WHERE tenant = ?1 ORDER BY session_id DESC LIMIT {limit}"),
            &[tenant],
        )
    }

    // ---- Auth sessions + OIDC state (shared across replicas for HA) ----
    //
    // These back the gateway's AuthManager. Persisting them means a login issued
    // by one replica validates on any replica, and sessions survive a restart.
    // `expires_at` is stored as a fixed-width UTC string ("…Z", second-precision)
    // so lexicographic comparison equals chronological comparison for the SQL
    // purge; the exact expiry lives in the JSON blob and is checked in Rust.

    pub fn put_auth_session(&self, token_hash: &str, session: &AuthSession) {
        let json = serde_json::to_string(session).unwrap_or_default();
        let exp = session.expires_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        self.exec_pg(
            "INSERT OR REPLACE INTO auth_sessions (token_hash, data, expires_at) VALUES (?1, ?2, ?3)",
            "INSERT INTO auth_sessions (token_hash, data, expires_at) VALUES ($1, $2, $3) ON CONFLICT (token_hash) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at",
            &[token_hash, json.as_str(), exp.as_str()],
        );
    }

    pub fn get_auth_session(&self, token_hash: &str) -> Option<AuthSession> {
        self.one_de(
            "SELECT data FROM auth_sessions WHERE token_hash = ?1",
            &[token_hash],
        )
    }

    pub fn delete_auth_session(&self, token_hash: &str) {
        self.exec(
            "DELETE FROM auth_sessions WHERE token_hash = ?1",
            &[token_hash],
        );
    }

    /// Update a session's `last_used` (and any other blob field) in place, for
    /// idle-timeout tracking. Does not touch `expires_at`.
    pub fn touch_auth_session(&self, token_hash: &str, session: &AuthSession) {
        let json = serde_json::to_string(session).unwrap_or_default();
        self.exec(
            "UPDATE auth_sessions SET data = ?1 WHERE token_hash = ?2",
            &[json.as_str(), token_hash],
        );
    }

    // ---- Login lockout (brute-force defense, shared across replicas) ----

    pub fn get_login_lockout(&self, username: &str) -> Option<LockoutState> {
        self.one_de(
            "SELECT data FROM login_lockouts WHERE username = ?1",
            &[username],
        )
    }

    pub fn put_login_lockout(&self, username: &str, state: &LockoutState) {
        let json = serde_json::to_string(state).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO login_lockouts (username, data) VALUES (?1, ?2)",
            "INSERT INTO login_lockouts (username, data) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET data = EXCLUDED.data",
            &[username, json.as_str()],
        );
    }

    pub fn clear_login_lockout(&self, username: &str) {
        self.exec(
            "DELETE FROM login_lockouts WHERE username = ?1",
            &[username],
        );
    }

    pub fn put_oidc_state(&self, state: &str, expires_at: DateTime<Utc>) {
        let exp = expires_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        self.exec_pg(
            "INSERT OR REPLACE INTO oidc_states (state, expires_at) VALUES (?1, ?2)",
            "INSERT INTO oidc_states (state, expires_at) VALUES ($1, $2) ON CONFLICT (state) DO UPDATE SET expires_at = EXCLUDED.expires_at",
            &[state, exp.as_str()],
        );
    }

    /// Validate-and-consume a CSRF state nonce: returns its expiry (for the
    /// caller to range-check) and deletes it so it can't be replayed.
    pub fn consume_oidc_state(&self, state: &str) -> Option<DateTime<Utc>> {
        let exp = self
            .query_col(
                "SELECT expires_at FROM oidc_states WHERE state = ?1",
                &[state],
            )
            .into_iter()
            .next()?;
        self.exec("DELETE FROM oidc_states WHERE state = ?1", &[state]);
        DateTime::parse_from_rfc3339(&exp)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    }

    /// Best-effort cleanup of expired sessions and OIDC states.
    pub fn purge_expired_auth(&self, now: DateTime<Utc>) {
        let now_s = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        self.exec(
            "DELETE FROM auth_sessions WHERE expires_at < ?1",
            &[now_s.as_str()],
        );
        self.exec(
            "DELETE FROM oidc_states WHERE expires_at < ?1",
            &[now_s.as_str()],
        );
    }

    // ---- Observed flows (blast radius) ----

    pub fn record_flow(
        &self,
        tenant: &str,
        agent: &str,
        provider: &str,
        sensitive: bool,
        threat: bool,
    ) {
        let s = if sensitive { "1" } else { "0" };
        let t = if threat { "1" } else { "0" };
        let now = Utc::now().to_rfc3339();
        // The 0/1 deltas are inlined (internal, not user input) so every bound
        // param is a string; the upsert increment works in both dialects.
        let sql = format!(
            "INSERT INTO flows (tenant, agent, provider, requests, sensitive, threats, last_seen) \
             VALUES (?1, ?2, ?3, 1, {s}, {t}, ?4) \
             ON CONFLICT (tenant, agent, provider) DO UPDATE SET \
               requests = flows.requests + 1, \
               sensitive = flows.sensitive + {s}, \
               threats = flows.threats + {t}, \
               last_seen = ?4"
        );
        self.exec(&sql, &[tenant, agent, provider, now.as_str()]);
    }

    pub fn list_flows(&self, tenant: &str) -> Vec<FlowRow> {
        fn row(
            agent: String,
            provider: String,
            req: i64,
            sens: i64,
            thr: i64,
            last: String,
        ) -> FlowRow {
            FlowRow {
                agent,
                provider,
                requests: req as u64,
                sensitive: sens as u64,
                threats: thr as u64,
                last_seen: chrono::DateTime::parse_from_rfc3339(&last)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }
        }
        const SQL: &str =
            "SELECT agent, provider, requests, sensitive, threats, last_seen FROM flows WHERE tenant = ?1";
        match &*self.backend {
            Backend::Sqlite(m) => {
                let conn = m.lock().unwrap();
                let Ok(mut stmt) = conn.prepare(SQL) else {
                    return Vec::new();
                };
                let rows = stmt.query_map([tenant], |r| {
                    Ok(row(
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get::<_, String>(5).unwrap_or_default(),
                    ))
                });
                match rows {
                    Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
                    Err(_) => Vec::new(),
                }
            }
            Backend::Pg(ex) => {
                let tenant = tenant.to_string();
                ex.run(move |pool| {
                    let Ok(mut c) = pool.get() else {
                        return Vec::new();
                    };
                    match c.query(&pg_ph(SQL), &[&tenant]) {
                        Ok(rows) => rows
                            .iter()
                            .map(|r| {
                                row(
                                    r.get(0),
                                    r.get(1),
                                    r.get(2),
                                    r.get(3),
                                    r.get(4),
                                    r.get::<_, Option<String>>(5).unwrap_or_default(),
                                )
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    }
                })
            }
        }
    }

    // ---- SLO snapshots (breach trends) ----

    pub fn record_slo_snapshot(&self, tenant: &str, snap: &SloSnapshot) {
        let json = serde_json::to_string(snap).unwrap_or_default();
        self.exec(
            "INSERT INTO slo_snapshots (tenant, data) VALUES (?1, ?2)",
            &[tenant, json.as_str()],
        );
    }

    pub fn record_governance_snapshot(&self, tenant: &str, snap: &GovernanceSnapshot) {
        let json = serde_json::to_string(snap).unwrap_or_default();
        self.exec(
            "INSERT INTO governance_snapshots (tenant, data) VALUES (?1, ?2)",
            &[tenant, json.as_str()],
        );
    }

    pub fn governance_history(&self, tenant: &str, limit: usize) -> Vec<GovernanceSnapshot> {
        let mut v: Vec<GovernanceSnapshot> = self.list_de(
            &format!("SELECT data FROM governance_snapshots WHERE tenant = ?1 ORDER BY seq DESC LIMIT {limit}"),
            &[tenant],
        );
        v.reverse();
        v
    }

    pub fn slo_history(&self, tenant: &str, limit: usize) -> Vec<SloSnapshot> {
        let mut v: Vec<SloSnapshot> = self.list_de(
            &format!(
                "SELECT data FROM slo_snapshots WHERE tenant = ?1 ORDER BY seq DESC LIMIT {limit}"
            ),
            &[tenant],
        );
        v.reverse();
        v
    }

    // ---- Asset inventory ----

    pub fn upsert_asset(&self, tenant: &str, asset: &AssetRow) {
        let json = serde_json::to_string(asset).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO assets (id, tenant, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO assets (id, tenant, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, id) DO UPDATE SET data = EXCLUDED.data",
            &[asset.id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn list_assets(&self, tenant: &str) -> Vec<AssetRow> {
        self.list_de(
            "SELECT data FROM assets WHERE tenant = ?1 ORDER BY id LIMIT 100000",
            &[tenant],
        )
    }

    // ---- Crypto-agility policy drift baselines ----

    /// Persist the latest evaluation of a policy (upsert by tenant+policy).
    pub fn record_policy_snapshot(&self, tenant: &str, policy_id: &str, snap: &PolicySnapshotRow) {
        let json = serde_json::to_string(snap).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO policy_snapshots (tenant, policy_id, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO policy_snapshots (tenant, policy_id, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, policy_id) DO UPDATE SET data = EXCLUDED.data",
            &[tenant, policy_id, json.as_str()],
        );
    }

    /// The previous evaluation of a policy (the drift baseline), if any.
    pub fn latest_policy_snapshot(&self, tenant: &str, policy_id: &str) -> Option<PolicySnapshotRow> {
        self.one_de(
            "SELECT data FROM policy_snapshots WHERE tenant = ?1 AND policy_id = ?2 LIMIT 1",
            &[tenant, policy_id],
        )
    }

    // ---- Issued certificates (internal PQC CA) ----

    pub fn record_certificate(&self, tenant: &str, cert: &CertificateRow) {
        let json = serde_json::to_string(cert).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO certificates (id, tenant, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO certificates (id, tenant, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, id) DO UPDATE SET data = EXCLUDED.data",
            &[cert.id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn list_certificates(&self, tenant: &str) -> Vec<CertificateRow> {
        self.list_de(
            "SELECT data FROM certificates WHERE tenant = ?1 ORDER BY id LIMIT 100000",
            &[tenant],
        )
    }

    pub fn get_certificate(&self, tenant: &str, id: &str) -> Option<CertificateRow> {
        self.one_de(
            "SELECT data FROM certificates WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        )
    }

    // ---- Estate targets (connected systems) ----

    pub fn upsert_target(&self, tenant: &str, target: &TargetRow) {
        let json = serde_json::to_string(target).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO targets (id, tenant, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO targets (id, tenant, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, id) DO UPDATE SET data = EXCLUDED.data",
            &[target.id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn list_targets(&self, tenant: &str) -> Vec<TargetRow> {
        self.list_de(
            "SELECT data FROM targets WHERE tenant = ?1 ORDER BY id LIMIT 100000",
            &[tenant],
        )
    }

    pub fn get_target(&self, tenant: &str, id: &str) -> Option<TargetRow> {
        self.one_de(
            "SELECT data FROM targets WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        )
    }

    pub fn delete_target(&self, tenant: &str, id: &str) {
        self.exec(
            "DELETE FROM targets WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        );
    }

    // ---- External connections (UI-managed integrations with stored secrets) ----

    pub fn upsert_connection(&self, tenant: &str, conn: &ConnectionRow) {
        let json = serde_json::to_string(conn).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO connections (id, tenant, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO connections (id, tenant, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, id) DO UPDATE SET data = EXCLUDED.data",
            &[conn.id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn list_connections(&self, tenant: &str) -> Vec<ConnectionRow> {
        self.list_de(
            "SELECT data FROM connections WHERE tenant = ?1 ORDER BY id LIMIT 10000",
            &[tenant],
        )
    }

    pub fn get_connection(&self, tenant: &str, id: &str) -> Option<ConnectionRow> {
        self.one_de(
            "SELECT data FROM connections WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        )
    }

    pub fn delete_connection(&self, tenant: &str, id: &str) {
        self.exec(
            "DELETE FROM connections WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        );
    }

    // ---- Persisted PQC-overlay routes (durable one-click protection) ----

    pub fn record_overlay_route(&self, tenant: &str, route: &OverlayRouteRow) {
        let json = serde_json::to_string(route).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO overlay_routes (id, tenant, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO overlay_routes (id, tenant, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, id) DO UPDATE SET data = EXCLUDED.data",
            &[route.id.as_str(), tenant, json.as_str()],
        );
    }

    /// Every persisted route across all tenants — used at startup to re-bind.
    pub fn list_all_overlay_routes(&self) -> Vec<OverlayRouteRow> {
        self.list_de("SELECT data FROM overlay_routes ORDER BY id LIMIT 100000", &[])
    }

    pub fn delete_overlay_route(&self, tenant: &str, id: &str) {
        self.exec(
            "DELETE FROM overlay_routes WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        );
    }

    /// Remove every persisted route fronting a given target (called when the
    /// target is deleted so it doesn't re-bind on the next restart).
    pub fn delete_overlay_routes_for_target(&self, tenant: &str, target_id: &str) {
        for r in self.list_all_overlay_routes() {
            if r.target_id.as_deref() == Some(target_id) {
                self.delete_overlay_route(tenant, &r.id);
            }
        }
    }

    // ---- Host-agent endpoints (firmware / boot-chain crypto inventory) ----

    pub fn upsert_endpoint(&self, tenant: &str, ep: &EndpointRow) {
        let json = serde_json::to_string(ep).unwrap_or_default();
        self.exec_pg(
            "INSERT OR REPLACE INTO endpoints (id, tenant, data) VALUES (?1, ?2, ?3)",
            "INSERT INTO endpoints (id, tenant, data) VALUES ($1, $2, $3) ON CONFLICT (tenant, id) DO UPDATE SET data = EXCLUDED.data",
            &[ep.id.as_str(), tenant, json.as_str()],
        );
    }

    pub fn list_endpoints(&self, tenant: &str) -> Vec<EndpointRow> {
        self.list_de(
            "SELECT data FROM endpoints WHERE tenant = ?1 ORDER BY id LIMIT 10000",
            &[tenant],
        )
    }

    pub fn get_endpoint(&self, tenant: &str, id: &str) -> Option<EndpointRow> {
        self.one_de(
            "SELECT data FROM endpoints WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        )
    }

    /// Find an endpoint by hostname (so repeat reports from the same host update
    /// in place rather than duplicating).
    pub fn find_endpoint_by_hostname(&self, tenant: &str, hostname: &str) -> Option<EndpointRow> {
        self.list_endpoints(tenant).into_iter().find(|e| e.hostname == hostname)
    }

    pub fn delete_endpoint(&self, tenant: &str, id: &str) {
        self.exec(
            "DELETE FROM endpoints WHERE tenant = ?1 AND id = ?2",
            &[tenant, id],
        );
    }

    // ---- Graph snapshots (drift/timeline) ----

    pub fn record_graph_snapshot(&self, tenant: &str, snap: &GraphSnapshot) {
        let json = serde_json::to_string(snap).unwrap_or_default();
        self.exec(
            "INSERT INTO graph_snapshots (tenant, data) VALUES (?1, ?2)",
            &[tenant, json.as_str()],
        );
    }

    pub fn graph_timeline(&self, tenant: &str, limit: usize) -> Vec<GraphSnapshot> {
        let mut v: Vec<GraphSnapshot> = self.list_de(
            &format!("SELECT data FROM graph_snapshots WHERE tenant = ?1 ORDER BY seq DESC LIMIT {limit}"),
            &[tenant],
        );
        v.reverse();
        v
    }

    pub fn latest_graph_snapshot(&self, tenant: &str) -> Option<GraphSnapshot> {
        self.one_de(
            "SELECT data FROM graph_snapshots WHERE tenant = ?1 ORDER BY seq DESC LIMIT 1",
            &[tenant],
        )
    }

    /// Distinct tenants that have any data (for admin/cross-tenant views).
    pub fn tenants(&self) -> Vec<String> {
        self.query_col(
            "SELECT DISTINCT tenant FROM scans UNION SELECT DISTINCT tenant FROM findings UNION SELECT DISTINCT tenant FROM sessions",
            &[],
        )
    }
}

/// Sharded audit backend: entry appends are lock-free (each replica writes only
/// its own `writer_id` rows), checkpoint creation is serialized.
impl AuditBackend for Store {
    fn append_entry(&self, entry: &AuditEntry) {
        let json = serde_json::to_string(entry).unwrap_or_default();
        let seq = entry.sequence as i64;
        match &*self.backend {
            Backend::Sqlite(m) => {
                let conn = m.lock().unwrap();
                if let Err(e) = conn.execute(
                    "INSERT INTO audit_entries (writer_id, seq, content_hash, data) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![entry.writer_id, seq, entry.content_hash, json],
                ) {
                    tracing::warn!(error = %e, "audit append failed");
                }
            }
            Backend::Pg(ex) => {
                let writer_id = entry.writer_id.clone();
                let content_hash = entry.content_hash.clone();
                ex.run(move |pool| {
                    if let Ok(mut c) = pool.get() {
                        if let Err(e) = c.execute(
                            "INSERT INTO audit_entries (writer_id, seq, content_hash, data) VALUES ($1, $2, $3, $4)",
                            &[&writer_id, &seq, &content_hash, &json],
                        ) {
                            tracing::warn!(error = %e, "audit append failed");
                        }
                    }
                });
            }
        }
    }

    fn writer_tip(&self, writer_id: &str) -> Option<(u64, String)> {
        match &*self.backend {
            Backend::Sqlite(m) => {
                let conn = m.lock().unwrap();
                conn.query_row(
                    "SELECT seq, content_hash FROM audit_entries WHERE writer_id = ?1 ORDER BY seq DESC LIMIT 1",
                    [writer_id],
                    |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?)),
                )
                .ok()
            }
            Backend::Pg(ex) => {
                let writer_id = writer_id.to_string();
                ex.run(move |pool| {
                    let mut c = pool.get().ok()?;
                    let rows = c
                        .query(
                            "SELECT seq, content_hash FROM audit_entries WHERE writer_id = $1 ORDER BY seq DESC LIMIT 1",
                            &[&writer_id],
                        )
                        .ok()?;
                    rows.first()
                        .map(|row| (row.get::<_, i64>(0) as u64, row.get::<_, String>(1)))
                })
            }
        }
    }

    fn all_writer_tips(&self) -> Vec<WriterTip> {
        let sql = "SELECT writer_id, seq, content_hash FROM audit_entries e \
                   WHERE seq = (SELECT MAX(seq) FROM audit_entries WHERE writer_id = e.writer_id)";
        match &*self.backend {
            Backend::Sqlite(m) => {
                let conn = m.lock().unwrap();
                let Ok(mut stmt) = conn.prepare(sql) else {
                    return Vec::new();
                };
                let Ok(rows) = stmt.query_map([], |r| {
                    Ok(WriterTip {
                        writer_id: r.get::<_, String>(0)?,
                        seq: r.get::<_, i64>(1)? as u64,
                        content_hash: r.get::<_, String>(2)?,
                    })
                }) else {
                    return Vec::new();
                };
                rows.filter_map(|r| r.ok()).collect()
            }
            Backend::Pg(ex) => ex.run(move |pool| {
                let Ok(mut c) = pool.get() else {
                    return Vec::new();
                };
                match c.query(sql, &[]) {
                    Ok(rows) => rows
                        .iter()
                        .map(|row| WriterTip {
                            writer_id: row.get::<_, String>(0),
                            seq: row.get::<_, i64>(1) as u64,
                            content_hash: row.get::<_, String>(2),
                        })
                        .collect(),
                    Err(_) => Vec::new(),
                }
            }),
        }
    }

    fn list_entries(&self, limit: usize) -> Vec<AuditEntry> {
        // Most-recent `limit` rows, returned oldest-first (newest last).
        let sql = format!(
            "SELECT data FROM (SELECT data, gseq FROM audit_entries ORDER BY gseq DESC LIMIT {limit}) sub ORDER BY gseq ASC"
        );
        self.query_col(&sql, &[])
            .iter()
            .filter_map(|j| serde_json::from_str(j).ok())
            .collect()
    }

    fn list_checkpoints(&self) -> Vec<AuditCheckpoint> {
        self.list_de(
            "SELECT data FROM audit_checkpoints ORDER BY checkpoint_seq ASC",
            &[],
        )
    }

    fn latest_checkpoint(&self) -> Option<AuditCheckpoint> {
        self.one_de(
            "SELECT data FROM audit_checkpoints ORDER BY checkpoint_seq DESC LIMIT 1",
            &[],
        )
    }

    fn commit_checkpoint(
        &self,
        build: &dyn Fn(u64, &str, Vec<WriterTip>) -> AuditCheckpoint,
    ) -> Option<AuditCheckpoint> {
        match &*self.backend {
            Backend::Sqlite(m) => {
                // Single process: holding the connection lock makes read+insert atomic.
                let conn = m.lock().unwrap();
                let (next_seq, prev_hash) = conn
                    .query_row(
                        "SELECT checkpoint_seq, content_hash FROM audit_checkpoints ORDER BY checkpoint_seq DESC LIMIT 1",
                        [],
                        |r| Ok((r.get::<_, i64>(0)? as u64 + 1, r.get::<_, String>(1)?)),
                    )
                    .unwrap_or((0, String::new()));
                let tips = {
                    let mut stmt = conn
                        .prepare(
                            "SELECT writer_id, seq, content_hash FROM audit_entries e \
                             WHERE seq = (SELECT MAX(seq) FROM audit_entries WHERE writer_id = e.writer_id)",
                        )
                        .ok()?;
                    let rows = stmt
                        .query_map([], |r| {
                            Ok(WriterTip {
                                writer_id: r.get::<_, String>(0)?,
                                seq: r.get::<_, i64>(1)? as u64,
                                content_hash: r.get::<_, String>(2)?,
                            })
                        })
                        .ok()?;
                    rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
                };
                if tips.is_empty() {
                    return None;
                }
                let cp = build(next_seq, &prev_hash, tips);
                let json = serde_json::to_string(&cp).unwrap_or_default();
                conn.execute(
                    "INSERT INTO audit_checkpoints (checkpoint_seq, content_hash, data) VALUES (?1, ?2, ?3)",
                    rusqlite::params![cp.checkpoint_seq as i64, cp.content_hash, json],
                )
                .ok()?;
                Some(cp)
            }
            Backend::Pg(ex) => {
                // Read the next sequence + previous hash + all writer tips on the
                // executor thread.
                let read = ex.run(|pool| -> Option<(u64, String, Vec<WriterTip>)> {
                    let mut c = pool.get().ok()?;
                    let latest = c
                        .query(
                            "SELECT checkpoint_seq, content_hash FROM audit_checkpoints ORDER BY checkpoint_seq DESC LIMIT 1",
                            &[],
                        )
                        .ok()?;
                    let (next_seq, prev_hash) = match latest.first() {
                        Some(row) => (row.get::<_, i64>(0) as u64 + 1, row.get::<_, String>(1)),
                        None => (0u64, String::new()),
                    };
                    let tip_rows = c
                        .query(
                            "SELECT writer_id, seq, content_hash FROM audit_entries e \
                             WHERE seq = (SELECT MAX(seq) FROM audit_entries WHERE writer_id = e.writer_id)",
                            &[],
                        )
                        .ok()?;
                    let tips: Vec<WriterTip> = tip_rows
                        .iter()
                        .map(|row| WriterTip {
                            writer_id: row.get::<_, String>(0),
                            seq: row.get::<_, i64>(1) as u64,
                            content_hash: row.get::<_, String>(2),
                        })
                        .collect();
                    if tips.is_empty() {
                        return None;
                    }
                    Some((next_seq, prev_hash, tips))
                });
                let (next_seq, prev_hash, tips) = read?;

                // Sign on the caller's thread, so `build` need not be `Send`.
                let cp = build(next_seq, &prev_hash, tips);
                let json = serde_json::to_string(&cp).unwrap_or_default();
                let seq = cp.checkpoint_seq as i64;
                let content_hash = cp.content_hash.clone();

                // Insert on the executor thread. The `checkpoint_seq` primary key
                // rejects a duplicate if another replica committed the same
                // sequence first — the loser just returns None (race lost),
                // matching the advisory-lock behaviour without holding a lock.
                let inserted = ex.run(move |pool| -> bool {
                    let Ok(mut c) = pool.get() else {
                        return false;
                    };
                    c.execute(
                        "INSERT INTO audit_checkpoints (checkpoint_seq, content_hash, data) VALUES ($1, $2, $3)",
                        &[&seq, &content_hash, &json],
                    )
                    .is_ok()
                });
                if inserted {
                    Some(cp)
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(score: f64) -> PostureSnapshot {
        PostureSnapshot {
            timestamp: Utc::now(),
            overall_score: score,
            total_assets: 3,
            by_status: std::collections::BTreeMap::new(),
            trigger: "test".into(),
        }
    }

    /// Regression: the Postgres backend must work when opened and queried from
    /// INSIDE an async runtime — the real gateway (AppState::new + axum handlers)
    /// runs there. Before the dedicated PgExecutor thread, the sync postgres
    /// client's `block_on` panicked with "Cannot start a runtime from within a
    /// runtime". Runs only when QW_TEST_PG_URL is set.
    #[test]
    fn postgres_works_inside_async_runtime() {
        let Ok(url) = std::env::var("QW_TEST_PG_URL") else {
            eprintln!("QW_TEST_PG_URL not set — skipping Postgres async test");
            return;
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Open + write + read, all inside the runtime (would have panicked).
            let s = Store::open_postgres(&url).expect("open_postgres inside async runtime");
            let tenant = format!("async-{}", uuid::Uuid::new_v4());
            s.record_posture(&tenant, &snap(77.0));
            let hist = s.posture_history(&tenant, 10);
            assert_eq!(hist.len(), 1, "posture row round-trips from async context");
            assert_eq!(hist[0].overall_score, 77.0);
        });
    }

    /// Postgres backend integration test. Runs only when QW_TEST_PG_URL points
    /// at a reachable Postgres; otherwise it is skipped so CI stays green without
    /// a database. Uses UUID tenants so it never collides with other data.
    #[test]
    fn postgres_backend_round_trip_and_isolation() {
        let Ok(url) = std::env::var("QW_TEST_PG_URL") else {
            eprintln!("QW_TEST_PG_URL not set — skipping Postgres integration test");
            return;
        };
        let s = Store::open_postgres(&url).expect("connect to Postgres");
        let a = format!("acme-{}", uuid::Uuid::new_v4());
        let b = format!("globex-{}", uuid::Uuid::new_v4());

        // Posture round-trip + chronological order + tenant isolation.
        s.record_posture(&a, &snap(80.0));
        s.record_posture(&a, &snap(60.0));
        s.record_posture(&b, &snap(95.0));
        let ah = s.posture_history(&a, 100);
        assert_eq!(ah.len(), 2);
        assert_eq!(ah[0].overall_score, 80.0, "chronological");
        assert_eq!(ah[1].overall_score, 60.0);
        let bh = s.posture_history(&b, 100);
        assert_eq!(bh.len(), 1);
        assert_eq!(bh[0].overall_score, 95.0);

        // Upsert path (alerts) — the ON CONFLICT clause differs from SQLite.
        let mut al = AlertEvent::new("test", AlertSeverity::Warning, "t", "m");
        al.id = format!("al-{}", uuid::Uuid::new_v4());
        s.record_alert(&a, &al);
        s.record_alert(&a, &al); // same id -> upsert, still one row
        assert_eq!(s.recent_alerts(&a, 10).len(), 1);

        // Flows upsert-increment (counter accumulation).
        s.record_flow(&a, "agent1", "openai", true, false);
        s.record_flow(&a, "agent1", "openai", false, true);
        let flows = s.list_flows(&a);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].requests, 2);
        assert_eq!(flows[0].sensitive, 1);
        assert_eq!(flows[0].threats, 1);

        // Auth sessions: upsert, lookup, delete, and OIDC consume-once — on
        // Postgres, where the ON CONFLICT / delete paths differ from SQLite.
        let th = format!("hash-{}", uuid::Uuid::new_v4());
        let sess = AuthSession {
            username: "carol".into(),
            role: "operator".into(),
            org: a.clone(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            last_used: Utc::now(),
        };
        s.put_auth_session(&th, &sess);
        assert_eq!(s.get_auth_session(&th).unwrap().username, "carol");
        s.delete_auth_session(&th);
        assert!(s.get_auth_session(&th).is_none());

        let st = format!("state-{}", uuid::Uuid::new_v4());
        s.put_oidc_state(&st, Utc::now() + chrono::Duration::minutes(10));
        assert!(s.consume_oidc_state(&st).is_some());
        assert!(s.consume_oidc_state(&st).is_none(), "consumed once");

        // Sharded audit tables on Postgres: BIGINT per-writer seq + the
        // advisory-locked checkpoint path (unique writer id per run).
        {
            use qw_audit::AuditEvent;
            let wa = format!("wa-{}", uuid::Uuid::new_v4());
            let ev = |n: u64| AuditEvent::SessionClosed {
                total_requests: n,
                total_tokens: 0,
            };
            let mut e0 = AuditEntry::new(&wa, 0, "s", ev(0), "");
            e0.content_hash = sha3_256_hex(&e0.content_bytes());
            e0.signature = "sig".into();
            s.append_entry(&e0);
            let mut e1 = AuditEntry::new(&wa, 1, "s", ev(1), &e0.content_hash);
            e1.content_hash = sha3_256_hex(&e1.content_bytes());
            e1.signature = "sig".into();
            s.append_entry(&e1);

            assert_eq!(s.writer_tip(&wa), Some((1, e1.content_hash.clone())));
            assert!(s
                .all_writer_tips()
                .iter()
                .any(|t| t.writer_id == wa && t.seq == 1));

            let cp = s.commit_checkpoint(&|seq, prev, tips| {
                let mut c = AuditCheckpoint::build(seq, prev, tips, Utc::now());
                c.signature = "sig".into();
                c
            });
            assert!(cp.is_some(), "checkpoint committed on Postgres");
            let latest = s.latest_checkpoint().expect("latest checkpoint");
            assert_eq!(latest.checkpoint_seq, cp.unwrap().checkpoint_seq);
        }

        // Cross-tenant isolation.
        assert!(s.recent_alerts(&b, 10).is_empty());
        assert!(s.list_flows(&b).is_empty());
    }

    #[test]
    fn auth_sessions_roundtrip_and_purge() {
        let s = Store::open_in_memory().unwrap();

        // Live session round-trips; unknown hash misses.
        let live = AuthSession {
            username: "alice".into(),
            role: "admin".into(),
            org: "acme".into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            last_used: Utc::now(),
        };
        s.put_auth_session("h-live", &live);
        assert_eq!(s.get_auth_session("h-live").unwrap().role, "admin");
        assert!(s.get_auth_session("h-missing").is_none());

        // Logout deletes it.
        s.delete_auth_session("h-live");
        assert!(s.get_auth_session("h-live").is_none());

        // Purge reaps an already-expired session but keeps a live one.
        s.put_auth_session(
            "h-expired",
            &AuthSession {
                username: "bob".into(),
                role: "viewer".into(),
                org: "acme".into(),
                expires_at: Utc::now() - chrono::Duration::hours(1),
                last_used: Utc::now(),
            },
        );
        s.put_auth_session("h-live2", &live);
        s.purge_expired_auth(Utc::now());
        assert!(s.get_auth_session("h-expired").is_none(), "expired purged");
        assert!(s.get_auth_session("h-live2").is_some(), "live kept");
    }

    #[test]
    fn login_lockout_round_trips_and_clears() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.get_login_lockout("mallory").is_none());
        s.put_login_lockout(
            "mallory",
            &LockoutState {
                failures: 5,
                first_failure_at: Utc::now(),
                locked_until: Some(Utc::now() + chrono::Duration::minutes(15)),
            },
        );
        let got = s.get_login_lockout("mallory").expect("lockout present");
        assert_eq!(got.failures, 5);
        assert!(got.locked_until.is_some());
        // A successful login clears it.
        s.clear_login_lockout("mallory");
        assert!(s.get_login_lockout("mallory").is_none());
    }

    #[test]
    fn touch_updates_last_used() {
        let s = Store::open_in_memory().unwrap();
        let t0 = Utc::now() - chrono::Duration::hours(2);
        let mut sess = AuthSession {
            username: "dave".into(),
            role: "viewer".into(),
            org: "acme".into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            last_used: t0,
        };
        s.put_auth_session("h-touch", &sess);
        let now = Utc::now();
        sess.last_used = now;
        s.touch_auth_session("h-touch", &sess);
        let got = s.get_auth_session("h-touch").unwrap();
        assert!(got.last_used > t0, "last_used advanced");
    }

    #[test]
    fn oidc_state_is_consumed_once() {
        let s = Store::open_in_memory().unwrap();
        s.put_oidc_state("csrf-1", Utc::now() + chrono::Duration::minutes(10));
        assert!(s.consume_oidc_state("csrf-1").is_some());
        assert!(s.consume_oidc_state("csrf-1").is_none(), "replay rejected");
        assert!(s.consume_oidc_state("never-issued").is_none());
    }

    #[test]
    fn posture_history_is_tenant_isolated() {
        let s = Store::open_in_memory().unwrap();
        s.record_posture("acme", &snap(80.0));
        s.record_posture("acme", &snap(60.0));
        s.record_posture("globex", &snap(95.0));

        let acme = s.posture_history("acme", 100);
        let globex = s.posture_history("globex", 100);
        assert_eq!(acme.len(), 2);
        assert_eq!(globex.len(), 1);
        assert_eq!(globex[0].overall_score, 95.0);
        // chronological order
        assert_eq!(acme[0].overall_score, 80.0);
        assert_eq!(acme[1].overall_score, 60.0);
    }

    #[test]
    fn posture_dedupes_identical_consecutive() {
        let s = Store::open_in_memory().unwrap();
        s.record_posture("t", &snap(50.0));
        s.record_posture("t", &snap(50.0));
        assert_eq!(s.posture_history("t", 100).len(), 1);
    }

    fn b64(b: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
    }

    /// Sharded audit: two writers append to one store, a global checkpoint
    /// commits both tips, and the whole thing verifies (per-writer chains +
    /// checkpoint chain) under the gateway's ML-DSA key.
    #[test]
    fn audit_sharded_roundtrip_and_verify() {
        use qw_audit::{verify_sharded, AuditEvent};

        let s = Store::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let id = qw_crypto::GatewayIdentity::load_or_generate(dir.path()).unwrap();
        let pk = id.public_key_bytes();

        let mk = |writer: &str, seq: u64, prev: &str| -> AuditEntry {
            let ev = AuditEvent::SessionClosed {
                total_requests: seq,
                total_tokens: 0,
            };
            let mut e = AuditEntry::new(writer, seq, "s", ev, prev);
            e.content_hash = sha3_256_hex(&e.content_bytes());
            e.signature = b64(&id.sign(e.content_hash.as_bytes()).unwrap());
            e
        };

        let a0 = mk("nodeA", 0, "");
        s.append_entry(&a0);
        let a1 = mk("nodeA", 1, &a0.content_hash);
        s.append_entry(&a1);
        let b0 = mk("nodeB", 0, "");
        s.append_entry(&b0);

        // Resume + tips.
        assert_eq!(s.writer_tip("nodeA"), Some((1, a1.content_hash.clone())));
        assert_eq!(s.writer_tip("nodeB"), Some((0, b0.content_hash.clone())));
        assert_eq!(s.all_writer_tips().len(), 2);

        // Commit a global checkpoint: the store assigns seq + prev + tips under
        // its lock; the closure signs.
        let cp = s
            .commit_checkpoint(&|seq, prev, tips| {
                let mut cp = AuditCheckpoint::build(seq, prev, tips, Utc::now());
                cp.signature = b64(&id.sign(cp.content_hash.as_bytes()).unwrap());
                cp
            })
            .expect("checkpoint committed");
        assert_eq!(cp.checkpoint_seq, 0);
        assert_eq!(cp.tips.len(), 2);

        // Full sharded verification.
        let entries = s.list_entries(1000);
        let checkpoints = s.list_checkpoints();
        assert_eq!(entries.len(), 3);
        let r = verify_sharded(&entries, &checkpoints, &pk);
        assert!(r.valid, "expected valid, errors: {:?}", r.errors);
        assert_eq!(r.writers_checked, 2);
        assert_eq!(r.checkpoints_checked, 1);
        assert_eq!(r.signatures_valid, 3);

        // A second checkpoint chains to the first.
        let cp2 = s
            .commit_checkpoint(&|seq, prev, tips| {
                let mut cp = AuditCheckpoint::build(seq, prev, tips, Utc::now());
                cp.signature = b64(&id.sign(cp.content_hash.as_bytes()).unwrap());
                cp
            })
            .expect("second checkpoint");
        assert_eq!(cp2.checkpoint_seq, 1);
        assert_eq!(cp2.prev_checkpoint_hash, cp.content_hash);
    }

    #[test]
    fn alerts_roundtrip_and_isolate() {
        let s = Store::open_in_memory().unwrap();
        s.record_alert(
            "a",
            &AlertEvent::new("test", AlertSeverity::Critical, "t", "m"),
        );
        s.record_alert("b", &AlertEvent::new("test", AlertSeverity::Info, "t", "m"));
        assert_eq!(s.recent_alerts("a", 10).len(), 1);
        assert_eq!(
            s.recent_alerts("a", 10)[0].severity,
            AlertSeverity::Critical
        );
        assert_eq!(s.recent_alerts("b", 10).len(), 1);
        assert_eq!(s.tenants().len(), 0); // alerts not counted in tenants()
    }
}
