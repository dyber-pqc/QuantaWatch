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

use qw_cbom::PostureSnapshot;
use qw_crypto::sha3_256_hex;
use qw_integrations::RemediationTicket;
use qw_scanner::{FindingRecord, ScanRecord, ScanResult, ScanTarget};

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

/// Storage backend. SQLite (single-node, file or in-memory) or Postgres (shared
/// across replicas for HA). Both keep the same JSON-blob-per-row model, so the
/// public API is identical; only the SQL dialect differs.
enum Backend {
    Sqlite(Mutex<Connection>),
    Pg(PgPool),
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

/// Postgres schema. Same shape as SQLite; `BIGSERIAL` replaces
/// `INTEGER PRIMARY KEY AUTOINCREMENT` for the append-only sequence.
const PG_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, completed_at TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS findings (id TEXT, tenant TEXT NOT NULL, scan_id TEXT, created_at TEXT, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS posture (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS remediations (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGINT);
    CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGINT);
    CREATE TABLE IF NOT EXISTS sessions (session_id TEXT, tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL, PRIMARY KEY (tenant, session_id));
    CREATE TABLE IF NOT EXISTS flows (tenant TEXT NOT NULL, agent TEXT NOT NULL, provider TEXT NOT NULL, requests BIGINT NOT NULL DEFAULT 0, sensitive BIGINT NOT NULL DEFAULT 0, threats BIGINT NOT NULL DEFAULT 0, last_seen TEXT, PRIMARY KEY (tenant, agent, provider));
    CREATE TABLE IF NOT EXISTS graph_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS assets (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
    CREATE TABLE IF NOT EXISTS slo_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS governance_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq BIGSERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS oidc_states (state TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
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
        // Connect directly once to surface a clear error (r2d2 hides the cause)
        // and apply the schema.
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
        Ok(Self {
            backend: Arc::new(Backend::Pg(pool)),
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
            Backend::Pg(pool) => {
                if let Ok(mut c) = pool.get() {
                    let p: Vec<&(dyn postgres::types::ToSql + Sync)> = params
                        .iter()
                        .map(|s| s as &(dyn postgres::types::ToSql + Sync))
                        .collect();
                    if let Err(e) = c.execute(pg_sql, &p[..]) {
                        tracing::warn!(error = %e, "postgres write failed");
                    }
                }
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
            Backend::Pg(pool) => {
                let Ok(mut c) = pool.get() else {
                    return Vec::new();
                };
                let p: Vec<&(dyn postgres::types::ToSql + Sync)> = params
                    .iter()
                    .map(|s| s as &(dyn postgres::types::ToSql + Sync))
                    .collect();
                match c.query(&pg_ph(sqlite_sql), &p[..]) {
                    Ok(rows) => rows.iter().map(|row| row.get::<_, String>(0)).collect(),
                    Err(e) => {
                        tracing::warn!(error = %e, "postgres query failed");
                        Vec::new()
                    }
                }
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
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oidc_states (
                state TEXT PRIMARY KEY, expires_at TEXT NOT NULL
            );
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
            CREATE TABLE posture (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE remediations (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER);
            CREATE TABLE alerts (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER);
            CREATE TABLE sessions (session_id TEXT, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, session_id));
            CREATE TABLE flows (tenant TEXT NOT NULL, agent TEXT NOT NULL, provider TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0, sensitive INTEGER NOT NULL DEFAULT 0, threats INTEGER NOT NULL DEFAULT 0, last_seen TEXT, PRIMARY KEY (tenant, agent, provider));
            CREATE TABLE graph_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE assets (id TEXT NOT NULL, tenant TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE slo_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE governance_snapshots (tenant TEXT NOT NULL, data TEXT NOT NULL, seq INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE auth_sessions (token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at TEXT NOT NULL);
            CREATE TABLE oidc_states (state TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
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
            let fr = FindingRecord {
                id: finding.id.clone(),
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
            };
            let fjson = serde_json::to_string(&fr).unwrap_or_default();
            let created = fr.created_at.to_rfc3339();
            self.exec(
                "INSERT INTO findings (id, tenant, scan_id, created_at, data) VALUES (?1, ?2, ?3, ?4, ?5)",
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
            Backend::Pg(pool) => {
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
        };
        s.put_auth_session(&th, &sess);
        assert_eq!(s.get_auth_session(&th).unwrap().username, "carol");
        s.delete_auth_session(&th);
        assert!(s.get_auth_session(&th).is_none());

        let st = format!("state-{}", uuid::Uuid::new_v4());
        s.put_oidc_state(&st, Utc::now() + chrono::Duration::minutes(10));
        assert!(s.consume_oidc_state(&st).is_some());
        assert!(s.consume_oidc_state(&st).is_none(), "consumed once");

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
            },
        );
        s.put_auth_session("h-live2", &live);
        s.purge_expired_auth(Utc::now());
        assert!(s.get_auth_session("h-expired").is_none(), "expired purged");
        assert!(s.get_auth_session("h-live2").is_some(), "live kept");
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
