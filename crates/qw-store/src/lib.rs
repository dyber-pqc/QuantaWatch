//! SQLite-backed, tenant-scoped persistence for QuantaWatch.
//!
//! Replaces the per-crate JSONL stores. Every row carries a `tenant` column for
//! multi-tenant isolation plus the full record serialized as JSON, which gives
//! exact round-trip without mapping every enum to a column.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

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

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Store {
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
            CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant);
            CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_posture_tenant ON posture(tenant);
            CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant);
            CREATE INDEX IF NOT EXISTS idx_remediations_tenant ON remediations(tenant);
            "#,
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.conn.lock().unwrap().execute_batch(
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
            "#,
        )?;
        Ok(store)
    }

    fn list_json<T: for<'de> Deserialize<'de>>(
        &self,
        sql: &str,
        tenant: &str,
        limit: usize,
    ) -> Vec<T> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![tenant, limit as i64], |row| row.get::<_, String>(0));
        match rows {
            Ok(rows) => rows
                .filter_map(|r| r.ok())
                .filter_map(|j| serde_json::from_str(&j).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
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

        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO scans (id, tenant, completed_at, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                record.id,
                tenant,
                record.completed_at.to_rfc3339(),
                serde_json::to_string(&record).unwrap_or_default()
            ],
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
            let _ = conn.execute(
                "INSERT INTO findings (id, tenant, scan_id, created_at, data) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![fr.id, tenant, fr.scan_id, fr.created_at.to_rfc3339(), serde_json::to_string(&fr).unwrap_or_default()],
            );
        }
    }

    pub fn list_scans(&self, tenant: &str, limit: usize) -> Vec<ScanRecord> {
        self.list_json(
            "SELECT data FROM scans WHERE tenant = ?1 ORDER BY completed_at DESC LIMIT ?2",
            tenant,
            limit,
        )
    }

    pub fn get_scan(&self, tenant: &str, id: &str) -> Option<ScanRecord> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM scans WHERE tenant = ?1 AND id = ?2",
            params![tenant, id],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|j| serde_json::from_str(&j).ok())
    }

    pub fn findings_for_scan(&self, tenant: &str, scan_id: &str) -> Vec<FindingRecord> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn
            .prepare("SELECT data FROM findings WHERE tenant = ?1 AND scan_id = ?2 ORDER BY seq")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![tenant, scan_id], |row| row.get::<_, String>(0));
        match rows {
            Ok(rows) => rows
                .filter_map(|r| r.ok())
                .filter_map(|j| serde_json::from_str(&j).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn all_findings(&self, tenant: &str) -> Vec<FindingRecord> {
        self.list_json(
            "SELECT data FROM findings WHERE tenant = ?1 ORDER BY seq LIMIT ?2",
            tenant,
            1_000_000,
        )
    }

    pub fn get_finding(&self, tenant: &str, id: &str) -> Option<FindingRecord> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM findings WHERE tenant = ?1 AND id = ?2 LIMIT 1",
            params![tenant, id],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|j| serde_json::from_str(&j).ok())
    }

    // ---- Posture history ----

    pub fn record_posture(&self, tenant: &str, snap: &PostureSnapshot) {
        let conn = self.conn.lock().unwrap();
        // Skip if identical to the most recent snapshot for this tenant.
        let last: Option<String> = conn
            .query_row(
                "SELECT data FROM posture WHERE tenant = ?1 ORDER BY seq DESC LIMIT 1",
                params![tenant],
                |r| r.get(0),
            )
            .ok();
        if let Some(prev) = last.and_then(|j| serde_json::from_str::<PostureSnapshot>(&j).ok()) {
            if (prev.overall_score - snap.overall_score).abs() < f64::EPSILON
                && prev.total_assets == snap.total_assets
            {
                return;
            }
        }
        let _ = conn.execute(
            "INSERT INTO posture (tenant, data) VALUES (?1, ?2)",
            params![tenant, serde_json::to_string(snap).unwrap_or_default()],
        );
    }

    pub fn posture_history(&self, tenant: &str, limit: usize) -> Vec<PostureSnapshot> {
        let mut v: Vec<PostureSnapshot> = self.list_json(
            "SELECT data FROM posture WHERE tenant = ?1 ORDER BY seq DESC LIMIT ?2",
            tenant,
            limit,
        );
        v.reverse(); // chronological
        v
    }

    pub fn latest_posture(&self, tenant: &str) -> Option<PostureSnapshot> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM posture WHERE tenant = ?1 ORDER BY seq DESC LIMIT 1",
            params![tenant],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|j| serde_json::from_str(&j).ok())
    }

    // ---- Remediations ----

    pub fn record_remediation(&self, tenant: &str, ticket: &RemediationTicket) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO remediations (id, tenant, data, seq) VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(seq),0)+1 FROM remediations))",
            params![ticket.id, tenant, serde_json::to_string(ticket).unwrap_or_default()],
        );
    }

    pub fn list_remediations(&self, tenant: &str) -> Vec<RemediationTicket> {
        self.list_json(
            "SELECT data FROM remediations WHERE tenant = ?1 ORDER BY seq DESC LIMIT ?2",
            tenant,
            1000,
        )
    }

    // ---- Alerts ----

    pub fn record_alert(&self, tenant: &str, alert: &AlertEvent) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO alerts (id, tenant, data, seq) VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(seq),0)+1 FROM alerts))",
            params![alert.id, tenant, serde_json::to_string(alert).unwrap_or_default()],
        );
    }

    pub fn recent_alerts(&self, tenant: &str, limit: usize) -> Vec<AlertEvent> {
        self.list_json(
            "SELECT data FROM alerts WHERE tenant = ?1 ORDER BY seq DESC LIMIT ?2",
            tenant,
            limit,
        )
    }

    // ---- Sessions ----

    pub fn upsert_session(&self, tenant: &str, s: &SessionRow) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, tenant, data) VALUES (?1, ?2, ?3)",
            params![
                s.session_id,
                tenant,
                serde_json::to_string(s).unwrap_or_default()
            ],
        );
    }

    pub fn list_sessions(&self, tenant: &str, limit: usize) -> Vec<SessionRow> {
        self.list_json(
            "SELECT data FROM sessions WHERE tenant = ?1 ORDER BY rowid DESC LIMIT ?2",
            tenant,
            limit,
        )
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
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO flows (tenant, agent, provider, requests, sensitive, threats, last_seen)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)
             ON CONFLICT(tenant, agent, provider) DO UPDATE SET
               requests = requests + 1,
               sensitive = sensitive + ?4,
               threats = threats + ?5,
               last_seen = ?6",
            params![
                tenant,
                agent,
                provider,
                sensitive as i64,
                threat as i64,
                Utc::now().to_rfc3339()
            ],
        );
    }

    pub fn list_flows(&self, tenant: &str) -> Vec<FlowRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT agent, provider, requests, sensitive, threats, last_seen FROM flows WHERE tenant = ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![tenant], |row| {
            let last: String = row.get(5).unwrap_or_default();
            Ok(FlowRow {
                agent: row.get(0)?,
                provider: row.get(1)?,
                requests: row.get::<_, i64>(2)? as u64,
                sensitive: row.get::<_, i64>(3)? as u64,
                threats: row.get::<_, i64>(4)? as u64,
                last_seen: chrono::DateTime::parse_from_rfc3339(&last)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        });
        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    // ---- SLO snapshots (breach trends) ----

    pub fn record_slo_snapshot(&self, tenant: &str, snap: &SloSnapshot) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO slo_snapshots (tenant, data) VALUES (?1, ?2)",
            params![tenant, serde_json::to_string(snap).unwrap_or_default()],
        );
    }

    pub fn slo_history(&self, tenant: &str, limit: usize) -> Vec<SloSnapshot> {
        let mut v: Vec<SloSnapshot> = self.list_json(
            "SELECT data FROM slo_snapshots WHERE tenant = ?1 ORDER BY seq DESC LIMIT ?2",
            tenant,
            limit,
        );
        v.reverse();
        v
    }

    // ---- Asset inventory ----

    pub fn upsert_asset(&self, tenant: &str, asset: &AssetRow) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO assets (id, tenant, data) VALUES (?1, ?2, ?3)",
            params![
                asset.id,
                tenant,
                serde_json::to_string(asset).unwrap_or_default()
            ],
        );
    }

    pub fn list_assets(&self, tenant: &str) -> Vec<AssetRow> {
        self.list_json(
            "SELECT data FROM assets WHERE tenant = ?1 ORDER BY id LIMIT ?2",
            tenant,
            100_000,
        )
    }

    // ---- Graph snapshots (drift/timeline) ----

    pub fn record_graph_snapshot(&self, tenant: &str, snap: &GraphSnapshot) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO graph_snapshots (tenant, data) VALUES (?1, ?2)",
            params![tenant, serde_json::to_string(snap).unwrap_or_default()],
        );
    }

    pub fn graph_timeline(&self, tenant: &str, limit: usize) -> Vec<GraphSnapshot> {
        let mut v: Vec<GraphSnapshot> = self.list_json(
            "SELECT data FROM graph_snapshots WHERE tenant = ?1 ORDER BY seq DESC LIMIT ?2",
            tenant,
            limit,
        );
        v.reverse();
        v
    }

    pub fn latest_graph_snapshot(&self, tenant: &str) -> Option<GraphSnapshot> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM graph_snapshots WHERE tenant = ?1 ORDER BY seq DESC LIMIT 1",
            params![tenant],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|j| serde_json::from_str(&j).ok())
    }

    /// Distinct tenants that have any data (for admin/cross-tenant views).
    pub fn tenants(&self) -> Vec<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT DISTINCT tenant FROM scans UNION SELECT DISTINCT tenant FROM findings UNION SELECT DISTINCT tenant FROM sessions",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |row| row.get::<_, String>(0));
        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
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
            by_status: HashMap::new(),
            trigger: "test".into(),
        }
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
