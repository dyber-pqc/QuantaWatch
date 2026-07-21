use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single audit log entry with PQC signature.
///
/// Entries are sharded by `writer_id`: each gateway replica owns one chain, and
/// `sequence`/`prev_hash` are scoped to that writer. `writer_id` is committed in
/// the content hash, so an entry cannot be re-attributed to another writer's
/// chain without detection. Global tamper-evidence across writers comes from the
/// periodic [`crate::AuditCheckpoint`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    /// Which replica's chain this belongs to.
    #[serde(default)]
    pub writer_id: String,
    /// Position within this writer's chain (0-based).
    pub sequence: u64,
    pub session_id: String,
    pub event: AuditEvent,
    /// Content hash of the previous entry in THIS writer's chain.
    pub prev_hash: String,
    pub content_hash: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
}

/// Types of audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    SessionCreated {
        agent_name: String,
        provider: String,
        model: String,
        client_ip: String,
    },
    RequestProcessed {
        provider: String,
        model: String,
        prompt_hash: String,
        response_hash: String,
        policy_decision: String,
        tools_requested: Vec<String>,
        tools_allowed: Vec<String>,
        tools_denied: Vec<String>,
        threats_detected: u32,
        latency_ms: u64,
    },
    ThreatBlocked {
        category: String,
        severity: String,
        pattern: String,
    },
    PolicyViolation {
        rule: String,
        reason: String,
        agent_name: String,
    },
    SessionClosed {
        total_requests: u64,
        total_tokens: u64,
    },
    ScanCompleted {
        scan_id: String,
        scanner_id: String,
        target: String,
        finding_count: u32,
        status: String,
    },
    FindingCreated {
        finding_id: String,
        category: String,
        severity: String,
        pqc_status: String,
        asset: String,
    },
    PostureChanged {
        previous_score: f64,
        new_score: f64,
        trigger: String,
    },
    IntegrationSync {
        integration_id: String,
        action: String,
        detail: String,
    },
    // ---- Access / change events (SOC2 CC6/CC7/CC8) ----
    LoginSucceeded {
        principal: String,
        auth_method: String,
        client_ip: String,
    },
    LoginFailed {
        username: String,
        client_ip: String,
    },
    Logout {
        principal: String,
    },
    /// An authenticated caller was refused an endpoint by RBAC.
    AccessDenied {
        principal: String,
        method: String,
        path: String,
        required_permission: String,
    },
    /// A successful mutating admin action (change tracking).
    AdminAction {
        principal: String,
        method: String,
        path: String,
        permission: String,
    },
    /// In-path crypto enforcement acted on a flow (flagged or blocked).
    CryptoPolicyEnforced {
        provider: String,
        agent: String,
        action: String,
        channel_status: String,
        required: String,
    },
    /// A crypto-agility policy was enforced on a violating asset (a remediation
    /// PR/ticket was opened, or an alert raised).
    AgilityPolicyEnforced {
        policy_id: String,
        severity: String,
        resource: String,
        action: String,
        outcome: String,
    },
    /// The PQC-terminating overlay began protecting a route (hybrid-PQC TLS on
    /// the client leg, forwarding to a legacy upstream).
    OverlayRouteProtected {
        route_id: String,
        listen: String,
        upstream: String,
        mode: String,
    },
}

impl AuditEntry {
    /// Create the content bytes for hashing (everything except content_hash, signature, merkle_root).
    pub fn content_bytes(&self) -> Vec<u8> {
        let content = serde_json::json!({
            "id": self.id,
            "timestamp": self.timestamp.to_rfc3339(),
            "writer_id": self.writer_id,
            "sequence": self.sequence,
            "session_id": self.session_id,
            "event": self.event,
            "prev_hash": self.prev_hash,
        });
        serde_json::to_vec(&content).unwrap_or_default()
    }

    /// Create a new entry from an event (without hash/signature, which are added by the logger).
    pub fn new(
        writer_id: &str,
        sequence: u64,
        session_id: &str,
        event: AuditEvent,
        prev_hash: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            writer_id: writer_id.to_string(),
            sequence,
            session_id: session_id.to_string(),
            event,
            prev_hash: prev_hash.to_string(),
            content_hash: String::new(),
            signature: String::new(),
            merkle_root: None,
        }
    }
}
