//! Live threats feed, derived from the tamper-evident audit log.
//!
//! Threats aren't a separate store — they're the security-relevant subset of the
//! signed audit trail (in-path threat blocks, policy violations, quantum-unsafe
//! channels blocked by enforcement, RBAC denials, failed logins). Reading them
//! from the audit log means every threat shown is already cryptographically
//! attested, and the same event powers the SIEM export and the board report.

use axum::{extract::State, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde_json::json;

use qw_audit::{AuditBackend, AuditEvent};

use crate::state::AppState;

fn norm_severity(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "med" => "medium",
        _ => "low",
    }
}

/// GET /api/threats — recent detections from the audit log, newest first.
pub async fn get_threats(State(state): State<AppState>) -> impl IntoResponse {
    let entries = state.store.list_entries(500);

    let mut rows: Vec<(DateTime<Utc>, serde_json::Value)> = Vec::new();
    for e in &entries {
        let mapped: Option<(&str, &str, String, bool)> = match &e.event {
            AuditEvent::ThreatBlocked {
                category,
                severity,
                pattern,
            } => Some((
                category.as_str(),
                norm_severity(severity.as_str()),
                format!("In-path monitor blocked {category} (pattern: {pattern})"),
                true,
            )),
            AuditEvent::PolicyViolation {
                rule,
                reason,
                agent_name,
            } => Some((
                "policy_violation",
                "medium",
                format!("Agent '{agent_name}' violated policy '{rule}': {reason}"),
                true,
            )),
            AuditEvent::CryptoPolicyEnforced {
                provider,
                agent,
                action,
                channel_status,
                required,
            } => {
                let blocked = action == "blocked";
                Some((
                    "quantum_unsafe_channel",
                    if blocked { "high" } else { "medium" },
                    format!(
                        "Agent '{agent}' → {provider}: channel {channel_status} is below required {required} ({action})"
                    ),
                    blocked,
                ))
            }
            AuditEvent::AccessDenied {
                principal,
                method,
                path,
                required_permission,
            } => Some((
                "unauthorized_access",
                "medium",
                format!("{principal} was denied {method} {path} (needs {required_permission})"),
                true,
            )),
            AuditEvent::LoginFailed {
                username,
                client_ip,
            } => Some((
                "failed_login",
                "low",
                format!("Failed login for '{username}' from {client_ip}"),
                false,
            )),
            _ => None,
        };

        if let Some((threat_type, severity, description, blocked)) = mapped {
            rows.push((
                e.timestamp,
                json!({
                    "id": e.sequence,
                    "timestamp": e.timestamp.to_rfc3339(),
                    "session_id": e.session_id,
                    "threat_type": threat_type,
                    "severity": severity,
                    "description": description,
                    "blocked": blocked,
                }),
            ));
        }
    }

    rows.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    let threats: Vec<serde_json::Value> = rows.into_iter().map(|(_, v)| v).collect();
    let by = |s: &str| threats.iter().filter(|t| t["severity"] == s).count();

    Json(json!({
        "threats": threats,
        "total": threats.len(),
        "critical": by("critical"),
        "high": by("high"),
        "medium": by("medium"),
        "low": by("low"),
    }))
}
