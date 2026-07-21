use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCapability {
    DiscoverTargets,
    CreateRemediation,
    SyncStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStatus {
    pub connected: bool,
    pub user: Option<String>,
    pub scopes: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationOpts {
    pub project: Option<String>,
    pub assignee: Option<String>,
    pub priority: Option<String>,
    pub labels: Vec<String>,
}

impl Default for RemediationOpts {
    fn default() -> Self {
        Self {
            project: None,
            assignee: None,
            priority: None,
            labels: vec!["pqc-remediation".to_string(), "quantawatch".to_string()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    InProgress,
    Resolved,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationTicket {
    pub id: String,
    pub integration_id: String,
    pub external_id: String,
    pub external_url: String,
    pub status: TicketStatus,
    pub finding_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub id: String,
    pub integration_type: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub api_token_env: String,
    /// Secret supplied directly by a UI-managed connection. Takes precedence
    /// over `api_token_env`. Never serialized back out (kept off YAML/JSON).
    #[serde(default, skip_serializing)]
    pub token: Option<String>,
    #[serde(default)]
    pub default_project: Option<String>,
    /// ENV var holding this integration's own inbound-webhook secret (overrides the global).
    #[serde(default)]
    pub webhook_secret_env: Option<String>,
    #[serde(default)]
    pub settings: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrationInfo {
    pub id: String,
    pub integration_type: String,
    pub display_name: String,
    pub capabilities: Vec<IntegrationCapability>,
    pub status: ConnectionStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remediation_opts_default() {
        let opts = RemediationOpts::default();
        assert!(opts.project.is_none());
        assert!(opts.assignee.is_none());
        assert!(opts.priority.is_none());
        assert_eq!(opts.labels.len(), 2);
        assert_eq!(opts.labels[0], "pqc-remediation");
        assert_eq!(opts.labels[1], "quantawatch");
    }
}
