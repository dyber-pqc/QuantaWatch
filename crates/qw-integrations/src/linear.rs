use crate::registry::{Integration, IntegrationError};
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use qw_scanner::{Finding, FindingSeverity, ScanTarget};

pub struct LinearIntegration {
    id: String,
    token: String,
    team_id: Option<String>,
    client: reqwest::Client,
}

impl LinearIntegration {
    pub fn from_config(config: &IntegrationConfig) -> Option<Self> {
        let token = std::env::var(&config.api_token_env).ok()?;
        Some(Self {
            id: config.id.clone(),
            token,
            team_id: config.settings.get("team_id").cloned(),
            client: reqwest::Client::new(),
        })
    }

    fn severity_to_priority(severity: &FindingSeverity) -> u8 {
        match severity {
            FindingSeverity::Critical => 1, // Urgent
            FindingSeverity::High => 2,     // High
            FindingSeverity::Medium => 3,   // Medium
            FindingSeverity::Low => 4,      // Low
            FindingSeverity::Info => 0,     // No priority
        }
    }
}

#[async_trait]
impl Integration for LinearIntegration {
    fn id(&self) -> &str {
        &self.id
    }
    fn display_name(&self) -> &str {
        "Linear"
    }

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        vec![
            IntegrationCapability::CreateRemediation,
            IntegrationCapability::SyncStatus,
        ]
    }

    async fn test_connection(&self) -> Result<ConnectionStatus, IntegrationError> {
        let query = serde_json::json!({
            "query": "{ viewer { id name email } }"
        });

        let resp = self
            .client
            .post("https://api.linear.app/graphql")
            .header("Authorization", &self.token)
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await?;

        if resp.status().is_success() {
            let result: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| IntegrationError::ApiError(e.to_string()))?;
            let name = result["data"]["viewer"]["name"].as_str().map(String::from);
            Ok(ConnectionStatus {
                connected: true,
                user: name,
                scopes: vec!["write".to_string()],
                error: None,
            })
        } else {
            Ok(ConnectionStatus {
                connected: false,
                user: None,
                scopes: vec![],
                error: Some(format!("HTTP {}", resp.status())),
            })
        }
    }

    async fn remediation_status(
        &self,
        external_id: &str,
    ) -> Result<TicketStatus, IntegrationError> {
        let query = serde_json::json!({
            "query": format!("query {{ issue(id: \"{external_id}\") {{ state {{ type }} }} }}")
        });
        let v: serde_json::Value = self
            .client
            .post("https://api.linear.app/graphql")
            .header("Authorization", &self.token)
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| IntegrationError::ApiError(e.to_string()))?;
        Ok(match v["data"]["issue"]["state"]["type"].as_str() {
            Some("completed") => TicketStatus::Resolved,
            Some("canceled") => TicketStatus::Closed,
            Some("started") => TicketStatus::InProgress,
            Some("backlog") | Some("unstarted") => TicketStatus::Open,
            _ => TicketStatus::Unknown,
        })
    }

    async fn discover_targets(&self) -> Result<Vec<ScanTarget>, IntegrationError> {
        Err(IntegrationError::NotSupported(
            "Linear does not discover scan targets".to_string(),
        ))
    }

    async fn create_remediation(
        &self,
        finding: &Finding,
        _opts: &RemediationOpts,
    ) -> Result<RemediationTicket, IntegrationError> {
        let team_id = self.team_id.as_deref().ok_or_else(|| {
            IntegrationError::NotConfigured("No Linear team_id configured".to_string())
        })?;

        let priority = Self::severity_to_priority(&finding.severity);
        let remediation_text = finding
            .remediation
            .as_deref()
            .unwrap_or("Review and remediate the cryptographic finding.");

        let description = format!(
            "## PQC Finding: {}\n\n\
             **Severity:** {:?}\n\
             **PQC Status:** {}\n\
             **Category:** {}\n\
             **Location:** {}\n\n\
             ### Description\n{}\n\n\
             ### Remediation\n{}\n\n\
             ---\n\
             _Created by QuantaWatch Cryptographic Posture Management_",
            finding.title,
            finding.severity,
            finding.pqc_status,
            finding.category,
            finding.asset.location.path,
            finding.description,
            remediation_text,
        );

        let title = format!("[PQC] {}", finding.title);

        let mutation = format!(
            r#"mutation {{ issueCreate(input: {{ teamId: "{}", title: "{}", description: "{}", priority: {} }}) {{ success issue {{ id identifier url }} }} }}"#,
            team_id,
            title.replace('"', r#"\""#),
            description.replace('"', r#"\""#).replace('\n', r#"\n"#),
            priority,
        );

        let query = serde_json::json!({ "query": mutation });

        let resp = self
            .client
            .post("https://api.linear.app/graphql")
            .header("Authorization", &self.token)
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IntegrationError::ApiError(format!(
                "Failed to create issue: {body}"
            )));
        }

        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IntegrationError::ApiError(e.to_string()))?;

        let issue = &result["data"]["issueCreate"]["issue"];
        let identifier = issue["identifier"].as_str().unwrap_or_default().to_string();
        let url = issue["url"].as_str().unwrap_or_default().to_string();

        Ok(RemediationTicket {
            id: uuid::Uuid::new_v4().to_string(),
            integration_id: self.id.clone(),
            external_id: identifier,
            external_url: url,
            status: TicketStatus::Open,
            finding_id: finding.id.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
}
