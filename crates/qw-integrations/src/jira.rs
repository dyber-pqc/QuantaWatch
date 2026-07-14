use async_trait::async_trait;
use chrono::Utc;
use qw_scanner::{ScanTarget, Finding, FindingSeverity};
use crate::types::*;
use crate::registry::{Integration, IntegrationError};

pub struct JiraIntegration {
    id: String,
    token: String,
    email: String,
    base_url: String,
    default_project: Option<String>,
    client: reqwest::Client,
}

impl JiraIntegration {
    pub fn from_config(config: &IntegrationConfig) -> Option<Self> {
        let token = std::env::var(&config.api_token_env).ok()?;
        let email = config.settings.get("email").cloned()?;
        Some(Self {
            id: config.id.clone(),
            token,
            email,
            base_url: config.base_url.clone()?,
            default_project: config.default_project.clone(),
            client: reqwest::Client::new(),
        })
    }

    fn severity_to_priority(severity: &FindingSeverity) -> &str {
        match severity {
            FindingSeverity::Critical => "Highest",
            FindingSeverity::High => "High",
            FindingSeverity::Medium => "Medium",
            FindingSeverity::Low => "Low",
            FindingSeverity::Info => "Lowest",
        }
    }
}

#[async_trait]
impl Integration for JiraIntegration {
    fn id(&self) -> &str { &self.id }
    fn display_name(&self) -> &str { "Jira" }

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        vec![IntegrationCapability::CreateRemediation, IntegrationCapability::SyncStatus]
    }

    async fn test_connection(&self) -> Result<ConnectionStatus, IntegrationError> {
        let resp = self.client.get(format!("{}/rest/api/3/myself", self.base_url))
            .basic_auth(&self.email, Some(&self.token))
            .header("Accept", "application/json")
            .send()
            .await?;

        if resp.status().is_success() {
            let user: serde_json::Value = resp.json().await
                .map_err(|e| IntegrationError::ApiError(e.to_string()))?;
            Ok(ConnectionStatus {
                connected: true,
                user: user["displayName"].as_str().map(String::from),
                scopes: vec!["write:jira-work".to_string()],
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

    async fn discover_targets(&self) -> Result<Vec<ScanTarget>, IntegrationError> {
        Err(IntegrationError::NotSupported(
            "Jira does not discover scan targets".to_string(),
        ))
    }

    async fn remediation_status(&self, external_id: &str) -> Result<TicketStatus, IntegrationError> {
        use base64::Engine;
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.email, self.token));
        let v: serde_json::Value = self.client
            .get(format!("{}/rest/api/3/issue/{}?fields=status", self.base_url, external_id))
            .header("Authorization", format!("Basic {auth}"))
            .header("Accept", "application/json")
            .send().await?.json().await.map_err(|e| IntegrationError::ApiError(e.to_string()))?;
        Ok(match v["fields"]["status"]["statusCategory"]["key"].as_str() {
            Some("done") => TicketStatus::Resolved,
            Some("indeterminate") => TicketStatus::InProgress,
            Some("new") => TicketStatus::Open,
            _ => TicketStatus::Unknown,
        })
    }

    async fn create_remediation(
        &self,
        finding: &Finding,
        opts: &RemediationOpts,
    ) -> Result<RemediationTicket, IntegrationError> {
        let project = opts.project.as_deref()
            .or(self.default_project.as_deref())
            .ok_or_else(|| IntegrationError::NotConfigured(
                "No Jira project specified".to_string(),
            ))?;

        let priority = Self::severity_to_priority(&finding.severity);
        let remediation_text = finding.remediation.as_deref()
            .unwrap_or("Review and remediate the cryptographic finding.");

        let description = format!(
            "h2. PQC Finding: {}\n\n\
             *Severity:* {:?}\n\
             *PQC Status:* {}\n\
             *Category:* {}\n\
             *Location:* {}\n\n\
             h3. Description\n{}\n\n\
             h3. Remediation\n{}\n\n\
             ----\n\
             _Created by QuantaWatch Cryptographic Posture Management_",
            finding.title,
            finding.severity,
            finding.pqc_status,
            finding.category,
            finding.asset.location.path,
            finding.description,
            remediation_text,
        );

        let mut labels = opts.labels.clone();
        labels.push(format!("pqc-{}", finding.pqc_status));

        let issue_body = serde_json::json!({
            "fields": {
                "project": { "key": project },
                "summary": format!("[PQC] {}", finding.title),
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": description
                        }]
                    }]
                },
                "issuetype": { "name": "Task" },
                "priority": { "name": priority },
                "labels": labels,
            }
        });

        let resp = self.client.post(format!("{}/rest/api/3/issue", self.base_url))
            .basic_auth(&self.email, Some(&self.token))
            .header("Content-Type", "application/json")
            .json(&issue_body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IntegrationError::ApiError(
                format!("Failed to create issue: {body}"),
            ));
        }

        let result: serde_json::Value = resp.json().await
            .map_err(|e| IntegrationError::ApiError(e.to_string()))?;

        let issue_key = result["key"].as_str().unwrap_or_default().to_string();

        Ok(RemediationTicket {
            id: uuid::Uuid::new_v4().to_string(),
            integration_id: self.id.clone(),
            external_id: issue_key.clone(),
            external_url: format!("{}/browse/{}", self.base_url, issue_key),
            status: TicketStatus::Open,
            finding_id: finding.id.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_to_priority() {
        assert_eq!(JiraIntegration::severity_to_priority(&FindingSeverity::Critical), "Highest");
        assert_eq!(JiraIntegration::severity_to_priority(&FindingSeverity::High), "High");
        assert_eq!(JiraIntegration::severity_to_priority(&FindingSeverity::Medium), "Medium");
        assert_eq!(JiraIntegration::severity_to_priority(&FindingSeverity::Low), "Low");
        assert_eq!(JiraIntegration::severity_to_priority(&FindingSeverity::Info), "Lowest");
    }
}
