use crate::registry::{Integration, IntegrationError};
use crate::types::*;
use async_trait::async_trait;
use qw_scanner::{Finding, ScanTarget, TargetType};

pub struct GitLabIntegration {
    id: String,
    token: String,
    base_url: String,
    group: Option<String>,
    client: reqwest::Client,
}

impl GitLabIntegration {
    pub fn from_config(config: &IntegrationConfig) -> Option<Self> {
        let token = config
            .token
            .clone()
            .or_else(|| std::env::var(&config.api_token_env).ok())?;
        Some(Self {
            id: config.id.clone(),
            token,
            base_url: config
                .base_url
                .clone()
                .unwrap_or_else(|| "https://gitlab.com/api/v4".to_string()),
            group: config.settings.get("group").cloned(),
            client: reqwest::Client::new(),
        })
    }
}

#[async_trait]
impl Integration for GitLabIntegration {
    fn id(&self) -> &str {
        &self.id
    }
    fn display_name(&self) -> &str {
        "GitLab"
    }

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        vec![IntegrationCapability::DiscoverTargets]
    }

    async fn test_connection(&self) -> Result<ConnectionStatus, IntegrationError> {
        let resp = self
            .client
            .get(format!("{}/user", self.base_url))
            .header("PRIVATE-TOKEN", &self.token)
            .header("User-Agent", "QuantaWatch")
            .send()
            .await?;

        if resp.status().is_success() {
            let user: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| IntegrationError::ApiError(e.to_string()))?;
            Ok(ConnectionStatus {
                connected: true,
                user: user["username"].as_str().map(String::from),
                scopes: vec!["api".to_string()],
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
        let mut targets = Vec::new();
        let dep_files = [
            "Cargo.toml",
            "package.json",
            "requirements.txt",
            "go.mod",
            "Gemfile",
        ];

        let projects_url = if let Some(ref group) = self.group {
            format!(
                "{}/groups/{}/projects?per_page=100",
                self.base_url,
                urlencoded(group)
            )
        } else {
            format!("{}/projects?membership=true&per_page=100", self.base_url)
        };

        let resp = self
            .client
            .get(&projects_url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("User-Agent", "QuantaWatch")
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(IntegrationError::ApiError(format!(
                "Failed to list projects: HTTP {}",
                resp.status()
            )));
        }

        let projects: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| IntegrationError::ApiError(e.to_string()))?;

        for project in &projects {
            let id = project["id"].as_u64().unwrap_or_default();
            let path = project["path_with_namespace"].as_str().unwrap_or_default();
            let default_branch = project["default_branch"].as_str().unwrap_or("main");

            for dep_file in &dep_files {
                let file_url = format!(
                    "{}/projects/{}/repository/files/{}?ref={}",
                    self.base_url,
                    id,
                    urlencoded(dep_file),
                    default_branch
                );

                let check = self
                    .client
                    .head(&file_url)
                    .header("PRIVATE-TOKEN", &self.token)
                    .header("User-Agent", "QuantaWatch")
                    .send()
                    .await;

                if let Ok(resp) = check {
                    if resp.status().is_success() {
                        let mut metadata = std::collections::HashMap::new();
                        metadata.insert("project".to_string(), path.to_string());
                        metadata.insert("project_id".to_string(), id.to_string());
                        metadata.insert("branch".to_string(), default_branch.to_string());
                        metadata.insert("integration".to_string(), self.id.clone());

                        targets.push(ScanTarget {
                            id: uuid::Uuid::new_v4().to_string(),
                            target_type: TargetType::DependencyFile,
                            address: format!("{}/{}", path, dep_file),
                            metadata,
                        });
                    }
                }
            }
        }

        Ok(targets)
    }

    async fn create_remediation(
        &self,
        _finding: &Finding,
        _opts: &RemediationOpts,
    ) -> Result<RemediationTicket, IntegrationError> {
        Err(IntegrationError::NotSupported(
            "GitLab integration does not support remediation tickets. Use Jira or Linear."
                .to_string(),
        ))
    }

    async fn fetch_content(&self, target: &ScanTarget) -> Result<Option<String>, IntegrationError> {
        let project_id = target.metadata.get("project_id").ok_or_else(|| {
            IntegrationError::NotConfigured("target missing project_id metadata".to_string())
        })?;
        let branch = target
            .metadata
            .get("branch")
            .map(String::as_str)
            .unwrap_or("main");
        let filename = target.address.rsplit('/').next().unwrap_or(&target.address);

        let url = format!(
            "{}/projects/{}/repository/files/{}/raw?ref={}",
            self.base_url,
            project_id,
            urlencoded(filename),
            branch,
        );

        let resp = self
            .client
            .get(&url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("User-Agent", "QuantaWatch")
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(IntegrationError::ApiError(format!(
                "Failed to fetch content: HTTP {}",
                resp.status()
            )));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| IntegrationError::ApiError(e.to_string()))?;
        Ok(Some(body))
    }
}

fn urlencoded(s: &str) -> String {
    s.replace('/', "%2F")
}
