use crate::types::*;
use async_trait::async_trait;
use qw_scanner::{Finding, ScanTarget};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Not configured: {0}")]
    NotConfigured(String),
    #[error("Capability not supported: {0}")]
    NotSupported(String),
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

#[async_trait]
pub trait Integration: Send + Sync + 'static {
    fn id(&self) -> &str;
    fn display_name(&self) -> &str;
    fn capabilities(&self) -> Vec<IntegrationCapability>;
    async fn test_connection(&self) -> Result<ConnectionStatus, IntegrationError>;
    async fn discover_targets(&self) -> Result<Vec<ScanTarget>, IntegrationError>;
    async fn create_remediation(
        &self,
        finding: &Finding,
        opts: &RemediationOpts,
    ) -> Result<RemediationTicket, IntegrationError>;

    /// Fetch the raw content of a discovered target (e.g. a remote dependency
    /// file) so it can be scanned inline. Defaults to `None` for integrations
    /// that do not expose file content.
    async fn fetch_content(
        &self,
        _target: &ScanTarget,
    ) -> Result<Option<String>, IntegrationError> {
        Ok(None)
    }

    /// Fetch the current status of a previously-created remediation
    /// (ticket/PR) by its external id, to reconcile the closed-loop state.
    async fn remediation_status(
        &self,
        _external_id: &str,
    ) -> Result<TicketStatus, IntegrationError> {
        Ok(TicketStatus::Unknown)
    }

    /// Register an inbound webhook with the provider so it pushes status
    /// changes to `callback_url` (signed with `secret`). Returns a description.
    async fn register_webhook(
        &self,
        _callback_url: &str,
        _secret: &str,
    ) -> Result<String, IntegrationError> {
        Err(IntegrationError::NotSupported(
            "webhook registration not supported".to_string(),
        ))
    }
}

pub struct IntegrationRegistry {
    integrations: HashMap<String, Box<dyn Integration>>,
}

impl Default for IntegrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrationRegistry {
    pub fn new() -> Self {
        Self {
            integrations: HashMap::new(),
        }
    }

    pub fn register(&mut self, integration: Box<dyn Integration>) {
        self.integrations
            .insert(integration.id().to_string(), integration);
    }

    pub fn get(&self, id: &str) -> Option<&dyn Integration> {
        self.integrations.get(id).map(|i| i.as_ref())
    }

    pub fn list(&self) -> Vec<IntegrationInfo> {
        self.integrations
            .values()
            .map(|i| IntegrationInfo {
                id: i.id().to_string(),
                integration_type: i.id().split('-').next().unwrap_or(i.id()).to_string(),
                display_name: i.display_name().to_string(),
                capabilities: i.capabilities(),
                status: ConnectionStatus {
                    connected: false,
                    user: None,
                    scopes: vec![],
                    error: None,
                },
            })
            .collect()
    }
}

/// Construct a single integration from its config (used both at startup and for
/// UI-managed connections built on demand from a stored secret).
pub fn build_one(config: &IntegrationConfig) -> Option<Box<dyn Integration>> {
    match config.integration_type.as_str() {
        "github" => crate::github::GitHubIntegration::from_config(config)
            .map(|i| Box::new(i) as Box<dyn Integration>),
        "gitlab" => crate::gitlab::GitLabIntegration::from_config(config)
            .map(|i| Box::new(i) as Box<dyn Integration>),
        "jira" => crate::jira::JiraIntegration::from_config(config)
            .map(|i| Box::new(i) as Box<dyn Integration>),
        "linear" => crate::linear::LinearIntegration::from_config(config)
            .map(|i| Box::new(i) as Box<dyn Integration>),
        other => {
            tracing::warn!(integration_type = other, "Unknown integration type, skipping");
            None
        }
    }
}

pub fn build_integration_registry(configs: &[IntegrationConfig]) -> IntegrationRegistry {
    let mut registry = IntegrationRegistry::new();
    for config in configs {
        if let Some(integration) = build_one(config) {
            registry.register(integration);
        }
    }
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new_is_empty() {
        let registry = IntegrationRegistry::new();
        assert!(registry.list().is_empty());
    }

    #[test]
    fn test_registry_get_nonexistent() {
        let registry = IntegrationRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }
}
