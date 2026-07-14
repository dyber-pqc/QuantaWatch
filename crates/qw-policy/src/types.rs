use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// A complete policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub default: DefaultEffect,
    #[serde(default)]
    pub agents: HashMap<String, AgentPolicy>,
}

fn default_version() -> String {
    "1".to_string()
}

/// Default policy effect when no rules match.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultEffect {
    Allow,
    #[default]
    Deny,
}

/// Policy for a specific agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub blocked_tools: Vec<String>,
    #[serde(default)]
    pub blocked_actions: Vec<String>,
    #[serde(default)]
    pub data_policy: Option<String>,
    #[serde(default)]
    pub max_tokens_per_session: Option<u64>,
    #[serde(default)]
    pub max_requests_per_minute: Option<u32>,
    #[serde(default)]
    pub offline: bool,
}

/// Context extracted from a request for policy evaluation.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub agent_name: String,
    pub session_id: String,
    pub model: String,
    pub provider: String,
    pub tools_requested: Vec<String>,
    pub client_ip: String,
    pub labels: HashMap<String, String>,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub reason: String,
    pub tools_allowed: Vec<String>,
    pub tools_denied: Vec<String>,
}

/// Allow or deny effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

impl PolicyDecision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            effect: Effect::Allow,
            reason: reason.into(),
            tools_allowed: vec![],
            tools_denied: vec![],
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            effect: Effect::Deny,
            reason: reason.into(),
            tools_allowed: vec![],
            tools_denied: vec![],
        }
    }

    pub fn is_allowed(&self) -> bool {
        self.effect == Effect::Allow
    }
}
