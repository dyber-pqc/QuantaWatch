use crate::types::*;
use crate::PolicyError;

/// The policy engine evaluates requests against loaded policies.
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    /// Create a new policy engine from a config.
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// Load from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let config = crate::yaml_parser::parse_policy(yaml)?;
        Ok(Self::new(config))
    }

    /// Load from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let config = crate::yaml_parser::load_policy(path)?;
        Ok(Self::new(config))
    }

    /// Evaluate a request against the policy.
    pub fn evaluate(&self, ctx: &RequestContext) -> PolicyDecision {
        // Look up agent policy
        let agent_policy = match self.config.agents.get(&ctx.agent_name) {
            Some(p) => p,
            None => {
                return match self.config.default {
                    DefaultEffect::Allow => PolicyDecision::allow("no agent policy, default allow"),
                    DefaultEffect::Deny => PolicyDecision::deny(
                        format!("no policy defined for agent '{}'", ctx.agent_name)
                    ),
                };
            }
        };

        // Check model access
        if !agent_policy.allowed_models.is_empty() {
            let model_allowed = agent_policy.allowed_models.iter().any(|pattern| {
                matches_glob(pattern, &ctx.model)
            });
            if !model_allowed {
                return PolicyDecision::deny(
                    format!("model '{}' not allowed for agent '{}'", ctx.model, ctx.agent_name)
                );
            }
        }

        // Check tool access
        let mut tools_allowed = Vec::new();
        let mut tools_denied = Vec::new();

        for tool in &ctx.tools_requested {
            // Check blocked list first (deny overrides)
            if agent_policy.blocked_tools.iter().any(|p| matches_glob(p, tool)) {
                tools_denied.push(tool.clone());
                continue;
            }

            // Check allowed list
            if agent_policy.allowed_tools.is_empty()
                || agent_policy.allowed_tools.iter().any(|p| matches_glob(p, tool))
            {
                tools_allowed.push(tool.clone());
            } else {
                tools_denied.push(tool.clone());
            }
        }

        if !tools_denied.is_empty() && tools_allowed.is_empty() {
            return PolicyDecision {
                effect: Effect::Deny,
                reason: format!("all requested tools denied for agent '{}'", ctx.agent_name),
                tools_allowed,
                tools_denied,
            };
        }

        // Check offline mode
        if agent_policy.offline && is_cloud_provider(&ctx.provider) {
            return PolicyDecision::deny(
                format!("agent '{}' is offline-only, cannot use cloud provider '{}'", ctx.agent_name, ctx.provider)
            );
        }

        // Partial allow (some tools denied)
        if !tools_denied.is_empty() {
            return PolicyDecision {
                effect: Effect::Allow,
                reason: format!("partial allow: some tools denied for agent '{}'", ctx.agent_name),
                tools_allowed,
                tools_denied,
            };
        }

        PolicyDecision {
            effect: Effect::Allow,
            reason: format!("all checks passed for agent '{}'", ctx.agent_name),
            tools_allowed,
            tools_denied,
        }
    }

    /// Get the agent policy for a given name.
    pub fn get_agent_policy(&self, agent_name: &str) -> Option<&AgentPolicy> {
        self.config.agents.get(agent_name)
    }

    /// Get all agent names.
    pub fn agent_names(&self) -> Vec<String> {
        self.config.agents.keys().cloned().collect()
    }

    /// Get the full config.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }
}

/// Simple glob matching: supports `*` as wildcard.
fn matches_glob(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let (prefix, suffix) = (parts[0], parts[1]);
            return value.starts_with(prefix) && value.ends_with(suffix);
        }
    }
    pattern == value
}

fn is_cloud_provider(provider: &str) -> bool {
    matches!(provider, "anthropic" | "openai" | "bedrock" | "gemini" | "deepseek-cloud")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_ctx(agent: &str, model: &str, provider: &str, tools: Vec<&str>) -> RequestContext {
        RequestContext {
            agent_name: agent.to_string(),
            session_id: "test-session".to_string(),
            model: model.to_string(),
            provider: provider.to_string(),
            tools_requested: tools.into_iter().map(String::from).collect(),
            client_ip: "127.0.0.1".to_string(),
            labels: HashMap::new(),
        }
    }

    #[test]
    fn test_allow_matching_model() {
        let engine = PolicyEngine::from_yaml(r#"
agents:
  bot:
    allowed_models: ["claude-sonnet"]
    allowed_tools: ["*"]
"#).unwrap();
        let ctx = make_ctx("bot", "claude-sonnet", "anthropic", vec![]);
        assert!(engine.evaluate(&ctx).is_allowed());
    }

    #[test]
    fn test_deny_wrong_model() {
        let engine = PolicyEngine::from_yaml(r#"
agents:
  bot:
    allowed_models: ["claude-sonnet"]
"#).unwrap();
        let ctx = make_ctx("bot", "gpt-4o", "openai", vec![]);
        assert!(!engine.evaluate(&ctx).is_allowed());
    }

    #[test]
    fn test_wildcard_model() {
        let engine = PolicyEngine::from_yaml(r#"
agents:
  bot:
    allowed_models: ["claude-*"]
"#).unwrap();
        let ctx = make_ctx("bot", "claude-sonnet-4-20250514", "anthropic", vec![]);
        assert!(engine.evaluate(&ctx).is_allowed());
    }

    #[test]
    fn test_blocked_tool() {
        let engine = PolicyEngine::from_yaml(r#"
agents:
  bot:
    allowed_models: ["*"]
    allowed_tools: ["*"]
    blocked_tools: ["email_send"]
"#).unwrap();
        let ctx = make_ctx("bot", "claude-sonnet", "anthropic", vec!["web_search", "email_send"]);
        let decision = engine.evaluate(&ctx);
        assert!(decision.is_allowed()); // partial allow
        assert_eq!(decision.tools_denied, vec!["email_send"]);
        assert_eq!(decision.tools_allowed, vec!["web_search"]);
    }

    #[test]
    fn test_default_deny_unknown_agent() {
        let engine = PolicyEngine::from_yaml(r#"
default: deny
agents: {}
"#).unwrap();
        let ctx = make_ctx("unknown", "claude", "anthropic", vec![]);
        assert!(!engine.evaluate(&ctx).is_allowed());
    }

    #[test]
    fn test_offline_agent_blocks_cloud() {
        let engine = PolicyEngine::from_yaml(r#"
agents:
  local-bot:
    allowed_models: ["*"]
    offline: true
"#).unwrap();
        let ctx = make_ctx("local-bot", "claude", "anthropic", vec![]);
        assert!(!engine.evaluate(&ctx).is_allowed());

        let ctx_local = make_ctx("local-bot", "llama3", "ollama", vec![]);
        assert!(engine.evaluate(&ctx_local).is_allowed());
    }

    #[test]
    fn test_glob_matching() {
        assert!(matches_glob("*", "anything"));
        assert!(matches_glob("claude-*", "claude-sonnet"));
        assert!(matches_glob("claude-*", "claude-opus"));
        assert!(!matches_glob("claude-*", "gpt-4o"));
        assert!(matches_glob("exact", "exact"));
        assert!(!matches_glob("exact", "other"));
    }
}
