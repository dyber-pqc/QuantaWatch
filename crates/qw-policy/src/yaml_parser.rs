use crate::types::PolicyConfig;
use crate::PolicyError;
use std::path::Path;

/// Load a policy configuration from a YAML file.
pub fn load_policy(path: &Path) -> Result<PolicyConfig, PolicyError> {
    let content = std::fs::read_to_string(path)?;
    let config: PolicyConfig = serde_yaml::from_str(&content)?;
    validate_policy(&config)?;
    Ok(config)
}

/// Load policy from a YAML string.
pub fn parse_policy(yaml: &str) -> Result<PolicyConfig, PolicyError> {
    let config: PolicyConfig = serde_yaml::from_str(yaml)?;
    validate_policy(&config)?;
    Ok(config)
}

fn validate_policy(config: &PolicyConfig) -> Result<(), PolicyError> {
    for (name, agent) in &config.agents {
        // Validate that allowed_models is not empty (unless it's a wildcard)
        if agent.allowed_models.is_empty() && !agent.allowed_tools.contains(&"*".to_string()) {
            tracing::warn!(agent = %name, "agent has no allowed_models defined");
        }

        // Validate no overlap between allowed and blocked tools
        for tool in &agent.allowed_tools {
            if agent.blocked_tools.contains(tool) && tool != "*" {
                return Err(PolicyError::InvalidPolicy(format!(
                    "agent '{name}': tool '{tool}' is both allowed and blocked"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_policy() {
        let yaml = r#"
version: "1"
default: deny
agents:
  support-bot:
    description: "Customer support agent"
    allowed_models:
      - claude-sonnet
      - gpt-4o
    allowed_tools:
      - web_search
    blocked_tools:
      - code_execution
"#;
        let config = parse_policy(yaml).unwrap();
        assert_eq!(config.agents.len(), 1);
        let bot = &config.agents["support-bot"];
        assert_eq!(bot.allowed_models.len(), 2);
        assert_eq!(bot.blocked_tools, vec!["code_execution"]);
    }

    #[test]
    fn test_parse_empty_policy() {
        let yaml = r#"
agents: {}
"#;
        let config = parse_policy(yaml).unwrap();
        assert!(config.agents.is_empty());
    }

    #[test]
    fn test_conflicting_tools_rejected() {
        let yaml = r#"
agents:
  bad-agent:
    allowed_tools:
      - web_search
    blocked_tools:
      - web_search
"#;
        let result = parse_policy(yaml);
        assert!(result.is_err());
    }
}
