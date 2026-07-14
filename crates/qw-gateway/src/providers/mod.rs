pub mod traits;
pub mod anthropic;
pub mod openai;
pub mod ollama;

use std::collections::HashMap;
use crate::config::GatewayConfig;
use traits::LlmProvider;

/// Registry of configured LLM providers.
pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn LlmProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, provider: Box<dyn LlmProvider>) {
        self.providers.insert(name.to_string(), provider);
    }

    pub fn get(&self, name: &str) -> Option<&dyn LlmProvider> {
        self.providers.get(name).map(|p| p.as_ref())
    }

    pub fn names(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    /// Resolve provider from a request path.
    pub fn resolve_from_path<'a>(&'a self, path: &'a str) -> Option<(&'a str, &'a dyn LlmProvider)> {
        // Check path-based routing
        if path.starts_with("/v1/messages") || path.starts_with("/claude") {
            if let Some(p) = self.providers.get("anthropic") {
                return Some(("anthropic", p.as_ref()));
            }
        }
        if path.starts_with("/v1/chat/completions") || path.starts_with("/openai") {
            if let Some(p) = self.providers.get("openai") {
                return Some(("openai", p.as_ref()));
            }
        }
        if path.starts_with("/api/chat") || path.starts_with("/api/generate") || path.starts_with("/ollama") {
            if let Some(p) = self.providers.get("ollama") {
                return Some(("ollama", p.as_ref()));
            }
        }

        // Check for provider-prefixed paths: /{provider}/...
        let parts: Vec<&str> = path.trim_start_matches('/').splitn(2, '/').collect();
        if parts.len() >= 1 {
            if let Some(p) = self.providers.get(parts[0]) {
                return Some((parts[0], p.as_ref()));
            }
        }

        None
    }
}

/// Build provider registry from config.
pub fn build_registry(config: &GatewayConfig) -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();

    for (name, provider_config) in &config.providers {
        let api_key = provider_config.api_key_env.as_ref()
            .and_then(|env| std::env::var(env).ok());

        match provider_config.protocol.as_str() {
            "anthropic" => {
                registry.register(name, Box::new(anthropic::AnthropicProvider::new(
                    provider_config.upstream.clone(),
                    api_key,
                )));
            }
            "openai" => {
                registry.register(name, Box::new(openai::OpenAiProvider::new(
                    provider_config.upstream.clone(),
                    api_key,
                )));
            }
            "ollama" => {
                registry.register(name, Box::new(ollama::OllamaProvider::new(
                    provider_config.upstream.clone(),
                )));
            }
            "openai-compat" => {
                // Use OpenAI adapter for any OpenAI-compatible endpoint
                registry.register(name, Box::new(openai::OpenAiProvider::new(
                    provider_config.upstream.clone(),
                    api_key,
                )));
            }
            _ => {
                tracing::warn!(name = %name, protocol = %provider_config.protocol, "Unknown protocol, skipping");
            }
        }
    }

    registry
}
