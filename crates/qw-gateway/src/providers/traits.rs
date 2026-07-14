use bytes::Bytes;
use serde::{Serialize, Deserialize};

/// Normalized representation of an LLM request for policy/monitor inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedRequest {
    pub model: String,
    pub system_prompt: Option<String>,
    pub messages: Vec<NormalizedMessage>,
    pub tools: Vec<ToolDefinition>,
    pub max_tokens: Option<u32>,
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
}

/// Trait that every LLM provider adapter must implement.
pub trait LlmProvider: Send + Sync + 'static {
    /// Provider name (e.g., "anthropic", "openai", "ollama").
    fn name(&self) -> &str;

    /// The upstream base URL.
    fn upstream_url(&self) -> &str;

    /// Parse a raw request body into a NormalizedRequest for inspection.
    fn parse_request(&self, body: &Bytes) -> Option<NormalizedRequest>;

    /// Extract text content from a response body for monitoring.
    fn extract_response_text(&self, body: &Bytes) -> Option<String>;

    /// Extract tool use calls from response body.
    fn extract_tool_calls(&self, body: &Bytes) -> Vec<String>;

    /// Build the upstream URL for a given request path.
    fn build_upstream_url(&self, path: &str) -> String;

    /// Get the API key header name and value, if applicable.
    fn api_key_header(&self) -> Option<(&str, String)>;
}
