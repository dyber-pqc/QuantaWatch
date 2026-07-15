//! Azure OpenAI adapter.
//!
//! The request/response bodies are OpenAI-shaped (so parsing is delegated to
//! the OpenAI adapter), but Azure differs in two ways:
//!   * auth is an `api-key: <key>` header, not `Authorization: Bearer <key>`;
//!   * the model is addressed by *deployment* in the URL, e.g.
//!     `/openai/deployments/{deployment}/chat/completions?api-version=...`,
//!     which the caller supplies — we pass the path through to the configured
//!     resource endpoint.

use super::openai::OpenAiProvider;
use super::traits::*;
use bytes::Bytes;

pub struct AzureOpenAiProvider {
    upstream: String,
    api_key: Option<String>,
    /// Header name for the key; Azure uses `api-key`.
    key_header: String,
    inner: OpenAiProvider,
}

impl AzureOpenAiProvider {
    pub fn new(upstream: String, api_key: Option<String>, key_header: Option<String>) -> Self {
        Self {
            inner: OpenAiProvider::new(upstream.clone(), api_key.clone()),
            upstream,
            api_key,
            key_header: key_header.unwrap_or_else(|| "api-key".to_string()),
        }
    }
}

impl LlmProvider for AzureOpenAiProvider {
    fn name(&self) -> &str {
        "azure-openai"
    }

    fn upstream_url(&self) -> &str {
        &self.upstream
    }

    // Bodies are OpenAI-shaped — reuse that parsing entirely.
    fn parse_request(&self, body: &Bytes) -> Option<NormalizedRequest> {
        self.inner.parse_request(body)
    }

    fn extract_response_text(&self, body: &Bytes) -> Option<String> {
        self.inner.extract_response_text(body)
    }

    fn extract_tool_calls(&self, body: &Bytes) -> Vec<String> {
        self.inner.extract_tool_calls(body)
    }

    fn build_upstream_url(&self, path: &str) -> String {
        // Strip our routing prefix; the rest (deployment + api-version) is the
        // caller's Azure path and passes through untouched.
        let clean = path
            .strip_prefix("/azure-openai")
            .or_else(|| path.strip_prefix("/azure"))
            .unwrap_or(path);
        format!("{}{}", self.upstream, clean)
    }

    fn api_key_header(&self) -> Option<(&str, String)> {
        self.api_key
            .as_ref()
            .map(|key| (self.key_header.as_str(), key.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> AzureOpenAiProvider {
        AzureOpenAiProvider::new(
            "https://res.openai.azure.com".to_string(),
            Some("secret".to_string()),
            None,
        )
    }

    #[test]
    fn uses_api_key_header_not_bearer() {
        let p = provider();
        let (name, value) = p.api_key_header().unwrap();
        assert_eq!(name, "api-key");
        assert_eq!(value, "secret", "Azure takes the raw key, not 'Bearer ...'");
    }

    #[test]
    fn passes_deployment_path_through() {
        let p = provider();
        let path = "/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01";
        assert_eq!(
            p.build_upstream_url(path),
            format!("https://res.openai.azure.com{path}")
        );
    }

    #[test]
    fn strips_routing_prefix() {
        let p = provider();
        assert_eq!(
            p.build_upstream_url("/azure/openai/deployments/d/chat/completions"),
            "https://res.openai.azure.com/openai/deployments/d/chat/completions"
        );
    }

    #[test]
    fn parses_openai_shaped_body() {
        let body = Bytes::from(
            r#"{"model":"gpt-4o","messages":[{"role":"system","content":"be nice"},{"role":"user","content":"hi"}]}"#,
        );
        let req = provider().parse_request(&body).unwrap();
        assert_eq!(req.model, "gpt-4o");
        assert_eq!(req.system_prompt.as_deref(), Some("be nice"));
        assert_eq!(req.messages.len(), 2);
    }
}
