use super::traits::*;
use bytes::Bytes;

pub struct OllamaProvider {
    upstream: String,
}

impl OllamaProvider {
    pub fn new(upstream: String) -> Self {
        Self { upstream }
    }
}

impl LlmProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn upstream_url(&self) -> &str {
        &self.upstream
    }

    fn parse_request(&self, body: &Bytes) -> Option<NormalizedRequest> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;

        let model = json.get("model")?.as_str()?.to_string();
        let stream = json.get("stream").and_then(|s| s.as_bool()).unwrap_or(true);
        let system_prompt = json
            .get("system")
            .and_then(|s| s.as_str())
            .map(String::from);

        let messages = json
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|msg| {
                        let role = msg.get("role")?.as_str()?.to_string();
                        let content = msg.get("content")?.as_str()?.to_string();
                        Some(NormalizedMessage { role, content })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let tools = json
            .get("tools")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|tool| {
                        let name = tool
                            .get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(|n| n.as_str())?
                            .to_string();
                        Some(ToolDefinition { name })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(NormalizedRequest {
            model,
            system_prompt,
            messages,
            tools,
            max_tokens: None,
            stream,
        })
    }

    fn extract_response_text(&self, body: &Bytes) -> Option<String> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;
        // Ollama chat response format
        json.get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(String::from)
    }

    fn extract_tool_calls(&self, body: &Bytes) -> Vec<String> {
        let json: serde_json::Value = match serde_json::from_slice(body) {
            Ok(j) => j,
            Err(_) => return vec![],
        };
        json.get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|tc| tc.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|tc| {
                        tc.get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(|n| n.as_str())
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn build_upstream_url(&self, path: &str) -> String {
        let clean_path = if path.starts_with("/ollama") {
            path.trim_start_matches("/ollama")
        } else {
            path
        };
        format!("{}{}", self.upstream, clean_path)
    }

    fn api_key_header(&self) -> Option<(&str, String)> {
        None
    }
}
