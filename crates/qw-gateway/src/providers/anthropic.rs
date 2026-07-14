use super::traits::*;
use bytes::Bytes;

pub struct AnthropicProvider {
    upstream: String,
    api_key: Option<String>,
}

impl AnthropicProvider {
    pub fn new(upstream: String, api_key: Option<String>) -> Self {
        Self { upstream, api_key }
    }
}

impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn upstream_url(&self) -> &str {
        &self.upstream
    }

    fn parse_request(&self, body: &Bytes) -> Option<NormalizedRequest> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;

        let model = json.get("model")?.as_str()?.to_string();
        let system_prompt = json
            .get("system")
            .and_then(|s| s.as_str())
            .map(String::from);
        let max_tokens = json
            .get("max_tokens")
            .and_then(|t| t.as_u64())
            .map(|t| t as u32);
        let stream = json
            .get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);

        let messages = json
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|msg| {
                        let role = msg.get("role")?.as_str()?.to_string();
                        let content = if let Some(s) = msg.get("content").and_then(|c| c.as_str()) {
                            s.to_string()
                        } else if let Some(arr) = msg.get("content").and_then(|c| c.as_array()) {
                            // Handle array content blocks
                            arr.iter()
                                .filter_map(|block| {
                                    if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                                        block.get("text").and_then(|t| t.as_str()).map(String::from)
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join("\n")
                        } else {
                            return None;
                        };
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
                        let name = tool.get("name")?.as_str()?.to_string();
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
            max_tokens,
            stream,
        })
    }

    fn extract_response_text(&self, body: &Bytes) -> Option<String> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;
        let content = json.get("content")?.as_array()?;
        let texts: Vec<String> = content
            .iter()
            .filter_map(|block| {
                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                    block.get("text").and_then(|t| t.as_str()).map(String::from)
                } else {
                    None
                }
            })
            .collect();
        if texts.is_empty() {
            None
        } else {
            Some(texts.join("\n"))
        }
    }

    fn extract_tool_calls(&self, body: &Bytes) -> Vec<String> {
        let json: serde_json::Value = match serde_json::from_slice(body) {
            Ok(j) => j,
            Err(_) => return vec![],
        };
        json.get("content")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|block| {
                        if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                            block.get("name").and_then(|n| n.as_str()).map(String::from)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn build_upstream_url(&self, path: &str) -> String {
        // Strip any provider prefix from the path
        let clean_path = if path.starts_with("/claude") {
            path.trim_start_matches("/claude")
        } else {
            path
        };
        format!("{}{}", self.upstream, clean_path)
    }

    fn api_key_header(&self) -> Option<(&str, String)> {
        self.api_key.as_ref().map(|key| ("x-api-key", key.clone()))
    }
}
