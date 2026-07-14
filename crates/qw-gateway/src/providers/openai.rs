use bytes::Bytes;
use super::traits::*;

pub struct OpenAiProvider {
    upstream: String,
    api_key: Option<String>,
}

impl OpenAiProvider {
    pub fn new(upstream: String, api_key: Option<String>) -> Self {
        Self { upstream, api_key }
    }
}

impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &str { "openai" }

    fn upstream_url(&self) -> &str { &self.upstream }

    fn parse_request(&self, body: &Bytes) -> Option<NormalizedRequest> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;

        let model = json.get("model")?.as_str()?.to_string();
        let max_tokens = json.get("max_tokens").and_then(|t| t.as_u64()).map(|t| t as u32);
        let stream = json.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

        let mut system_prompt = None;
        let mut messages = Vec::new();

        if let Some(arr) = json.get("messages").and_then(|m| m.as_array()) {
            for msg in arr {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();

                if role == "system" {
                    system_prompt = Some(content.clone());
                }
                messages.push(NormalizedMessage {
                    role: role.to_string(),
                    content,
                });
            }
        }

        let tools = json.get("tools")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter().filter_map(|tool| {
                    let name = tool.get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())?
                        .to_string();
                    Some(ToolDefinition { name })
                }).collect()
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
        let choices = json.get("choices")?.as_array()?;
        let texts: Vec<String> = choices.iter()
            .filter_map(|choice| {
                choice.get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                    .map(String::from)
            })
            .collect();
        if texts.is_empty() { None } else { Some(texts.join("\n")) }
    }

    fn extract_tool_calls(&self, body: &Bytes) -> Vec<String> {
        let json: serde_json::Value = match serde_json::from_slice(body) {
            Ok(j) => j,
            Err(_) => return vec![],
        };
        json.get("choices")
            .and_then(|c| c.as_array())
            .map(|choices| {
                choices.iter()
                    .filter_map(|choice| {
                        choice.get("message")
                            .and_then(|m| m.get("tool_calls"))
                            .and_then(|tc| tc.as_array())
                    })
                    .flatten()
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
        let clean_path = if path.starts_with("/openai") {
            path.trim_start_matches("/openai")
        } else {
            path
        };
        format!("{}{}", self.upstream, clean_path)
    }

    fn api_key_header(&self) -> Option<(&str, String)> {
        self.api_key.as_ref().map(|key| ("Authorization", format!("Bearer {key}")))
    }
}
