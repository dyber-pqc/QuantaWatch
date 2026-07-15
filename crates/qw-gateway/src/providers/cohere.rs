//! Cohere Chat API adapter (`POST /v1/chat`).
//!
//! Cohere's shape differs from OpenAI: the current turn is `message`, prior
//! turns are `chat_history` (`{role: USER|CHATBOT, message}`), the system
//! prompt is `preamble`, and tool calls come back as `tool_calls[].name`.

use super::traits::*;
use bytes::Bytes;

pub struct CohereProvider {
    upstream: String,
    api_key: Option<String>,
}

impl CohereProvider {
    pub fn new(upstream: String, api_key: Option<String>) -> Self {
        Self { upstream, api_key }
    }
}

impl LlmProvider for CohereProvider {
    fn name(&self) -> &str {
        "cohere"
    }

    fn upstream_url(&self) -> &str {
        &self.upstream
    }

    fn parse_request(&self, body: &Bytes) -> Option<NormalizedRequest> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;
        let model = json.get("model")?.as_str()?.to_string();
        let system_prompt = json
            .get("preamble")
            .and_then(|p| p.as_str())
            .map(String::from);
        let max_tokens = json
            .get("max_tokens")
            .and_then(|t| t.as_u64())
            .map(|t| t as u32);
        let stream = json
            .get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);

        let mut messages = Vec::new();
        // Prior turns.
        if let Some(hist) = json.get("chat_history").and_then(|h| h.as_array()) {
            for turn in hist {
                let role = match turn.get("role").and_then(|r| r.as_str()) {
                    Some("CHATBOT") => "assistant",
                    Some("SYSTEM") => "system",
                    _ => "user",
                };
                let content = turn
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                messages.push(NormalizedMessage {
                    role: role.to_string(),
                    content,
                });
            }
        }
        // The current turn.
        if let Some(msg) = json.get("message").and_then(|m| m.as_str()) {
            messages.push(NormalizedMessage {
                role: "user".to_string(),
                content: msg.to_string(),
            });
        }

        let tools = json
            .get("tools")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|tool| {
                        Some(ToolDefinition {
                            name: tool.get("name")?.as_str()?.to_string(),
                        })
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
        json.get("text").and_then(|t| t.as_str()).map(String::from)
    }

    fn extract_tool_calls(&self, body: &Bytes) -> Vec<String> {
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
            return vec![];
        };
        json.get("tool_calls")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|tc| tc.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn build_upstream_url(&self, path: &str) -> String {
        let clean = path.strip_prefix("/cohere").unwrap_or(path);
        format!("{}{}", self.upstream, clean)
    }

    fn api_key_header(&self) -> Option<(&str, String)> {
        self.api_key
            .as_ref()
            .map(|key| ("Authorization", format!("Bearer {key}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> CohereProvider {
        CohereProvider::new("https://api.cohere.com".to_string(), Some("k".to_string()))
    }

    #[test]
    fn parses_preamble_history_and_current_turn() {
        let body = Bytes::from(
            r#"{"model":"command-r-plus","preamble":"be terse","chat_history":[{"role":"USER","message":"hi"},{"role":"CHATBOT","message":"hello"}],"message":"and now?"}"#,
        );
        let req = provider().parse_request(&body).unwrap();
        assert_eq!(req.model, "command-r-plus");
        assert_eq!(req.system_prompt.as_deref(), Some("be terse"));
        assert_eq!(req.messages.len(), 3, "2 history turns + current message");
        assert_eq!(
            req.messages[1].role, "assistant",
            "CHATBOT maps to assistant"
        );
        assert_eq!(req.messages[2].content, "and now?");
    }

    #[test]
    fn extracts_response_text_and_tool_calls() {
        let body = Bytes::from(r#"{"text":"the answer","tool_calls":[{"name":"web_search"}]}"#);
        let p = provider();
        assert_eq!(
            p.extract_response_text(&body).as_deref(),
            Some("the answer")
        );
        assert_eq!(p.extract_tool_calls(&body), vec!["web_search".to_string()]);
    }

    #[test]
    fn builds_url_and_bearer_header() {
        let p = provider();
        assert_eq!(
            p.build_upstream_url("/v1/chat"),
            "https://api.cohere.com/v1/chat"
        );
        assert_eq!(
            p.build_upstream_url("/cohere/v1/chat"),
            "https://api.cohere.com/v1/chat"
        );
        let (n, v) = p.api_key_header().unwrap();
        assert_eq!(n, "Authorization");
        assert_eq!(v, "Bearer k");
    }
}
