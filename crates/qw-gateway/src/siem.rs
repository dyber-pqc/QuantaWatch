//! SIEM export — render the signed audit log for Splunk / Elastic / ArcSight.
//!
//! Deliberately **pull-based**: the SIEM scrapes an endpoint rather than the
//! gateway pushing events out. That keeps the integration working in
//! air-gapped deployments (no egress from the gateway at all) and means a SIEM
//! outage can never block or back-pressure the in-path proxy.
//!
//! Two formats:
//! * `jsonl` — one flat JSON object per line, ECS-flavoured field names
//!   (Elastic, Splunk HEC, Datadog).
//! * `cef`   — ArcSight Common Event Format (QRadar, ArcSight, Splunk CIM).

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemFormat {
    Jsonl,
    Cef,
}

impl SiemFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "jsonl" | "json" | "ecs" => Some(Self::Jsonl),
            "cef" => Some(Self::Cef),
            _ => None,
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            // No registered type for JSON Lines; this is the de-facto one.
            Self::Jsonl => "application/x-ndjson",
            Self::Cef => "text/plain; charset=utf-8",
        }
    }
}

/// CEF severity (0-10) for an audit event type.
fn cef_severity(event_type: &str) -> u8 {
    match event_type {
        "threat_blocked" => 8,
        "policy_violation" | "access_denied" | "crypto_policy_enforced" => 6,
        "finding_created" | "login_failed" => 5,
        "posture_changed" => 4,
        "scan_completed" | "integration_sync" | "admin_action" => 3,
        _ => 2, // session lifecycle, request processed, login/logout
    }
}

/// Human-readable event name.
fn event_name(event_type: &str) -> &str {
    match event_type {
        "session_created" => "Agent session created",
        "request_processed" => "LLM request proxied",
        "threat_blocked" => "Threat blocked",
        "policy_violation" => "Policy violation",
        "session_closed" => "Agent session closed",
        "scan_completed" => "Crypto scan completed",
        "finding_created" => "Crypto finding created",
        "posture_changed" => "Posture score changed",
        "integration_sync" => "Integration sync",
        "login_succeeded" => "Admin login succeeded",
        "login_failed" => "Admin login failed",
        "logout" => "Admin logout",
        "access_denied" => "Access denied (RBAC)",
        "admin_action" => "Admin action performed",
        "crypto_policy_enforced" => "In-path crypto enforcement",
        _ => "QuantaWatch event",
    }
}

/// Escape a CEF *header* field: `|` and `\` are structural.
fn cef_header_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape a CEF *extension* value: `=` and `\` are structural; newlines break
/// the one-event-per-line framing.
fn cef_extension_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

/// Flatten a JSON scalar to a string; skip nested objects (arrays are joined).
fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(a) => {
            let parts: Vec<String> = a.iter().filter_map(scalar_to_string).collect();
            Some(parts.join(","))
        }
        _ => None,
    }
}

/// Render one audit entry as a CEF line.
fn to_cef(entry: &Value, version: &str) -> String {
    let event = entry.get("event").cloned().unwrap_or(Value::Null);
    let event_type = event
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");

    // Extensions: standard CEF keys where they map cleanly, then the event's
    // own scalar fields as custom keys.
    let mut ext: Vec<String> = Vec::new();
    if let Some(ts) = entry.get("timestamp").and_then(|t| t.as_str()) {
        ext.push(format!("rt={}", cef_extension_escape(ts)));
    }
    if let Some(id) = entry.get("id").and_then(|t| t.as_str()) {
        ext.push(format!("externalId={}", cef_extension_escape(id)));
    }
    if let Some(seq) = entry.get("sequence") {
        ext.push(format!("cn1Label=Sequence cn1={seq}"));
    }
    if let Some(sid) = entry.get("session_id").and_then(|t| t.as_str()) {
        ext.push(format!(
            "cs1Label=SessionId cs1={}",
            cef_extension_escape(sid)
        ));
    }
    if let Some(hash) = entry.get("content_hash").and_then(|t| t.as_str()) {
        ext.push(format!(
            "cs2Label=ContentHash cs2={}",
            cef_extension_escape(hash)
        ));
    }
    if let Some(obj) = event.as_object() {
        for (k, v) in obj {
            if k == "type" {
                continue;
            }
            if let Some(s) = scalar_to_string(v) {
                ext.push(format!("{k}={}", cef_extension_escape(&s)));
            }
        }
    }

    format!(
        "CEF:0|Dyber|QuantaWatch|{}|{}|{}|{}|{}",
        cef_header_escape(version),
        cef_header_escape(event_type),
        cef_header_escape(event_name(event_type)),
        cef_severity(event_type),
        ext.join(" ")
    )
}

/// Render one audit entry as a flat ECS-flavoured JSON object.
///
/// `include_signatures` is off by default deliberately: an ML-DSA-65 signature
/// is ~3.3 KB (≈4.4 KB base64), which would dominate every event and blow up
/// ingest cost on volume-billed SIEMs. The chain-linkage hashes are always
/// included, and full verification belongs with `qw verify` against the raw
/// log — not the SIEM.
fn to_ecs(entry: &Value, include_signatures: bool) -> Value {
    let event = entry.get("event").cloned().unwrap_or(Value::Null);
    let event_type = event
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");

    let mut out = serde_json::Map::new();
    if let Some(ts) = entry.get("timestamp") {
        out.insert("@timestamp".into(), ts.clone());
    }
    out.insert("event.kind".into(), Value::from("event"));
    out.insert("event.module".into(), Value::from("quantawatch"));
    out.insert("event.dataset".into(), Value::from("quantawatch.audit"));
    out.insert("event.action".into(), Value::from(event_type));
    out.insert(
        "event.severity".into(),
        Value::from(cef_severity(event_type)),
    );
    if let Some(seq) = entry.get("sequence") {
        out.insert("event.sequence".into(), seq.clone());
    }
    if let Some(id) = entry.get("id") {
        out.insert("event.id".into(), id.clone());
    }
    // Chain-linkage fields — cheap, and what makes this log worth ingesting.
    for (src, dst) in [
        ("session_id", "quantawatch.session_id"),
        ("content_hash", "quantawatch.content_hash"),
        ("prev_hash", "quantawatch.prev_hash"),
        ("merkle_root", "quantawatch.merkle_root"),
    ] {
        if let Some(v) = entry.get(src) {
            out.insert(dst.into(), v.clone());
        }
    }
    // The full PQC signature is opt-in — see the note on this function.
    if include_signatures {
        if let Some(v) = entry.get("signature") {
            out.insert("quantawatch.signature".into(), v.clone());
        }
    } else if entry.get("signature").is_some() {
        out.insert("quantawatch.signed".into(), Value::Bool(true));
    }
    if let Some(obj) = event.as_object() {
        for (k, v) in obj {
            if k == "type" {
                continue;
            }
            out.insert(format!("quantawatch.{k}"), v.clone());
        }
    }
    Value::Object(out)
}

/// Render audit entries in the requested SIEM format (newline-delimited).
pub fn render(
    entries: &[Value],
    format: SiemFormat,
    version: &str,
    include_signatures: bool,
) -> String {
    let mut out = String::new();
    for entry in entries {
        match format {
            SiemFormat::Cef => out.push_str(&to_cef(entry, version)),
            SiemFormat::Jsonl => out.push_str(
                &serde_json::to_string(&to_ecs(entry, include_signatures)).unwrap_or_default(),
            ),
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn threat_entry() -> Value {
        json!({
            "id": "e-1",
            "timestamp": "2026-07-15T10:00:00Z",
            "sequence": 42,
            "session_id": "sess-abc",
            "event": {
                "type": "threat_blocked",
                "category": "prompt_injection",
                "severity": "high",
                "pattern": "system_override"
            },
            "prev_hash": "aaa",
            "content_hash": "bbb",
            "signature": "sig"
        })
    }

    #[test]
    fn cef_header_and_severity() {
        let line = render(&[threat_entry()], SiemFormat::Cef, "1.0.0", false);
        assert!(
            line.starts_with("CEF:0|Dyber|QuantaWatch|1.0.0|threat_blocked|Threat blocked|8|"),
            "got: {line}"
        );
        assert!(line.contains("cs1Label=SessionId cs1=sess-abc"));
        assert!(line.contains("cn1Label=Sequence cn1=42"));
        assert!(line.contains("category=prompt_injection"));
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn cef_escapes_structural_characters() {
        let mut e = threat_entry();
        e["event"]["pattern"] = json!("a=b\\c\nd");
        let line = render(&[e], SiemFormat::Cef, "1.0.0", false);
        // '=' and '\' escaped; the newline must not break one-event-per-line.
        assert!(line.contains(r"pattern=a\=b\\c d"), "got: {line}");
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn jsonl_maps_to_ecs_fields() {
        let out = render(&[threat_entry()], SiemFormat::Jsonl, "1.0.0", false);
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["@timestamp"], "2026-07-15T10:00:00Z");
        assert_eq!(v["event.action"], "threat_blocked");
        assert_eq!(v["event.module"], "quantawatch");
        assert_eq!(v["event.severity"], 8);
        assert_eq!(v["event.sequence"], 42);
        // Chain-integrity fields are what make this log worth ingesting.
        assert_eq!(v["quantawatch.content_hash"], "bbb");
        assert_eq!(
            v["quantawatch.signed"], true,
            "signature elided but flagged"
        );
        assert_eq!(v["quantawatch.category"], "prompt_injection");
    }

    #[test]
    fn signatures_are_elided_by_default_but_available_on_request() {
        // Default: no ~4.4KB signature blob (SIEMs bill by ingest volume), but
        // the event is still flagged as signed and chain-linked.
        let lean = render(&[threat_entry()], SiemFormat::Jsonl, "1.0.0", false);
        let v: Value = serde_json::from_str(lean.trim()).unwrap();
        assert!(v.get("quantawatch.signature").is_none());
        assert_eq!(v["quantawatch.signed"], true);
        assert_eq!(v["quantawatch.prev_hash"], "aaa");

        // Opt-in: full signature for anyone who wants to verify in the SIEM.
        let full = render(&[threat_entry()], SiemFormat::Jsonl, "1.0.0", true);
        let v: Value = serde_json::from_str(full.trim()).unwrap();
        assert_eq!(v["quantawatch.signature"], "sig");
        assert!(full.len() > lean.len());
    }

    #[test]
    fn jsonl_is_one_valid_object_per_line() {
        let out = render(
            &[threat_entry(), threat_entry()],
            SiemFormat::Jsonl,
            "1.0.0",
            false,
        );
        assert_eq!(out.lines().count(), 2);
        for line in out.lines() {
            serde_json::from_str::<Value>(line).expect("each line parses");
        }
    }

    #[test]
    fn arrays_are_flattened_for_cef() {
        let entry = json!({
            "id": "e-2", "timestamp": "2026-07-15T10:00:00Z", "sequence": 1, "session_id": "s",
            "event": { "type": "request_processed", "tools_denied": ["a", "b"], "latency_ms": 12 }
        });
        let line = render(&[entry], SiemFormat::Cef, "1.0.0", false);
        assert!(line.contains("tools_denied=a,b"), "got: {line}");
        assert!(line.contains("latency_ms=12"));
    }

    #[test]
    fn format_parsing_and_unknown_event_fallback() {
        assert_eq!(SiemFormat::parse("CEF"), Some(SiemFormat::Cef));
        assert_eq!(SiemFormat::parse("jsonl"), Some(SiemFormat::Jsonl));
        assert_eq!(SiemFormat::parse("ecs"), Some(SiemFormat::Jsonl));
        assert_eq!(SiemFormat::parse("syslog"), None);

        let entry = json!({"id":"x","timestamp":"t","sequence":0,"session_id":"s","event":{"type":"brand_new"}});
        let line = render(&[entry], SiemFormat::Cef, "1.0.0", false);
        assert!(
            line.contains("|brand_new|QuantaWatch event|2|"),
            "got: {line}"
        );
    }
}
