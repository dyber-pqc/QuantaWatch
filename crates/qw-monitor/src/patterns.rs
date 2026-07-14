use crate::types::{Severity, ThreatCategory};
use regex::Regex;

pub struct PatternRule {
    pub name: &'static str,
    pub regex: Regex,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub description: &'static str,
    pub confidence: f64,
}

/// Build the default prompt injection pattern library.
pub fn injection_patterns() -> Vec<PatternRule> {
    vec![
        PatternRule {
            name: "ignore_instructions",
            regex: Regex::new(r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)").unwrap(),
            category: ThreatCategory::PromptInjection,
            severity: Severity::High,
            description: "Attempt to override system instructions",
            confidence: 0.9,
        },
        PatternRule {
            name: "you_are_now",
            regex: Regex::new(r"(?i)you\s+are\s+now\s+(a|an|the)\s+").unwrap(),
            category: ThreatCategory::PromptInjection,
            severity: Severity::High,
            description: "Role reassignment attempt",
            confidence: 0.8,
        },
        PatternRule {
            name: "system_prompt_override",
            regex: Regex::new(r"(?i)(system\s*prompt|system\s*message|system\s*instruction)\s*[:=]").unwrap(),
            category: ThreatCategory::PromptInjection,
            severity: Severity::Critical,
            description: "System prompt injection",
            confidence: 0.95,
        },
        PatternRule {
            name: "delimiter_injection",
            regex: Regex::new(r"(?i)(---+|####+|</?(system)>)").unwrap(),
            category: ThreatCategory::PromptInjection,
            severity: Severity::Medium,
            description: "Delimiter-based prompt injection",
            confidence: 0.7,
        },
        PatternRule {
            name: "jailbreak_dan",
            regex: Regex::new(r"(?i)(DAN|do\s+anything\s+now|jailbreak|bypass\s+(safety|filter|restriction)|developer\s+mode)").unwrap(),
            category: ThreatCategory::JailbreakAttempt,
            severity: Severity::High,
            description: "Jailbreak attempt (DAN-style)",
            confidence: 0.85,
        },
        PatternRule {
            name: "system_prompt_extraction",
            regex: Regex::new(r"(?i)(repeat|show|print|display|reveal|output|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules|initial\s+message)").unwrap(),
            category: ThreatCategory::SystemPromptExtraction,
            severity: Severity::Medium,
            description: "System prompt extraction attempt",
            confidence: 0.75,
        },
        PatternRule {
            name: "instruction_boundary",
            regex: Regex::new(r"(?i)(end\s+of\s+(system|initial)\s+(prompt|instructions|message)|begin\s+new\s+(instructions|session|conversation))").unwrap(),
            category: ThreatCategory::PromptInjection,
            severity: Severity::High,
            description: "Instruction boundary manipulation",
            confidence: 0.85,
        },
        PatternRule {
            name: "forget_instructions",
            regex: Regex::new(r"(?i)(forget|disregard|discard|abandon|override)\s+(everything|all|your|the|any)\s+(previous|prior|above|earlier|original)?\s*(instructions|rules|guidelines|prompts|context)").unwrap(),
            category: ThreatCategory::PromptInjection,
            severity: Severity::High,
            description: "Instruction override attempt",
            confidence: 0.9,
        },
    ]
}

/// Build the default data exfiltration pattern library.
pub fn exfiltration_patterns() -> Vec<PatternRule> {
    vec![
        PatternRule {
            name: "base64_block",
            regex: Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}").unwrap(),
            category: ThreatCategory::DataExfiltration,
            severity: Severity::Medium,
            description: "Large base64-encoded block in output",
            confidence: 0.6,
        },
        PatternRule {
            name: "api_key_pattern",
            regex: Regex::new(r"(?i)sk-[a-zA-Z0-9]{20,}").unwrap(),
            category: ThreatCategory::DataExfiltration,
            severity: Severity::Critical,
            description: "Potential API key in output",
            confidence: 0.9,
        },
        PatternRule {
            name: "dangerous_command_rm",
            regex: Regex::new(r"(?i)rm\s+-rf\s+(/|~|/var|/etc|/usr)").unwrap(),
            category: ThreatCategory::DangerousOutput,
            severity: Severity::Critical,
            description: "Destructive shell command in output",
            confidence: 0.95,
        },
        PatternRule {
            name: "dangerous_sql",
            regex: Regex::new(r"(?i)(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)").unwrap(),
            category: ThreatCategory::DangerousOutput,
            severity: Severity::High,
            description: "Destructive SQL command in output",
            confidence: 0.85,
        },
    ]
}

/// Build the default PII detection pattern library.
pub fn pii_patterns() -> Vec<PatternRule> {
    vec![
        PatternRule {
            name: "ssn",
            regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            category: ThreatCategory::PiiExposure,
            severity: Severity::Critical,
            description: "Social Security Number detected",
            confidence: 0.9,
        },
        PatternRule {
            name: "credit_card",
            regex: Regex::new(r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}").unwrap(),
            category: ThreatCategory::PiiExposure,
            severity: Severity::Critical,
            description: "Credit card number detected",
            confidence: 0.85,
        },
        PatternRule {
            name: "email",
            regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
            category: ThreatCategory::PiiExposure,
            severity: Severity::Low,
            description: "Email address detected",
            confidence: 0.8,
        },
        PatternRule {
            name: "phone_us",
            regex: Regex::new(r"\d{3}[-.\s]?\d{3}[-.\s]?\d{4}").unwrap(),
            category: ThreatCategory::PiiExposure,
            severity: Severity::Medium,
            description: "US phone number detected",
            confidence: 0.7,
        },
    ]
}
