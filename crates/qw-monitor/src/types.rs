use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub threats: Vec<DetectedThreat>,
    pub severity: Severity,
    pub should_block: bool,
}

impl ThreatAssessment {
    pub fn clean() -> Self {
        Self {
            threats: vec![],
            severity: Severity::None,
            should_block: false,
        }
    }

    pub fn from_threats(threats: Vec<DetectedThreat>, blocking_threshold: &Severity) -> Self {
        if threats.is_empty() {
            return Self::clean();
        }

        let severity = threats.iter()
            .map(|t| &t.severity)
            .max()
            .cloned()
            .unwrap_or(Severity::None);

        let should_block = severity >= *blocking_threshold;

        Self { threats, severity, should_block }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedThreat {
    pub category: ThreatCategory,
    pub pattern_name: String,
    pub description: String,
    pub matched_text: String,
    pub severity: Severity,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    PromptInjection,
    SystemPromptExtraction,
    DataExfiltration,
    PiiExposure,
    JailbreakAttempt,
    DangerousOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}
