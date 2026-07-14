use crate::patterns::{exfiltration_patterns, PatternRule};
use crate::types::DetectedThreat;

pub struct ExfiltrationDetector {
    patterns: Vec<PatternRule>,
}

impl Default for ExfiltrationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExfiltrationDetector {
    pub fn new() -> Self {
        Self {
            patterns: exfiltration_patterns(),
        }
    }

    /// Scan response text for data exfiltration patterns.
    pub fn scan(&self, text: &str) -> Vec<DetectedThreat> {
        let mut threats = Vec::new();

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(text) {
                threats.push(DetectedThreat {
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.to_string(),
                    description: pattern.description.to_string(),
                    matched_text: truncate_match(m.as_str(), 100),
                    severity: pattern.severity.clone(),
                    confidence: pattern.confidence,
                });
            }
        }

        threats
    }
}

fn truncate_match(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ThreatCategory;

    #[test]
    fn test_api_key_detection() {
        let detector = ExfiltrationDetector::new();
        let threats = detector.scan("Here's your key: sk-1234567890abcdefghijklmnop");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == ThreatCategory::DataExfiltration));
    }

    #[test]
    fn test_dangerous_rm_command() {
        let detector = ExfiltrationDetector::new();
        let threats = detector.scan("Run this command: rm -rf /var/data");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == ThreatCategory::DangerousOutput));
    }

    #[test]
    fn test_dangerous_sql() {
        let detector = ExfiltrationDetector::new();
        let threats = detector.scan("Execute: DROP TABLE users;");
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_response() {
        let detector = ExfiltrationDetector::new();
        let threats = detector.scan("The weather in San Francisco is sunny and 72 degrees.");
        assert!(threats.is_empty());
    }
}
