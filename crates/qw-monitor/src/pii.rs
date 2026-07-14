use crate::patterns::{pii_patterns, PatternRule};
use crate::types::DetectedThreat;

pub struct PiiDetector {
    patterns: Vec<PatternRule>,
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiDetector {
    pub fn new() -> Self {
        Self {
            patterns: pii_patterns(),
        }
    }

    /// Scan text for PII patterns.
    pub fn scan(&self, text: &str) -> Vec<DetectedThreat> {
        let mut threats = Vec::new();

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(text) {
                threats.push(DetectedThreat {
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.to_string(),
                    description: pattern.description.to_string(),
                    matched_text: redact_match(m.as_str()),
                    severity: pattern.severity.clone(),
                    confidence: pattern.confidence,
                });
            }
        }

        threats
    }
}

/// Redact the middle of a PII match for logging.
fn redact_match(s: &str) -> String {
    if s.len() <= 4 {
        "****".to_string()
    } else {
        let visible = 2;
        format!(
            "{}{}{}",
            &s[..visible],
            "*".repeat(s.len() - visible * 2),
            &s[s.len() - visible..]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ThreatCategory;

    #[test]
    fn test_ssn_detection() {
        let detector = PiiDetector::new();
        let threats = detector.scan("My SSN is 123-45-6789");
        assert!(!threats.is_empty());
        assert!(threats
            .iter()
            .any(|t| t.category == ThreatCategory::PiiExposure));
    }

    #[test]
    fn test_credit_card_detection() {
        let detector = PiiDetector::new();
        let threats = detector.scan("Card number: 4111 1111 1111 1111");
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_email_detection() {
        let detector = PiiDetector::new();
        let threats = detector.scan("Contact me at user@example.com");
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_no_pii() {
        let detector = PiiDetector::new();
        let threats = detector.scan("This is a normal message with no PII.");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_redaction() {
        let redacted = redact_match("123-45-6789");
        assert!(redacted.contains("*"));
        assert!(!redacted.contains("123-45-6789"));
    }
}
