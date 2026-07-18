//! Business context for crypto findings.
//!
//! A quantum-vulnerable certificate on the checkout service is not the same
//! risk as the same certificate on a dev sandbox — but by algorithm severity
//! alone they look identical. This module attaches *business* meaning to a
//! finding (which application it serves, how critical that application is, who
//! owns it) and combines it with the migration urgency into a single business
//! risk score, so the work list is ordered by what actually matters to the
//! organization rather than by cipher name.

use serde::{Deserialize, Serialize};

use crate::remediation::MigrationPriority;

/// How important the affected application is to the business.
///
/// Ordering for ranking is defined by `weight()`, not by the variant order —
/// don't derive `Ord` here (it would rank `Unknown` above `Medium`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Critical,
    High,
    Medium,
    Low,
    /// Default when the asset's business context is not declared.
    #[default]
    Unknown,
}

impl Criticality {
    /// Parse a free-text criticality (from config/tags). Unrecognized -> Unknown.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "critical" | "crit" | "tier0" | "tier-0" => Self::Critical,
            "high" | "important" | "tier1" | "tier-1" => Self::High,
            "medium" | "moderate" | "tier2" | "tier-2" => Self::Medium,
            "low" | "minor" | "sandbox" | "dev" | "test" => Self::Low,
            _ => Self::Unknown,
        }
    }

    /// Weight used in the business risk score.
    fn weight(&self) -> u32 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            // Unknown is treated as Medium: absent context shouldn't bury a
            // finding, nor inflate it above a known-critical one.
            Self::Medium | Self::Unknown => 2,
            Self::Low => 1,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

/// What a crypto asset means to the business.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BusinessContext {
    /// Application or service this asset serves (e.g. "checkout-api").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    pub criticality: Criticality,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_classification: Option<String>,
}

impl BusinessContext {
    /// Human-readable one-liner for a plan / ticket / PR body.
    pub fn summary(&self) -> String {
        match &self.application {
            Some(app) => {
                let mut s = format!("{app} ({} criticality", self.criticality.label());
                if let Some(owner) = &self.owner {
                    s.push_str(&format!(", owner {owner}"));
                }
                s.push(')');
                s
            }
            None => format!("unmapped asset ({} criticality)", self.criticality.label()),
        }
    }
}

/// Urgency weight from the crypto migration priority.
fn priority_weight(p: MigrationPriority) -> u32 {
    match p {
        MigrationPriority::P0 => 3,
        MigrationPriority::P1 => 2,
        MigrationPriority::P2 => 1,
    }
}

/// Combined business risk score: crypto urgency × business criticality.
///
/// This is what makes a P1 finding on a critical revenue system (2×4 = 8)
/// outrank a P0 finding on a dev sandbox (3×1 = 3) — the whole point of
/// business context. Range 1..=12.
pub fn business_risk_score(priority: MigrationPriority, criticality: Criticality) -> u32 {
    priority_weight(priority) * criticality.weight()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_p1_outranks_sandbox_p0() {
        // The headline case: a quantum-vulnerable cert on checkout beats a weak
        // cipher on a dev box, even though the sandbox finding is "more urgent"
        // by algorithm alone.
        let checkout = business_risk_score(MigrationPriority::P1, Criticality::Critical);
        let sandbox = business_risk_score(MigrationPriority::P0, Criticality::Low);
        assert!(checkout > sandbox, "{checkout} should beat {sandbox}");
        assert_eq!(checkout, 8);
        assert_eq!(sandbox, 3);
    }

    #[test]
    fn unknown_context_ranks_like_medium() {
        let unknown = business_risk_score(MigrationPriority::P1, Criticality::Unknown);
        let medium = business_risk_score(MigrationPriority::P1, Criticality::Medium);
        assert_eq!(
            unknown, medium,
            "absent context is neither buried nor inflated"
        );
    }

    #[test]
    fn criticality_parse_is_forgiving() {
        assert_eq!(Criticality::parse("Critical"), Criticality::Critical);
        assert_eq!(Criticality::parse("tier-0"), Criticality::Critical);
        assert_eq!(Criticality::parse("sandbox"), Criticality::Low);
        assert_eq!(Criticality::parse("whatever"), Criticality::Unknown);
    }

    #[test]
    fn score_is_bounded_and_monotone() {
        assert_eq!(
            business_risk_score(MigrationPriority::P0, Criticality::Critical),
            12
        );
        assert_eq!(
            business_risk_score(MigrationPriority::P2, Criticality::Low),
            1
        );
        // More critical never lowers the score at fixed priority.
        assert!(
            business_risk_score(MigrationPriority::P1, Criticality::High)
                >= business_risk_score(MigrationPriority::P1, Criticality::Medium)
        );
    }

    #[test]
    fn summary_reads_for_humans() {
        let ctx = BusinessContext {
            application: Some("checkout-api".into()),
            criticality: Criticality::Critical,
            owner: Some("payments-team".into()),
            ..Default::default()
        };
        assert_eq!(
            ctx.summary(),
            "checkout-api (critical criticality, owner payments-team)"
        );
        assert_eq!(
            BusinessContext::default().summary(),
            "unmapped asset (unknown criticality)"
        );
    }
}
