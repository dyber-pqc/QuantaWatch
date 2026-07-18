pub mod builder;
pub mod business;
pub mod compliance;
pub mod deterministic;
pub mod history;
pub mod model;
pub mod posture;
pub mod remediation;

pub use builder::CbomBuilder;
pub use business::{business_risk_score, BusinessContext, Criticality};
pub use compliance::{
    ComplianceEngine, ComplianceReport, ComplianceStatus, FrameworkSummary, MigrationItem,
};
pub use deterministic::{dedupe_scan_results, make_deterministic};
pub use history::{PostureHistoryStore, PostureSnapshot};
pub use model::*;
pub use posture::PostureEngine;
pub use remediation::{
    plan_all, plan_migration, plan_to_markdown, MigrationPatch, MigrationPlan, MigrationPriority,
    MigrationStrategy,
};
