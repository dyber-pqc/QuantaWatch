//! Multi-framework compliance controls.
//!
//! Generalizes the SOC 2 controls surface to the frameworks enterprises and
//! federal buyers actually ask for — CNSA 2.0, NIST SP 800-53, PCI-DSS, FedRAMP.
//! Every control is evaluated LIVE against the running configuration, and each
//! framework exposes a CI gate (`?gate=1` → HTTP 422 on failure). The signals
//! come from real QuantaWatch capabilities (in-path enforcement, at-rest
//! discovery, governance target, RBAC, tamper-evident audit) — so a "pass" is
//! backed by an enforced control, not a questionnaire answer.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::GatewayConfig;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Enforced,
    Partial,
    Configurable,
    Manual,
}

#[derive(Debug, Clone, Serialize)]
struct Control {
    id: &'static str,
    title: &'static str,
    /// Whether this control counts toward the gate.
    required: bool,
    status: Status,
    evidence: String,
    verify_at: &'static str,
}

/// Live capability signals derived once from config.
struct Signals {
    auth_on: bool,
    lockout: bool,
    idle_timeout: bool,
    enforce_on: bool,
    enforce_block: bool,
    at_rest_on: bool,
    key_rotation: bool,
    tls_scan: bool,
    target_pqc: bool,
    forbidden_set: bool,
    alerts_on: bool,
}

impl Signals {
    fn from_config(c: &GatewayConfig) -> Self {
        let ce = &c.crypto_enforcement;
        let dar = &c.scanner.data_at_rest;
        Self {
            auth_on: c.auth.enabled,
            lockout: c.auth.max_failed_logins > 0,
            idle_timeout: c.auth.idle_timeout_secs > 0,
            enforce_on: ce.enabled,
            enforce_block: ce.enabled && ce.mode.eq_ignore_ascii_case("enforce"),
            at_rest_on: dar.enabled && !dar.stores.is_empty(),
            key_rotation: dar.max_key_age_days > 0,
            tls_scan: c.scanner.tls.enabled,
            target_pqc: !c.crypto_policy.target.is_empty(),
            forbidden_set: !c.crypto_policy.forbidden.is_empty(),
            alerts_on: c.alerts.enabled,
        }
    }
}

fn c(
    id: &'static str,
    title: &'static str,
    required: bool,
    status: Status,
    evidence: impl Into<String>,
    verify_at: &'static str,
) -> Control {
    Control {
        id,
        title,
        required,
        status,
        evidence: evidence.into(),
        verify_at,
    }
}

/// enforced if `full`, else partial if `partial`, else configurable.
fn tri(full: bool, partial: bool) -> Status {
    if full {
        Status::Enforced
    } else if partial {
        Status::Partial
    } else {
        Status::Configurable
    }
}
fn on(b: bool) -> Status {
    if b {
        Status::Enforced
    } else {
        Status::Configurable
    }
}

struct Framework {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    controls: Vec<Control>,
}

fn cnsa(s: &Signals) -> Framework {
    Framework {
        id: "cnsa-2.0",
        name: "CNSA 2.0",
        description: "NSA Commercial National Security Algorithm Suite 2.0 (post-quantum).",
        controls: vec![
            c("CNSA-SYM", "AES-256 for symmetric protection", true, on(s.at_rest_on),
              "At-rest discovery classifies symmetric strength; AES-256 is CNSA-compliant, AES-128 is flagged.",
              "GET /api/findings?category=weak_algorithm"),
            c("CNSA-ASYM", "ML-KEM / ML-DSA as the asymmetric target", true, tri(false, s.target_pqc),
              if s.target_pqc { "Governance target set to the PQC suite (migration in progress)." } else { "No PQC target declared in crypto_policy.target." },
              "GET /api/governance"),
            c("CNSA-TRANSIT", "Post-quantum protection in transit", true,
              tri(s.enforce_block, s.enforce_on),
              if s.enforce_block { "In-path enforcement blocks sub-hybrid channels." } else if s.enforce_on { "Enforcement is in monitor mode (flags, does not block)." } else { "In-path crypto enforcement is off." },
              "config crypto_enforcement; quantawatch_crypto_enforcement_total"),
            c("CNSA-FORBID", "Legacy algorithms forbidden", true, on(s.forbidden_set),
              "crypto_policy.forbidden bans deprecated primitives; the governance gate fails on their presence.",
              "GET /api/governance?gate=1"),
            c("CNSA-INV", "Complete cryptographic inventory", false, Status::Enforced,
              "Deterministic CBOM inventories every discovered crypto asset (in-transit, at-rest, deps, code).",
              "GET /api/cbom"),
        ],
    }
}

fn nist_800_53(s: &Signals) -> Framework {
    Framework {
        id: "nist-800-53",
        name: "NIST SP 800-53 (crypto)",
        description: "Rev. 5 cryptographic and access control families (SC / AU / AC / SI).",
        controls: vec![
            c("SC-8", "Transmission confidentiality & integrity", true, on(s.tls_scan),
              "TLS scanning fingerprints every provider channel; in-path enforcement can require hybrid.",
              "GET /api/posture"),
            c("SC-12", "Cryptographic key establishment & management", true, on(s.key_rotation),
              "At-rest key-age policy flags stale keys; KEK posture (RSA vs ML-KEM) is classified.",
              "GET /api/findings?category=stale_key_rotation"),
            c("SC-13", "Cryptographic protection (approved algorithms)", true, tri(s.forbidden_set && s.target_pqc, s.forbidden_set || s.target_pqc),
              "Governance policy declares the approved target set and forbidden primitives, gated in CI.",
              "GET /api/governance"),
            c("SC-28", "Protection of information at rest", true, on(s.at_rest_on),
              "Data-at-rest scanner evaluates store encryption, cipher strength, and HNDL KEK exposure.",
              "GET /api/findings?category=unencrypted_at_rest"),
            c("AU-9", "Protection of audit information", true, Status::Enforced,
              "Audit log is a SHA3-256 hash chain + Merkle roots signed with ML-DSA-65; verifiable.",
              "POST /api/audit/verify"),
            c("AC-6", "Least privilege", true, on(s.auth_on),
              "Permission-based RBAC with per-resource read/write and custom least-privilege roles.",
              "GET /api/rbac"),
            c("SI-4", "System monitoring", false, tri(s.alerts_on, true),
              if s.alerts_on { "In-path monitor inspects every request/response; alerts fire to Slack/webhook on security events." } else { "In-path monitor is active; enable alerts for the response leg of SI-4." },
              "GET /api/threats; config alerts"),
        ],
    }
}

fn pci_dss(s: &Signals) -> Framework {
    Framework {
        id: "pci-dss",
        name: "PCI-DSS v4.0",
        description: "Payment Card Industry Data Security Standard — cryptographic requirements.",
        controls: vec![
            c("PCI-3", "Req 3 — Protect stored account data", true, on(s.at_rest_on),
              "At-rest discovery flags unencrypted stores, weak ciphers, and quantum-vulnerable KEKs.",
              "GET /api/findings?category=unencrypted_at_rest"),
            c("PCI-4", "Req 4 — Encrypt transmission across open networks", true, on(s.tls_scan),
              "TLS posture scanning + optional in-path enforcement of the transport standard.",
              "GET /api/posture"),
            c("PCI-8", "Req 8 — Identify users & authenticate access", true,
              tri(s.auth_on && s.lockout && s.idle_timeout, s.auth_on),
              if s.auth_on && s.lockout && s.idle_timeout { "Auth on, with failed-login lockout and idle-session timeout." } else if s.auth_on { "Auth on; enable lockout + idle timeout for full compliance." } else { "Authentication is disabled." },
              "config auth"),
            c("PCI-10", "Req 10 — Log & monitor all access", true, Status::Enforced,
              "Tamper-evident audit log records access, admin actions, and enforcement decisions.",
              "GET /api/audit"),
            c("PCI-12", "Req 12.3 — Crypto-agility risk management", false, tri(s.target_pqc, s.forbidden_set),
              "Crypto-agility governance tracks migration to the target suite with a deadline.",
              "GET /api/governance/history"),
        ],
    }
}

fn fedramp(s: &Signals) -> Framework {
    Framework {
        id: "fedramp",
        name: "FedRAMP (crypto)",
        description: "FedRAMP cryptographic posture (CNSA 2.0 + 800-53 continuous monitoring).",
        controls: vec![
            c("FR-1", "FIPS-validated cryptographic modules", true, Status::Manual,
              "QuantaWatch uses FIPS 203/204 algorithms (ML-KEM/ML-DSA); module validation is an org attestation.",
              "docs/SOC2.md, module certificates"),
            c("FR-2", "CNSA 2.0 migration plan", true, tri(s.target_pqc, false),
              if s.target_pqc { "PQC target + deadline declared; convergence tracked over time." } else { "Declare a PQC target in crypto_policy." },
              "GET /api/governance/history"),
            c("FR-3", "Continuous monitoring of crypto posture", true, Status::Enforced,
              "Scheduled re-scanning + governance gate + posture SLOs detect drift continuously.",
              "GET /api/slos?gate=1"),
            c("FR-4", "Encryption in transit and at rest", true,
              tri(s.at_rest_on && s.tls_scan, s.at_rest_on || s.tls_scan),
              "Both surfaces are scanned; in-path enforcement can hold transit to a PQC floor.",
              "GET /api/posture"),
            c("FR-5", "Audit logging & access control", true, on(s.auth_on),
              "Signed audit trail + permission-based RBAC; access and change events recorded.",
              "GET /api/audit, GET /api/rbac"),
        ],
    }
}

fn all(s: &Signals) -> Vec<Framework> {
    vec![cnsa(s), nist_800_53(s), pci_dss(s), fedramp(s)]
}

fn summarize(f: &Framework) -> serde_json::Value {
    let count = |st: Status| f.controls.iter().filter(|c| c.status == st).count();
    // Gate: any REQUIRED control that isn't fully Enforced is a gap.
    let gaps: Vec<&str> = f
        .controls
        .iter()
        .filter(|c| c.required && c.status != Status::Enforced)
        .map(|c| c.id)
        .collect();
    let pass = gaps.is_empty();
    json!({
        "id": f.id,
        "name": f.name,
        "description": f.description,
        "verdict": if pass { "PASS" } else { "GAPS" },
        "summary": {
            "total": f.controls.len(),
            "enforced": count(Status::Enforced),
            "partial": count(Status::Partial),
            "configurable": count(Status::Configurable),
            "manual": count(Status::Manual),
            "gaps": gaps.len(),
        },
        "gapControls": gaps,
    })
}

/// GET /api/frameworks — one summary per framework.
pub async fn list_frameworks(State(state): State<AppState>) -> impl IntoResponse {
    let s = Signals::from_config(&state.config);
    let frameworks: Vec<_> = all(&s).iter().map(summarize).collect();
    Json(json!({
        "note": "Controls are evaluated live against the running configuration. A PASS means \
                 every required control is enforced by the product, not attested on paper.",
        "frameworks": frameworks,
    }))
}

#[derive(Debug, Deserialize)]
pub struct GateQuery {
    #[serde(default)]
    gate: Option<u8>,
}

/// GET /api/frameworks/{id} — full control detail. `?gate=1` returns HTTP 422
/// when any required control is not enforced, so CI can block a regression.
pub async fn get_framework(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<GateQuery>,
) -> impl IntoResponse {
    let s = Signals::from_config(&state.config);
    let Some(f) = all(&s).into_iter().find(|f| f.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown framework: {id}") })),
        )
            .into_response();
    };
    let summary = summarize(&f);
    let pass = summary["verdict"] == "PASS";
    let body = json!({
        "id": f.id,
        "name": f.name,
        "description": f.description,
        "verdict": summary["verdict"],
        "summary": summary["summary"],
        "controls": f.controls,
    });
    let gate = q.gate.unwrap_or(0) == 1;
    if gate && !pass {
        (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
    } else {
        (StatusCode::OK, Json(body)).into_response()
    }
}
