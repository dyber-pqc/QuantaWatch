//! Host-agent endpoints: firmware / boot-chain crypto inventory.
//!
//! A network scan sees exposed ports; an SSH deep-scan sees listening services.
//! Neither can see the crypto rooted in a machine's *hardware and boot chain* —
//! the TPM's algorithms, how Secure Boot signs the loader, the measured-boot PCR
//! hash bank, the disk-encryption cipher. Those are almost universally classical
//! RSA/ECC/SHA and are the hardest of all to migrate (they need firmware, not a
//! config change), which makes them a first-order harvest-now/decrypt-later and
//! forge-later blind spot. A small agent runs on the host and posts this
//! inventory here (authenticated by the enrollment token); the gateway
//! classifies it and folds it into posture.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use qw_scanner::{
    AssetLocation, CryptoAsset, CryptoAssetType, Finding, FindingCategory, FindingSeverity,
    PqcStatus, ScanResult, ScanStatus, ScanTarget,
};
use qw_store::{EndpointComponent, EndpointRow};

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

fn pqc_rank(s: &str) -> u8 {
    match s {
        "classical_weak" => 0,
        "classical_secure" => 1,
        "unknown" => 2,
        "hybrid" => 3,
        "pqc_ready" => 4,
        _ => 2,
    }
}
#[allow(dead_code)]
fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// ---- The inventory an agent posts ----

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EndpointReport {
    hostname: String,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    os_kind: Option<String>,
    #[serde(default)]
    agent_version: Option<String>,
    #[serde(default)]
    tpm: Option<Tpm>,
    #[serde(default)]
    secure_boot: Option<SecureBoot>,
    #[serde(default)]
    measured_boot: Option<MeasuredBoot>,
    #[serde(default)]
    disk_encryption: Option<DiskEncryption>,
    #[serde(default)]
    crypto_libraries: Vec<CryptoLib>,
    #[serde(default)]
    ssh_host_keys: Vec<SshHostKey>,
    #[serde(default)]
    certificates: Vec<CertInfo>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Tpm {
    present: bool,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // accepted wire field, not read yet
    manufacturer: Option<String>,
    #[serde(default)]
    algorithms: Vec<String>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SecureBoot {
    enabled: bool,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // accepted wire field, not read yet
    setup_mode: Option<bool>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct MeasuredBoot {
    present: bool,
    /// "SHA-1" | "SHA-256" | ...
    #[serde(default)]
    pcr_bank: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DiskEncryption {
    enabled: bool,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    key_bits: Option<u32>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CryptoLib {
    name: String,
    #[serde(default)]
    version: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SshHostKey {
    #[serde(rename = "type")]
    key_type: String,
    #[serde(default)]
    #[allow(dead_code)] // accepted wire field, not read yet
    bits: Option<u32>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CertInfo {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // accepted wire field, not read yet
    not_after: Option<String>,
}

// ---- Classification ----

fn comp(
    category: &str,
    name: &str,
    detail: String,
    algorithm: Option<String>,
    pqc: &str,
    sev: &str,
) -> EndpointComponent {
    EndpointComponent {
        category: category.to_string(),
        name: name.to_string(),
        detail,
        algorithm,
        pqc_status: pqc.to_string(),
        severity: sev.to_string(),
    }
}

fn classify(r: &EndpointReport) -> Vec<EndpointComponent> {
    let mut out = Vec::new();

    // Secure Boot — the signature over the boot chain.
    if let Some(sb) = &r.secure_boot {
        if !sb.enabled {
            out.push(comp(
                "secure_boot",
                "Secure Boot",
                "Secure Boot is disabled — the boot chain is unsigned and can be tampered with."
                    .into(),
                None,
                "classical_weak",
                "high",
            ));
        } else {
            let alg = sb
                .signature_algorithm
                .clone()
                .unwrap_or_else(|| "RSA-2048/SHA-256".into());
            out.push(comp(
                "secure_boot", "Secure Boot",
                format!("Boot chain signed with {alg}. Classical signatures are forgeable by a quantum computer, and boot-signing keys can only be rotated by a firmware update — a slow, hardware-pinned migration."),
                Some(alg), "classical_secure", "high",
            ));
        }
    }

    // TPM — the hardware root of trust.
    if let Some(t) = &r.tpm {
        if !t.present {
            out.push(comp(
                "tpm",
                "TPM",
                "No TPM — no hardware root of trust for keys or attestation.".into(),
                None,
                "unknown",
                "medium",
            ));
        } else {
            let algs = if t.algorithms.is_empty() {
                "RSA-2048, ECC P-256".to_string()
            } else {
                t.algorithms.join(", ")
            };
            let ver = t.version.clone().unwrap_or_else(|| "2.0".into());
            out.push(comp(
                "tpm", &format!("TPM {ver}"),
                format!("Hardware root of trust offers {algs}. TPMs implement only classical algorithms today; keys sealed to the TPM are quantum-vulnerable and cannot be re-keyed to PQC without new silicon."),
                Some(algs), "classical_secure", "medium",
            ));
        }
    }

    // Measured boot / PCR hash bank.
    if let Some(mb) = &r.measured_boot {
        if mb.present {
            let bank = mb.pcr_bank.clone().unwrap_or_else(|| "SHA-256".into());
            if bank.to_uppercase().contains("SHA-1") || bank.to_uppercase().contains("SHA1") {
                out.push(comp("measured_boot", "Measured Boot", "Measured boot uses the SHA-1 PCR bank — SHA-1 is broken; switch to the SHA-256 bank.".into(), Some(bank), "classical_weak", "high"));
            } else {
                out.push(comp(
                    "measured_boot",
                    "Measured Boot",
                    format!("Measured boot uses the {bank} PCR bank."),
                    Some(bank),
                    "classical_secure",
                    "info",
                ));
            }
        }
    }

    // Disk encryption (symmetric — quantum-resilient at AES-256, note the margin).
    if let Some(de) = &r.disk_encryption {
        if !de.enabled {
            out.push(comp(
                "disk_encryption",
                "Disk encryption",
                "Disk is not encrypted — data at rest is exposed if the device is lost or seized."
                    .into(),
                None,
                "classical_weak",
                "high",
            ));
        } else {
            let cipher = de.cipher.clone().unwrap_or_else(|| "AES-256-XTS".into());
            let bits = de.key_bits.unwrap_or(256);
            let kind = de.kind.clone().unwrap_or_default();
            if bits >= 256 {
                out.push(comp("disk_encryption", "Disk encryption", format!("{kind} with {cipher}. AES-256 is symmetric — Grover only halves its strength, so it stays quantum-safe (~128-bit)."), Some(cipher), "classical_secure", "info"));
            } else {
                out.push(comp("disk_encryption", "Disk encryption", format!("{kind} with {cipher} ({bits}-bit). Under Grover, an {bits}-bit key drops to ~{}-bit — move to a 256-bit key.", bits / 2), Some(cipher), "classical_secure", "medium"));
            }
        }
    }

    // SSH host keys.
    for k in &r.ssh_host_keys {
        let n = k.key_type.to_lowercase();
        let (pqc, sev, note) = if n.contains("ssh-rsa") || n.contains("ssh-dss") {
            (
                "classical_weak",
                "medium",
                "SHA-1 RSA / DSA host key — deprecated.",
            )
        } else if n.contains("ed25519") || n.contains("ecdsa") || n.contains("rsa-sha2") {
            (
                "classical_secure",
                "info",
                "Classical host key — no PQC host-key format ships yet.",
            )
        } else {
            ("unknown", "low", "Unrecognized host key type.")
        };
        out.push(comp(
            "ssh_host_key",
            &format!("SSH host key {}", k.key_type),
            note.to_string(),
            Some(k.key_type.clone()),
            pqc,
            sev,
        ));
    }

    // Certificates from the host store.
    for c in &r.certificates {
        let sig = c.signature_algorithm.clone().unwrap_or_default();
        let sl = sig.to_lowercase();
        let (pqc, sev) = if sl.contains("ml-dsa") || sl.contains("dilithium") {
            ("pqc_ready", "info")
        } else if sl.contains("sha1") {
            ("classical_weak", "medium")
        } else if sl.is_empty() {
            ("unknown", "low")
        } else {
            ("classical_secure", "info")
        };
        let subj = c.subject.clone().unwrap_or_else(|| "(certificate)".into());
        out.push(comp(
            "certificate",
            &subj,
            format!(
                "Signature: {}",
                if sig.is_empty() {
                    "unknown".into()
                } else {
                    sig.clone()
                }
            ),
            Some(sig),
            pqc,
            sev,
        ));
    }

    // Crypto libraries (informational inventory).
    for l in &r.crypto_libraries {
        let v = l.version.clone().unwrap_or_default();
        out.push(comp(
            "crypto_library",
            &l.name,
            format!(
                "version {}",
                if v.is_empty() { "unknown".into() } else { v }
            ),
            None,
            "unknown",
            "info",
        ));
    }

    out
}

fn components_to_findings(hostname: &str, comps: &[EndpointComponent]) -> Vec<Finding> {
    comps
        .iter()
        // Informational inventory rows don't need a finding.
        .filter(|c| c.severity != "info")
        .map(|c| {
            let sev = match c.severity.as_str() {
                "critical" => FindingSeverity::Critical,
                "high" => FindingSeverity::High,
                "medium" => FindingSeverity::Medium,
                _ => FindingSeverity::Low,
            };
            let pqc = match c.pqc_status.as_str() {
                "pqc_ready" => PqcStatus::PqcReady,
                "hybrid" => PqcStatus::Hybrid,
                "classical_secure" => PqcStatus::ClassicalSecure,
                "classical_weak" => PqcStatus::ClassicalWeak,
                _ => PqcStatus::Unknown,
            };
            Finding {
                id: uuid::Uuid::new_v4().to_string(),
                category: if c.pqc_status == "classical_weak" { FindingCategory::WeakAlgorithm } else { FindingCategory::MissingPqc },
                severity: sev,
                title: format!("{} on {hostname}: {}", c.category.replace('_', " "), c.name),
                description: c.detail.clone(),
                asset: CryptoAsset {
                    id: uuid::Uuid::new_v4().to_string(),
                    asset_type: CryptoAssetType::ProtocolEndpoint,
                    name: format!("{} ({hostname})", c.name),
                    algorithm: c.algorithm.clone(),
                    key_length: None,
                    protocol_version: None,
                    location: AssetLocation { source_type: "endpoint-agent".into(), path: format!("endpoint/{hostname}"), line: None },
                    discovered_by: "host-agent".into(),
                    discovered_at: chrono::Utc::now(),
                },
                remediation: Some("Track as a firmware/boot-chain migration item — plan a PQC-capable firmware/TPM refresh; symmetric (disk) crypto only needs a 256-bit key.".into()),
                pqc_status: pqc,
                metadata: std::collections::HashMap::from([("category".to_string(), c.category.clone())]),
            }
        })
        .collect()
}

// ---- Handlers ----

/// GET /api/endpoints — enrolled endpoints with firmware posture (admin).
pub async fn list_endpoints(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let eps = state.store.list_endpoints(&tenant);
    let vulnerable = eps
        .iter()
        .filter(|e| matches!(e.pqc_status.as_str(), "classical_weak" | "classical_secure"))
        .count();
    Json(json!({
        "endpoints": eps,
        "total": eps.len(),
        "quantumVulnerable": vulnerable,
    }))
}

/// GET /api/endpoints/enroll — the enrollment token + ready-to-run install
/// commands (admin only; this is the secret an agent presents).
pub async fn enroll_info(State(state): State<AppState>) -> impl IntoResponse {
    let token = state.agent_enroll_token.as_str();
    Json(json!({
        "token": token,
        "reportPath": "/api/endpoints/report",
        "linux": format!("QW_URL=<gateway-url> QW_TOKEN={token} sh qw-agent.sh"),
        "windows": format!("$env:QW_URL='<gateway-url>'; $env:QW_TOKEN='{token}'; .\\qw-agent.ps1"),
        "note": "The agent gathers TPM, Secure Boot, measured-boot, disk-encryption and host-key crypto and POSTs it. The token authenticates the report; it grants report-only access, not admin.",
    }))
}

/// DELETE /api/endpoints/{id}
pub async fn delete_endpoint(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    state.store.delete_endpoint(&tenant, &id);
    Json(json!({ "id": id, "deleted": true }))
}

/// POST /api/endpoints/report — an agent posts its inventory. Authenticated by
/// the enrollment token (X-QW-Agent-Token), NOT an admin session; this route is
/// exempt from RBAC in the auth layer.
pub async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(raw): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Validate the agent token if auth is enabled.
    if state.auth_manager.enabled() {
        let presented = headers
            .get("x-qw-agent-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if presented.is_empty() || presented != state.agent_enroll_token.as_str() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid or missing agent token" })),
            )
                .into_response();
        }
    }
    let body: EndpointReport = match serde_json::from_value(raw.clone()) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid report: {e}") })),
            )
                .into_response()
        }
    };
    if body.hostname.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "hostname is required" })),
        )
            .into_response();
    }

    let tenant = qw_store::DEFAULT_TENANT.to_string();
    let components = classify(&body);
    let worst = components
        .iter()
        .map(|c| c.pqc_status.as_str())
        .min_by_key(|s| pqc_rank(s))
        .unwrap_or("unknown")
        .to_string();
    let findings = components_to_findings(&body.hostname, &components);
    let findings_count = findings.len() as u32;

    // Reuse an existing endpoint (same hostname) so re-reports update in place.
    let now = chrono::Utc::now();
    let existing = state
        .store
        .find_endpoint_by_hostname(&tenant, &body.hostname);
    let (id, enrolled_at) = match &existing {
        Some(e) => (e.id.clone(), e.enrolled_at),
        None => (uuid::Uuid::new_v4().to_string(), now),
    };

    let inventory = raw;
    let row = EndpointRow {
        id: id.clone(),
        hostname: body.hostname.clone(),
        os: body.os.clone().unwrap_or_default(),
        os_kind: body.os_kind.clone().unwrap_or_else(|| "other".into()),
        agent_version: body.agent_version.clone(),
        enrolled_at,
        last_report: now,
        pqc_status: worst.clone(),
        findings_count,
        components: components.clone(),
        inventory,
    };
    state.store.upsert_endpoint(&tenant, &row);

    // Fold the firmware findings into scan history + posture + graph.
    let mut sr_findings = findings;
    let result = ScanResult {
        scanner_id: "host-agent".to_string(),
        target_id: format!("endpoint:{}", row.id),
        started_at: now,
        completed_at: now,
        findings: std::mem::take(&mut sr_findings),
        status: ScanStatus::Completed,
        error: None,
    };
    let scan_target = ScanTarget::network_host(&body.hostname);
    state.store.record_scan(&tenant, &result, &scan_target);
    crate::background::recompute_and_snapshot(
        &state,
        &tenant,
        std::slice::from_ref(&result),
        "host-agent",
    )
    .await;

    let _ = state
        .audit_logger
        .log(
            "agent",
            qw_audit::AuditEvent::ScanCompleted {
                scan_id: result.target_id.clone(),
                scanner_id: "host-agent".to_string(),
                target: body.hostname.clone(),
                finding_count: findings_count,
                status: "endpoint-report".to_string(),
            },
        )
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "endpointId": id,
            "hostname": body.hostname,
            "pqcStatus": worst,
            "components": components.len(),
            "findings": findings_count,
        })),
    )
        .into_response()
}
