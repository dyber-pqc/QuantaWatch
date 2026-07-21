//! Internal PQC CA admin API: issue, list, renew, revoke, and verify hybrid
//! certificates.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

fn ca_or_503(state: &AppState) -> Result<&std::sync::Arc<crate::pki::CertAuthority>, axum::response::Response> {
    match &state.ca {
        Some(ca) => Ok(ca),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "PKI is disabled — set pki.enabled: true in config" })),
        )
            .into_response()),
    }
}

/// Strip the private key from an issued record before it is persisted/listed.
fn public_record(row: &qw_store::CertificateRow) -> serde_json::Value {
    serde_json::to_value(row).unwrap_or_else(|_| json!({}))
}

/// GET /api/pki/ca — the CA's trust material (classical cert + ML-DSA key).
pub async fn get_ca(State(state): State<AppState>) -> impl IntoResponse {
    match ca_or_503(&state) {
        Ok(ca) => Json(ca.ca_info()).into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueRequest {
    subject: String,
    #[serde(default)]
    sans: Vec<String>,
    #[serde(default)]
    validity_days: Option<u32>,
    /// "hybrid" (default) or "classical".
    #[serde(default)]
    key_type: Option<String>,
}

/// POST /api/pki/issue — issue a certificate. Returns the record PLUS the leaf
/// private key PEM (once — it is never stored).
pub async fn issue(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<IssueRequest>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let ca = match ca_or_503(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if body.subject.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "subject is required" }))).into_response();
    }
    let hybrid = body.key_type.as_deref() != Some("classical");
    let days = body
        .validity_days
        .unwrap_or(state.config.pki.default_validity_days);

    match ca.issue(&body.subject, &body.sans, days, hybrid) {
        Ok((row, key_pem)) => {
            state.store.record_certificate(&tenant, &row);
            audit_issued(&state, &row, false).await;
            let mut out = public_record(&row);
            out["keyPem"] = json!(key_pem); // returned once, not stored
            (StatusCode::CREATED, Json(out)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/pki/certificates — every issued cert (no private keys).
pub async fn list_certificates(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let certs = state.store.list_certificates(&tenant);
    let (mut active, mut hybrid, mut revoked) = (0, 0, 0);
    for c in &certs {
        match c.status.as_str() {
            "revoked" => revoked += 1,
            _ => active += 1,
        }
        if c.key_type == "hybrid" {
            hybrid += 1;
        }
    }
    Json(json!({
        "certificates": certs,
        "total": certs.len(),
        "active": active,
        "hybrid": hybrid,
        "revoked": revoked,
    }))
}

/// GET /api/pki/certificates/{id}
pub async fn get_certificate(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    match state.store.get_certificate(&tenant, &id) {
        Some(c) => Json(c).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("certificate '{id}' not found") })),
        )
            .into_response(),
    }
}

/// POST /api/pki/certificates/{id}/renew — reissue the same subject/SANs with a
/// fresh validity window (rotation). Returns the new record + key.
pub async fn renew(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let ca = match ca_or_503(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(prev) = state.store.get_certificate(&tenant, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("certificate '{id}' not found") })),
        )
            .into_response();
    };
    let hybrid = prev.key_type == "hybrid";
    let days = state.config.pki.default_validity_days;
    let sans: Vec<String> = prev.sans.iter().filter(|s| **s != prev.subject).cloned().collect();

    match ca.issue(&prev.subject, &sans, days, hybrid) {
        Ok((row, key_pem)) => {
            state.store.record_certificate(&tenant, &row);
            audit_issued(&state, &row, true).await;
            let mut out = public_record(&row);
            out["keyPem"] = json!(key_pem);
            out["renewedFrom"] = json!(id);
            (StatusCode::CREATED, Json(out)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/pki/certificates/{id}/revoke
pub async fn revoke(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let Some(mut cert) = state.store.get_certificate(&tenant, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("certificate '{id}' not found") })),
        )
            .into_response();
    };
    cert.status = "revoked".to_string();
    cert.revoked_at = Some(chrono::Utc::now());
    state.store.record_certificate(&tenant, &cert);
    let _ = state
        .audit_logger
        .log(
            "system",
            qw_audit::AuditEvent::CertificateRevoked {
                cert_id: cert.id.clone(),
                subject: cert.subject.clone(),
                reason: "manual".to_string(),
            },
        )
        .await;
    Json(json!({ "id": id, "status": "revoked" })).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    cert_pem: String,
    mldsa_public_key: String,
    mldsa_signature: String,
}

/// POST /api/pki/verify — check a certificate's ML-DSA post-quantum binding.
pub async fn verify(Json(body): Json<VerifyRequest>) -> impl IntoResponse {
    let valid = crate::pki::CertAuthority::verify_binding(
        &body.cert_pem,
        &body.mldsa_public_key,
        &body.mldsa_signature,
    );
    Json(json!({ "valid": valid, "binding": "ml-dsa-65" }))
}

async fn audit_issued(state: &AppState, row: &qw_store::CertificateRow, renewed: bool) {
    let _ = state
        .audit_logger
        .log(
            "system",
            qw_audit::AuditEvent::CertificateIssued {
                cert_id: row.id.clone(),
                subject: row.subject.clone(),
                key_type: row.key_type.clone(),
                serial: row.serial.clone(),
                not_after: row.not_after.to_rfc3339(),
                renewed,
            },
        )
        .await;
}
