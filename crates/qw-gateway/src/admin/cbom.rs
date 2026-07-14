use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use qw_cbom::{Attestation, CbomBuilder, CryptoBom, Measurement, PostureEngine};
use qw_crypto::sha3_256_hex;
use serde_json::json;

use crate::state::AppState;

/// Build a full CBOM document from the current provider crypto + cached posture,
/// then sign an attestation quote over it with the gateway's ML-DSA-65 identity.
pub fn build_cbom(state: &AppState) -> CryptoBom {
    let mut builder = CbomBuilder::new();
    let providers: Vec<_> = state
        .provider_crypto
        .iter()
        .map(|e| e.value().clone())
        .collect();
    builder.ingest_provider_info(&providers);
    let posture = PostureEngine::summarize(&[], &providers);
    let mut bom = builder.build_with_posture(&state.gateway_identity.fingerprint, posture);
    bom.attestation = Some(attest(state, &bom));
    bom
}

/// Produce a signed attestation quote binding the CBOM digest + platform
/// measurements to the gateway's PQC identity. Software stand-in for a hardware
/// QuantaTPM quote — same structure, honestly labelled.
fn attest(state: &AppState, bom: &CryptoBom) -> Attestation {
    let identity = &state.gateway_identity;

    // Digest the CBOM payload *without* an attestation (it's None here), over a
    // CANONICAL (sorted-key) serialization so an external verifier — which parses
    // the JSON into a value — can reproduce exactly the same bytes.
    let canonical = serde_json::to_value(bom).unwrap_or_default();
    let payload = serde_json::to_vec(&canonical).unwrap_or_default();
    let bom_digest = sha3_256_hex(&payload);
    let nonce = uuid::Uuid::new_v4().to_string();

    let pubkey = identity.public_key_bytes();
    let measurements = vec![
        Measurement {
            name: "gateway-identity".into(),
            value: identity.fingerprint.clone(),
        },
        Measurement {
            name: "platform-key".into(),
            value: sha3_256_hex(&pubkey),
        },
        Measurement {
            name: "tool".into(),
            value: format!("quantawatch-{}", env!("CARGO_PKG_VERSION")),
        },
    ];

    // Quote payload = digest | nonce | name=value;... (deterministic ordering)
    let measure_str = measurements
        .iter()
        .map(|m| format!("{}={}", m.name, m.value))
        .collect::<Vec<_>>()
        .join(";");
    let quote_payload = format!("{bom_digest}|{nonce}|{measure_str}");
    let signature = identity
        .sign(quote_payload.as_bytes())
        .map(hex::encode)
        .unwrap_or_default();

    Attestation {
        attestation_type: "software-ml-dsa-65".into(),
        algorithm: "ML-DSA-65".into(),
        signer_fingerprint: identity.fingerprint.clone(),
        bom_digest,
        nonce,
        measurements,
        signature,
        public_key: hex::encode(&pubkey),
        signed_at: chrono::Utc::now(),
        note: "Software-emulated attestation over the live CBOM; QuantaTPM hardware quote pending."
            .into(),
    }
}

pub async fn get_cbom(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!(build_cbom(&state)))
}

/// Return just the signed attestation quote over the current CBOM.
pub async fn get_attestation(State(state): State<AppState>) -> impl IntoResponse {
    let bom = build_cbom(&state);
    Json(json!(bom.attestation))
}

/// CBOM download with Content-Disposition so browsers save it as a file.
pub async fn download_cbom(State(state): State<AppState>) -> impl IntoResponse {
    let cbom = build_cbom(&state);
    match serde_json::to_string_pretty(&cbom) {
        Ok(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"quantawatch-cbom.json\"".to_string(),
                ),
            ],
            body,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn list_components(State(state): State<AppState>) -> impl IntoResponse {
    let cbom = build_cbom(&state);
    Json(json!({
        "components": cbom.components,
        "total": cbom.components.len(),
    }))
}

pub async fn list_services(State(state): State<AppState>) -> impl IntoResponse {
    let cbom = build_cbom(&state);
    Json(json!({
        "services": cbom.services,
        "total": cbom.services.len(),
    }))
}
