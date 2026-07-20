//! Signed evidence pack — a single, ML-DSA-signed audit deliverable folding the
//! CBOM (+ hardware-style attestation), compliance assessment, attack-path
//! graph, posture, and audit-chain verification into one downloadable document.

use std::collections::HashMap;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde_json::json;

use qw_cbom::{ComplianceEngine, PostureEngine};
use qw_crypto::sha3_256_hex;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

pub async fn evidence_pack(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let pack = build_pack(&state, &tenant).await;
    match serde_json::to_string_pretty(&pack) {
        Ok(s) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"quantawatch-evidence-pack.json\"".to_string(),
                ),
            ],
            s,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Build the signed evidence pack for `tenant` (reused by the endpoint and the
/// scheduled delivery task).
pub async fn build_pack(state: &AppState, tenant: &str) -> serde_json::Value {
    // 1. Posture.
    let providers: Vec<_> = state
        .provider_crypto
        .iter()
        .map(|e| e.value().clone())
        .collect();
    let posture = {
        let cache = state.posture_cache.read().await;
        cache
            .clone()
            .unwrap_or_else(|| PostureEngine::summarize(&[], &providers))
    };

    // 2. CBOM with signed attestation.
    let cbom = crate::admin::cbom::build_cbom(state);

    // 3. Compliance.
    let findings = state.store.all_findings(tenant);
    let compliance = ComplianceEngine::assess(&findings);

    // 4. Attack-path graph.
    let graph = crate::admin::graph::build_graph(state, tenant, &HashMap::new());
    let critical = graph
        .paths
        .iter()
        .filter(|p| p.severity == "critical")
        .count();

    // 5. Audit-chain verification (tamper-evidence): every per-writer chain plus
    //    the global checkpoint chain.
    let audit = {
        use qw_audit::AuditBackend;
        let pk = state.gateway_identity.public_key_bytes();
        let entries = state.store.list_entries(1_000_000);
        let checkpoints = state.store.list_checkpoints();
        let r = qw_audit::verify_sharded(&entries, &checkpoints, &pk);
        json!({
            "valid": r.valid, "entriesChecked": r.entries_checked,
            "writersChecked": r.writers_checked, "checkpointsChecked": r.checkpoints_checked,
            "signaturesValid": r.signatures_valid, "chainIntact": r.chain_intact,
            "merkleRootsValid": r.merkle_roots_valid, "errors": r.errors,
        })
    };

    // The pack body (everything that is signed).
    let body = json!({
        "version": "1.0",
        "tenant": tenant,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "gatewayFingerprint": state.gateway_identity.fingerprint,
        "posture": posture,
        "compliance": compliance,
        "attackPaths": { "total": graph.paths.len(), "critical": critical, "paths": graph.paths },
        "cbom": cbom,
        "auditChain": audit,
    });

    // Sign the canonical body with the gateway's ML-DSA-65 identity.
    let canonical = serde_json::to_vec(&body).unwrap_or_default();
    let digest = sha3_256_hex(&canonical);
    let signature = state
        .gateway_identity
        .sign(digest.as_bytes())
        .map(hex::encode)
        .unwrap_or_default();

    json!({
        "evidencePack": body,
        "signature": {
            "algorithm": "ML-DSA-65",
            "digestAlgorithm": "SHA3-256",
            "digest": digest,
            "value": signature,
            "publicKey": hex::encode(state.gateway_identity.public_key_bytes()),
            "note": "Verify: ML-DSA-65 verify(publicKey, signature, SHA3-256(canonical evidencePack)).",
        },
    })
}
