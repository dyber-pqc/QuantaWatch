//! Kubernetes ValidatingAdmissionWebhook.
//!
//! The apiserver calls `POST /api/k8s/admission` before admitting a resource.
//! This inspects the crypto that a resource carries and, per the admission mode
//! (Settings → "Kubernetes admission: enforce"), either DENIES a workload that
//! ships quantum-vulnerable crypto or admits it with a warning (monitor mode).
//!
//! Today it classifies **TLS Secrets** (`kubernetes.io/tls`) by parsing the
//! actual leaf certificate, and flags **Ingresses** that terminate TLS without
//! a declared PQC posture. Flagged objects are also recorded as findings so they
//! surface in the dashboard.
//!
//! In a cluster this endpoint is reached over mTLS (the webhook `caBundle`); the
//! manifest is in `deploy/k8s/`. This handler is auth-exempt because the caller
//! is the apiserver, not a dashboard user.

use axum::{extract::State, response::IntoResponse, Json};
use base64::Engine;
use serde_json::{json, Value};

use qw_scanner::{classify_cert, PqcStatus};

use crate::state::AppState;

/// The verdict for one admitted object.
struct Decision {
    /// Non-empty => a reason the object is quantum-vulnerable.
    reason: Option<String>,
    /// Human context (kind/name) for messages + findings.
    subject: String,
    location: String,
    algorithm: Option<String>,
}

fn allow_review(uid: &str) -> Value {
    review_response(uid, true, None, &[])
}

/// Build an `AdmissionReview` response.
fn review_response(uid: &str, allowed: bool, message: Option<&str>, warnings: &[String]) -> Value {
    let mut resp = json!({
        "uid": uid,
        "allowed": allowed,
    });
    if let Some(m) = message {
        resp["status"] = json!({ "code": if allowed { 200 } else { 403 }, "message": m });
    }
    if !warnings.is_empty() {
        resp["warnings"] = json!(warnings);
    }
    json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": resp,
    })
}

/// Classify the crypto a resource carries. Returns None for kinds we don't gate.
fn evaluate(request: &Value) -> Option<Decision> {
    let obj = request.get("object")?;
    let kind = request
        .get("kind")
        .and_then(|k| k.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let name = obj
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    let namespace = obj
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .or_else(|| request.get("namespace").and_then(Value::as_str))
        .unwrap_or("default");
    let location = format!("k8s://{namespace}/{}/{name}", kind.to_lowercase());

    match kind {
        "Secret" => {
            // Only TLS secrets carry a certificate we can classify.
            if obj.get("type").and_then(Value::as_str) != Some("kubernetes.io/tls") {
                return None;
            }
            let crt_b64 = obj.pointer("/data/tls.crt").and_then(Value::as_str)?;
            let pem = base64::engine::general_purpose::STANDARD
                .decode(crt_b64.trim())
                .ok()?;
            let summary = classify_cert(&pem);
            let (algorithm, pqc) = match &summary {
                Some(s) => (Some(s.algorithm.clone()), s.pqc_status),
                None => (None, PqcStatus::Unknown),
            };
            let reason = match pqc {
                PqcStatus::ClassicalWeak | PqcStatus::ClassicalSecure => Some(format!(
                    "TLS secret '{name}' uses a classical (quantum-vulnerable) certificate ({}).",
                    algorithm.clone().unwrap_or_else(|| "classical".into())
                )),
                _ => None,
            };
            Some(Decision {
                reason,
                subject: format!("Secret {namespace}/{name}"),
                location,
                algorithm,
            })
        }
        "Ingress" => {
            // We can't see the referenced cert here; advise unless the workload
            // declares a PQC posture via annotation.
            let terminates_tls = obj
                .pointer("/spec/tls")
                .map(|t| !t.is_null())
                .unwrap_or(false);
            let declared_pqc = obj
                .pointer("/metadata/annotations/quantawatch.io~1pqc")
                .and_then(Value::as_str)
                == Some("true");
            let reason = if terminates_tls && !declared_pqc {
                Some(format!(
                    "Ingress '{name}' terminates TLS with no declared post-quantum posture (annotate quantawatch.io/pqc: \"true\" once its cert is hybrid/ML-DSA)."
                ))
            } else {
                None
            };
            Some(Decision {
                reason,
                subject: format!("Ingress {namespace}/{name}"),
                location,
                algorithm: None,
            })
        }
        _ => None,
    }
}

/// `POST /api/k8s/admission` — the ValidatingAdmissionWebhook entry point.
pub async fn admission_review(
    State(state): State<AppState>,
    Json(review): Json<Value>,
) -> impl IntoResponse {
    let request = review.get("request").cloned().unwrap_or(Value::Null);
    let uid = request
        .get("uid")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let Some(decision) = evaluate(&request) else {
        // Nothing we gate → always admit.
        return Json(allow_review(&uid));
    };

    let Some(reason) = decision.reason else {
        return Json(allow_review(&uid));
    };

    // Enforce mode denies; monitor mode admits with a warning.
    let enforce =
        crate::admin::settings_api::load(&state, qw_store::DEFAULT_TENANT).k8s_admission_enforce;

    // Record it as a finding so it surfaces in the dashboard either way.
    let finding = qw_scanner::Finding {
        id: uuid::Uuid::new_v4().to_string(),
        category: qw_scanner::FindingCategory::MissingPqc,
        severity: qw_scanner::FindingSeverity::High,
        title: format!("K8s admission: {}", decision.subject),
        description: reason.clone(),
        asset: qw_scanner::CryptoAsset {
            id: uuid::Uuid::new_v4().to_string(),
            asset_type: qw_scanner::CryptoAssetType::Certificate,
            name: decision.subject.clone(),
            algorithm: decision.algorithm.clone(),
            key_length: None,
            protocol_version: None,
            location: qw_scanner::AssetLocation {
                source_type: "k8s_admission".into(),
                path: decision.location.clone(),
                line: None,
            },
            discovered_by: "k8s-admission".into(),
            discovered_at: chrono::Utc::now(),
        },
        remediation: Some(
            "Issue a hybrid/ML-DSA certificate for this workload (QuantaWatch PKI) and reference it, or front it with the PQC overlay.".into(),
        ),
        pqc_status: PqcStatus::ClassicalSecure,
        metadata: std::collections::HashMap::from([
            ("source".to_string(), "k8s-admission".to_string()),
            ("mode".to_string(), if enforce { "enforce" } else { "monitor" }.to_string()),
        ]),
    };
    let result = qw_scanner::ScanResult {
        scanner_id: "k8s-admission".into(),
        target_id: decision.location.clone(),
        started_at: chrono::Utc::now(),
        completed_at: chrono::Utc::now(),
        findings: vec![finding],
        status: qw_scanner::ScanStatus::Completed,
        error: None,
    };
    state.store.record_scan(
        qw_store::DEFAULT_TENANT,
        &result,
        &qw_scanner::ScanTarget::network_host(&decision.location),
    );

    let msg = format!(
        "QuantaWatch: {reason}{}",
        if enforce {
            " Denied (admission enforce mode)."
        } else {
            ""
        }
    );
    Json(review_response(&uid, !enforce, Some(&msg), &[reason]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real self-signed RSA-2048/SHA-256 leaf (classical) for the TLS-secret test.
    // Generated once; base64 of the DER is embedded so the test needs no network.
    const CLASSICAL_TLS_CRT_B64: &str = include_str!("../../testdata/classical_tls_crt.b64");

    fn secret_review(crt_b64: &str) -> Value {
        json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc-123",
                "kind": { "group": "", "version": "v1", "kind": "Secret" },
                "name": "web-tls",
                "namespace": "prod",
                "operation": "CREATE",
                "object": {
                    "metadata": { "name": "web-tls", "namespace": "prod" },
                    "type": "kubernetes.io/tls",
                    "data": { "tls.crt": crt_b64.trim() }
                }
            }
        })
    }

    #[test]
    fn non_tls_secret_is_ignored() {
        let review = json!({ "request": { "uid": "u", "kind": {"kind":"Secret"}, "object": { "type": "Opaque", "metadata": {"name":"x"} } } });
        assert!(evaluate(&review["request"])
            .and_then(|d| d.reason)
            .is_none());
    }

    #[test]
    fn classical_tls_secret_is_flagged() {
        let review = secret_review(CLASSICAL_TLS_CRT_B64);
        let d = evaluate(&review["request"]).expect("evaluated");
        assert!(d.reason.is_some(), "classical cert must be flagged");
        assert!(d.subject.contains("prod/web-tls"));
        assert!(d
            .algorithm
            .as_deref()
            .unwrap_or("")
            .to_uppercase()
            .contains("RSA"));
    }

    #[test]
    fn ingress_without_pqc_annotation_is_flagged() {
        let review = json!({ "request": { "uid":"u", "kind": {"kind":"Ingress"}, "object": {
            "metadata": {"name":"web","namespace":"prod"},
            "spec": {"tls": [{"hosts":["web.example.com"],"secretName":"web-tls"}]}
        }}});
        let d = evaluate(&review["request"]).unwrap();
        assert!(d.reason.is_some());
    }

    #[test]
    fn ingress_with_pqc_annotation_is_allowed() {
        let review = json!({ "request": { "uid":"u", "kind": {"kind":"Ingress"}, "object": {
            "metadata": {"name":"web","namespace":"prod","annotations": {"quantawatch.io/pqc":"true"}},
            "spec": {"tls": [{"hosts":["web.example.com"]}]}
        }}});
        assert!(evaluate(&review["request"]).unwrap().reason.is_none());
    }

    #[test]
    fn response_shape_is_valid_admission_review() {
        let deny = review_response("uid-1", false, Some("nope"), &["warn".into()]);
        assert_eq!(deny["kind"], "AdmissionReview");
        assert_eq!(deny["response"]["uid"], "uid-1");
        assert_eq!(deny["response"]["allowed"], false);
        assert_eq!(deny["response"]["status"]["code"], 403);
        assert_eq!(deny["response"]["warnings"][0], "warn");

        let allow = allow_review("uid-2");
        assert_eq!(allow["response"]["allowed"], true);
    }
}
