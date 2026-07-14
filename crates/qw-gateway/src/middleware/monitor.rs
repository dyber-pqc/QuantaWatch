use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;

use crate::error::GatewayError;
use crate::middleware::identity::SessionContext;
use crate::state::AppState;

/// Payload sensitivity signal derived by the monitor, consumed by the proxy
/// handler to record observed data flows (blast-radius analysis).
#[derive(Clone, Copy, Default)]
pub struct FlowSignal {
    pub sensitive: bool,
    pub threat: bool,
}

/// Prompt security monitor middleware.
pub async fn monitor_layer(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let session_ctx = request.extensions().get::<SessionContext>().cloned();
    let body_bytes = request.extensions().get::<Bytes>().cloned();

    let path = request.uri().path().to_string();
    let mut signal = FlowSignal::default();

    // Scan request for threats
    if let Some(ref body) = body_bytes {
        if let Some((provider_name, provider)) = state.providers.resolve_from_path(&path) {
            if let Some(normalized) = provider.parse_request(body) {
                // Build full text for scanning
                let mut scan_text = String::new();
                for msg in &normalized.messages {
                    scan_text.push_str(&msg.content);
                    scan_text.push('\n');
                }

                let assessment = state
                    .security_monitor
                    .scan_request(&scan_text, normalized.system_prompt.as_deref());

                // Derive the flow-sensitivity signal (PII / data-exfiltration = sensitive).
                signal.threat = !assessment.threats.is_empty();
                signal.sensitive = assessment.threats.iter().any(|t| {
                    let c = format!("{:?}", t.category).to_lowercase();
                    c.contains("pii")
                        || c.contains("exfil")
                        || c.contains("data")
                        || c.contains("secret")
                });

                // Record the observed agent→provider data flow (blast-radius analysis),
                // whether or not it is ultimately blocked — a blocked sensitive attempt is
                // itself meaningful exposure signal.
                let agent = session_ctx
                    .as_ref()
                    .map(|c| c.agent_name.as_str())
                    .unwrap_or("default");
                state.store.record_flow(
                    qw_store::DEFAULT_TENANT,
                    agent,
                    provider_name,
                    signal.sensitive,
                    signal.threat,
                );

                if assessment.should_block {
                    let session_id = session_ctx
                        .as_ref()
                        .map(|c| c.session_id.as_str())
                        .unwrap_or("unknown");

                    for threat in &assessment.threats {
                        tracing::warn!(
                            session_id = %session_id,
                            category = ?threat.category,
                            severity = ?threat.severity,
                            pattern = %threat.pattern_name,
                            "Threat detected and blocked"
                        );

                        let _ = state
                            .audit_logger
                            .log(
                                session_id,
                                qw_audit::AuditEvent::ThreatBlocked {
                                    category: format!("{:?}", threat.category),
                                    severity: format!("{:?}", threat.severity),
                                    pattern: threat.pattern_name.clone(),
                                },
                            )
                            .await;
                    }

                    return GatewayError::ThreatDetected(format!(
                        "{} threat(s) detected: {}",
                        assessment.threats.len(),
                        assessment
                            .threats
                            .iter()
                            .map(|t| t.description.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ))
                    .into_response();
                }
            }
        }
    }

    request.extensions_mut().insert(signal);
    next.run(request).await
}
