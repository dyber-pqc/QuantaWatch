use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{Response, IntoResponse},
};
use std::collections::HashMap;

use qw_policy::RequestContext;
use crate::state::AppState;
use crate::error::GatewayError;
use crate::middleware::identity::SessionContext;

/// Policy enforcement middleware.
pub async fn policy_layer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let session_ctx = request.extensions().get::<SessionContext>().cloned();

    let (agent_name, session_id) = match &session_ctx {
        Some(ctx) => (ctx.agent_name.clone(), ctx.session_id.clone()),
        None => ("default".to_string(), "unknown".to_string()),
    };

    // Extract request info for policy evaluation
    let path = request.uri().path().to_string();
    let provider_name = state.providers.resolve_from_path(&path)
        .map(|(name, _)| name.to_string())
        .unwrap_or_default();

    // Read body to parse request (we'll need to reconstruct the request)
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return GatewayError::Internal(format!("failed to read body: {e}")).into_response(),
    };

    // Parse request for model/tool info
    let (model, tools) = if let Some((_, provider)) = state.providers.resolve_from_path(&path) {
        if let Some(normalized) = provider.parse_request(&body_bytes) {
            let tool_names: Vec<String> = normalized.tools.iter().map(|t| t.name.clone()).collect();
            (normalized.model, tool_names)
        } else {
            (String::new(), vec![])
        }
    } else {
        (String::new(), vec![])
    };

    // Build policy context
    let client_ip = parts.headers
        .get("x-forwarded-for")
        .or_else(|| parts.headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let ctx = RequestContext {
        agent_name: agent_name.clone(),
        session_id: session_id.clone(),
        model: model.clone(),
        provider: provider_name.clone(),
        tools_requested: tools,
        client_ip,
        labels: HashMap::new(),
    };

    // Evaluate policy
    let policy_engine = state.policy_engine.read().await;
    let decision = policy_engine.evaluate(&ctx);
    drop(policy_engine);

    if !decision.is_allowed() {
        tracing::warn!(
            agent = %agent_name,
            model = %model,
            reason = %decision.reason,
            "Policy denied request"
        );

        // Log policy violation
        let _ = state.audit_logger.log(&session_id, qw_audit::AuditEvent::PolicyViolation {
            rule: decision.reason.clone(),
            reason: decision.reason.clone(),
            agent_name: agent_name.clone(),
        }).await;

        return GatewayError::PolicyDenied(decision.reason).into_response();
    }

    // Update session info
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        session.provider = provider_name;
        session.model = model;
        session.request_count += 1;
    }

    // Store body bytes and policy decision in extensions for downstream use
    let mut request = Request::from_parts(parts, axum::body::Body::from(body_bytes.clone()));
    request.extensions_mut().insert(session_ctx.unwrap_or(SessionContext {
        session_id,
        agent_name,
    }));
    request.extensions_mut().insert(PolicyResult {
        decision_reason: decision.reason,
        tools_allowed: decision.tools_allowed,
        tools_denied: decision.tools_denied,
    });
    request.extensions_mut().insert(body_bytes);

    next.run(request).await
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub decision_reason: String,
    pub tools_allowed: Vec<String>,
    pub tools_denied: Vec<String>,
}
