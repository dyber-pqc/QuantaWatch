use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use bytes::Bytes;
use serde_json::json;
use std::time::Instant;

use qw_crypto::sha3_256_hex;

use crate::error::GatewayError;
use crate::middleware::identity::SessionContext;
use crate::middleware::policy::PolicyResult;
use crate::middleware::{identity, monitor, policy};
use crate::state::AppState;

/// Proxy routes (provider-facing). Generic over state until composed.
fn proxy_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/v1/messages", post(proxy_handler))
        .route("/v1/chat/completions", post(proxy_handler))
        .route("/v1/chat", post(proxy_handler))
        .route("/api/chat", post(proxy_handler))
        .route("/api/generate", post(proxy_handler))
        // Provider-prefixed routes
        .route("/claude/{*rest}", any(proxy_handler))
        .route("/openai/{*rest}", any(proxy_handler))
        .route("/ollama/{*rest}", any(proxy_handler))
        .route("/azure/{*rest}", any(proxy_handler))
        .route("/azure-openai/{*rest}", any(proxy_handler))
        .route("/cohere/{*rest}", any(proxy_handler))
        // Middleware layers (applied in reverse order)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            monitor::monitor_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            policy::policy_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            identity::identity_layer,
        ))
}

/// RBAC + authentication middleware for the admin API. No-op when auth is
/// disabled. Exempts the login endpoint and health check.
async fn auth_layer(
    State(state): State<AppState>,
    mut req: Request,
    next: axum::middleware::Next,
) -> Response {
    if !state.auth_manager.enabled() {
        return next.run(req).await;
    }

    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Always-open endpoints (login, SSO flow, health, public auth config, inbound webhooks).
    if path.ends_with("/api/auth/login")
        || path.ends_with("/api/health")
        || path.ends_with("/api/auth/config")
        || path.contains("/api/auth/oidc/")
        || path.contains("/api/webhooks/")
    {
        return next.run(req).await;
    }

    // Extract credential: Authorization: Bearer <t>, or X-API-Key.
    let credential = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });

    let ctx = credential.and_then(|c| state.auth_manager.validate(&c));
    match ctx {
        None => (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "authentication required" })),
        )
            .into_response(),
        Some(mut ctx) => {
            let required = crate::auth::required_role(&method, &path);
            if ctx.role < required {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "error": "insufficient role",
                        "required": required.label(),
                        "have": ctx.role.label(),
                    })),
                )
                    .into_response();
            }
            // Multi-tenant switching: an admin may view another org's data by
            // sending X-Tenant. Non-admins are always pinned to their own org.
            if ctx.role == crate::auth::Role::Admin {
                if let Some(t) = req.headers().get("x-tenant").and_then(|v| v.to_str().ok()) {
                    if !t.is_empty() {
                        ctx.org = t.to_string();
                    }
                }
            }
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
    }
}

/// Admin/API routes (dashboard-facing), served at `/api/*`.
fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/api/health", get(health))
        // Prometheus scrape target. Behind auth like every other admin route —
        // scrape with an API key (Prometheus `authorization` credentials).
        .route("/metrics", get(crate::admin::metrics_api::get_metrics))
        .route("/api/auth/login", post(crate::admin::auth_api::login))
        .route("/api/auth/logout", post(crate::admin::auth_api::logout))
        .route("/api/auth/me", get(crate::admin::auth_api::me))
        .route("/api/auth/config", get(crate::admin::auth_api::auth_config))
        .route("/api/auth/oidc/login", get(crate::oidc::login))
        .route("/api/auth/oidc/callback", get(crate::oidc::callback))
        .route("/api/tenants", get(crate::admin::auth_api::list_tenants))
        .route("/api/sessions", get(crate::admin::sessions::list_sessions))
        .route(
            "/api/sessions/{id}",
            get(crate::admin::sessions::get_session),
        )
        .route(
            "/api/onboarding/scan",
            post(crate::admin::onboarding::onboarding_scan),
        )
        .route("/api/audit", get(crate::admin::audit_api::list_audit))
        .route(
            "/api/audit/export",
            get(crate::admin::audit_api::export_audit),
        )
        .route(
            "/api/audit/verify",
            post(crate::admin::audit_api::verify_audit),
        )
        .route("/api/config", get(crate::admin::config_api::get_config))
        .route("/api/stats", get(crate::admin::stats::get_stats))
        // Agent-aware posture
        .route("/api/agents", get(crate::admin::agents::list_agents))
        // Quantum attack-path engine (crypto security graph)
        .route(
            "/api/attack-paths",
            get(crate::admin::graph::get_attack_paths),
        )
        .route(
            "/api/attack-paths/simulate",
            post(crate::admin::graph::simulate),
        )
        .route(
            "/api/attack-paths/timeline",
            get(crate::admin::graph::get_timeline),
        )
        .route(
            "/api/attack-paths/{id}/remediate",
            post(crate::admin::graph::remediate_path),
        )
        // Asset inventory (agentless connectors)
        .route("/api/assets", get(crate::admin::assets_api::list_assets))
        .route(
            "/api/assets/sync",
            post(crate::admin::assets_api::sync_assets),
        )
        // Executive board report + signed evidence pack
        .route("/api/report/board", get(crate::admin::report::board_report))
        .route("/api/evidence", get(crate::admin::evidence::evidence_pack))
        // Posture SLOs / policy-as-code (CI gate via ?gate=1)
        .route("/api/slos", get(crate::admin::slos::get_slos))
        .route(
            "/api/slos/history",
            get(crate::admin::slos::get_slo_history),
        )
        .route(
            "/api/governance",
            get(crate::admin::governance::get_governance),
        )
        .route(
            "/api/governance/history",
            get(crate::admin::governance::get_governance_history),
        )
        // Compliance & migration
        .route(
            "/api/compliance",
            get(crate::admin::compliance::get_compliance),
        )
        .route(
            "/api/compliance/report",
            get(crate::admin::compliance::get_report),
        )
        // Alerts
        .route("/api/alerts", get(crate::admin::alerts_api::list_alerts))
        .route(
            "/api/alerts/test",
            post(crate::admin::alerts_api::test_alert),
        )
        // Posture & CBOM
        .route("/api/posture", get(crate::admin::posture::get_posture))
        .route(
            "/api/posture/history",
            get(crate::admin::posture::get_posture_history),
        )
        .route("/api/cbom", get(crate::admin::cbom::get_cbom))
        .route(
            "/api/cbom/attestation",
            get(crate::admin::cbom::get_attestation),
        )
        .route("/api/cbom/download", get(crate::admin::cbom::download_cbom))
        .route(
            "/api/cbom/components",
            get(crate::admin::cbom::list_components),
        )
        .route("/api/cbom/services", get(crate::admin::cbom::list_services))
        // Scanning
        .route("/api/scans", get(crate::admin::scans::list_scans))
        .route("/api/scans", post(crate::admin::scans::trigger_scan))
        .route("/api/scans/{id}", get(crate::admin::scans::get_scan))
        .route("/api/findings", get(crate::admin::scans::list_all_findings))
        // Integrations
        .route(
            "/api/integrations",
            get(crate::admin::integrations_api::list_integrations),
        )
        .route(
            "/api/integrations/{id}/test",
            post(crate::admin::integrations_api::test_integration),
        )
        .route(
            "/api/integrations/{id}/sync",
            post(crate::admin::integrations_api::sync_integration),
        )
        .route(
            "/api/integrations/{id}/scan",
            post(crate::admin::integrations_api::scan_integration),
        )
        .route(
            "/api/integrations/{id}/register-webhook",
            post(crate::admin::integrations_api::register_webhook),
        )
        .route(
            "/api/findings/{id}/remediate",
            post(crate::admin::remediation::remediate),
        )
        .route(
            "/api/findings/{id}/plan",
            get(crate::admin::remediation::get_migration_plan),
        )
        .route(
            "/api/remediations/plans",
            get(crate::admin::remediation::list_migration_plans),
        )
        .route("/api/risk", get(crate::admin::remediation::get_risk))
        .route(
            "/api/remediations",
            get(crate::admin::remediation::list_remediations),
        )
        .route(
            "/api/remediations/sync",
            post(crate::admin::remediation::sync_remediations),
        )
        // Inbound webhooks (push status)
        .route("/api/webhooks/github", post(crate::admin::webhooks::github))
        .route("/api/webhooks/jira", post(crate::admin::webhooks::jira))
        .route("/api/webhooks/linear", post(crate::admin::webhooks::linear))
}

/// Combined router: proxy routes plus admin routes nested under `/admin`.
/// Used by integration tests and as a single-port fallback.
pub fn build_router(state: AppState) -> Router {
    let admin = admin_routes().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_layer,
    ));
    Router::new()
        .merge(proxy_routes(state.clone()))
        .nest("/admin", admin)
        .layer(tower_http::cors::CorsLayer::permissive())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Proxy-only router for the provider-facing listener.
pub fn build_proxy_router(state: AppState) -> Router {
    Router::new()
        .merge(proxy_routes(state.clone()))
        .layer(tower_http::cors::CorsLayer::permissive())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Admin-only router for the dashboard-facing listener (serves `/api/*`).
pub fn build_admin_router(state: AppState) -> Router {
    admin_routes()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_layer,
        ))
        .layer(tower_http::cors::CorsLayer::permissive())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "quantawatch",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn proxy_handler(State(state): State<AppState>, request: Request) -> Response {
    let start = Instant::now();
    let path = request.uri().path().to_string();

    // Get session context
    let session_ctx = request
        .extensions()
        .get::<SessionContext>()
        .cloned()
        .unwrap_or(SessionContext {
            session_id: "unknown".to_string(),
            agent_name: "default".to_string(),
        });
    let policy_result = request.extensions().get::<PolicyResult>().cloned();
    let body_bytes = request.extensions().get::<Bytes>().cloned();

    // Resolve provider
    let (provider_name, provider) = match state.providers.resolve_from_path(&path) {
        Some(p) => p,
        None => {
            return GatewayError::ProviderNotFound(format!("no provider for path: {path}"))
                .into_response()
        }
    };

    // Get the request body
    let body = match body_bytes {
        Some(b) => b,
        None => {
            // Body wasn't cached by policy middleware, read it now
            let (_, body) = request.into_parts();
            match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    return GatewayError::Internal(format!("failed to read body: {e}"))
                        .into_response()
                }
            }
        }
    };

    let prompt_hash = sha3_256_hex(&body);

    // Parse for audit info
    let normalized = provider.parse_request(&body);
    let model = normalized
        .as_ref()
        .map(|n| n.model.clone())
        .unwrap_or_default();
    let tools_requested: Vec<String> = normalized
        .as_ref()
        .map(|n| n.tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();

    // Build upstream URL
    let upstream_url = provider.build_upstream_url(&path);

    // Circuit breaker: if this provider's upstream is already known-down, fail
    // fast with 503 instead of making the caller wait out the full timeout.
    let breaker = state.resilience.breaker(provider_name);
    if !breaker.allow() {
        tracing::warn!(provider = %provider_name, "upstream circuit open; fast-failing");
        state.metrics.record_circuit_rejection(provider_name);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "upstream temporarily unavailable (circuit open)",
                "provider": provider_name,
                "retryAfterSecs": state.config.resilience.circuit_cooldown_secs,
            })),
        )
            .into_response();
    }

    // Build the upstream request.
    let mut req_builder = state
        .http_client
        .post(&upstream_url)
        .body(body.to_vec())
        .header("content-type", "application/json");
    if let Some((header, value)) = provider.api_key_header() {
        req_builder = req_builder.header(header, &value);
    }
    if provider_name == "anthropic" {
        req_builder = req_builder.header("anthropic-version", "2023-06-01");
    }
    let upstream_req = match req_builder.build() {
        Ok(r) => r,
        Err(e) => {
            return GatewayError::Internal(format!("failed to build upstream request: {e}"))
                .into_response()
        }
    };

    // Send with retry (transport failures only) and record the outcome so the
    // breaker can trip on sustained upstream failure.
    let upstream_response = match state
        .resilience
        .send_with_retry(&state.http_client, upstream_req)
        .await
    {
        Ok(r) => {
            // Upstream 5xx counts as an upstream-health failure; 4xx does not
            // (that's the caller's request, not a sick upstream).
            if r.status().is_server_error() {
                breaker.record_failure();
            } else {
                breaker.record_success();
            }
            r
        }
        Err(e) => {
            breaker.record_failure();
            state
                .metrics
                .record_upstream_failure(provider_name, start.elapsed().as_millis() as u64);
            tracing::error!(error = %e, provider = %provider_name, "Upstream request failed after retries");
            return GatewayError::UpstreamError(format!("{e}")).into_response();
        }
    };

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();
    let response_body = match upstream_response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return GatewayError::UpstreamError(format!("failed to read response: {e}"))
                .into_response()
        }
    };

    let response_hash = sha3_256_hex(&response_body);
    let latency_ms = start.elapsed().as_millis() as u64;
    state
        .metrics
        .record_proxy(provider_name, status.as_u16(), latency_ms);

    // Scan response for threats (if configured)
    let mut threats_detected = 0u32;
    if state.config.monitor.scan_responses {
        if let Some(text) = provider.extract_response_text(&response_body) {
            let assessment = state.security_monitor.scan_response(&text);
            threats_detected = assessment.threats.len() as u32;
            if !assessment.threats.is_empty() {
                for threat in &assessment.threats {
                    state
                        .metrics
                        .record_threat(&format!("{:?}", threat.category).to_lowercase());
                    tracing::warn!(
                        session_id = %session_ctx.session_id,
                        category = ?threat.category,
                        severity = ?threat.severity,
                        "Threat detected in response"
                    );
                }
            }
        }
    }

    // Check for tool calls in response
    let tool_calls = provider.extract_tool_calls(&response_body);
    let (tools_allowed, tools_denied) = if let Some(ref pr) = policy_result {
        (pr.tools_allowed.clone(), pr.tools_denied.clone())
    } else {
        (tool_calls.clone(), vec![])
    };

    // Audit log (async, non-blocking)
    let _ = state
        .audit_logger
        .log(
            &session_ctx.session_id,
            qw_audit::AuditEvent::RequestProcessed {
                provider: provider_name.to_string(),
                model,
                prompt_hash,
                response_hash,
                policy_decision: policy_result
                    .map(|p| p.decision_reason)
                    .unwrap_or_else(|| "allowed".to_string()),
                tools_requested,
                tools_allowed,
                tools_denied,
                threats_detected,
                latency_ms,
            },
        )
        .await;

    // Build response
    let mut response =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));

    // Copy relevant headers from upstream
    for (key, value) in response_headers.iter() {
        if key != "transfer-encoding" {
            response = response.header(key, value);
        }
    }

    response
        .body(axum::body::Body::from(response_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
