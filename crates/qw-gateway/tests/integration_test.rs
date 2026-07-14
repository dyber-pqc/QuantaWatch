use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt; // for oneshot

use qw_gateway::config::GatewayConfig;
use qw_gateway::router::build_router;
use qw_gateway::state::AppState;

/// Helper: build an AppState from defaults using temporary directories,
/// then return the Axum router ready for `oneshot` calls.
async fn test_app() -> axum::Router {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let key_dir = tmp.path().join("keys");
    let audit_dir = tmp.path().join("audit");

    std::fs::create_dir_all(&key_dir).unwrap();
    std::fs::create_dir_all(&audit_dir).unwrap();

    let mut config = GatewayConfig::default();
    config.identity.key_dir = key_dir.to_str().unwrap().to_string();
    config.audit.path = audit_dir.to_str().unwrap().to_string();
    // Use permissive default policy for tests
    config.policy.default = "allow".to_string();

    let state = AppState::new(config)
        .await
        .expect("failed to create AppState");

    // Leak the tempdir so it is not cleaned up while the router is alive.
    // In a real test suite you would store it alongside the router.
    std::mem::forget(tmp);

    build_router(state)
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_200() {
    let app = test_app().await;

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "quantawatch");
    assert!(json["version"].is_string());
}

// ---------------------------------------------------------------------------
// Provider-prefixed route (no upstream configured = error response)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_to_provider_path_runs_middleware() {
    let app = test_app().await;

    // POST to /v1/chat/completions -- the provider is registered (openai) but
    // the upstream is unreachable in tests, so we expect an error from the
    // proxy handler (upstream error or similar), NOT a 404 "route not found".
    // This proves the middleware pipeline (identity -> policy -> monitor)
    // executed successfully.
    let request = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // The middleware ran (identity layer assigns a session header).
    assert!(
        response.headers().contains_key("x-quantawatch-session"),
        "identity middleware should set x-quantawatch-session header"
    );

    // The status should be 502 Bad Gateway (upstream unreachable) rather
    // than 404 (route not found), proving the handler was reached.
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "expected 502 from unreachable upstream, got {}",
        response.status()
    );
}

// ---------------------------------------------------------------------------
// Admin API: GET /admin/api/sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_sessions_returns_json_array() {
    let app = test_app().await;

    let request = Request::builder()
        .uri("/admin/api/sessions")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // The response wraps sessions in an object: { "sessions": [...], "total": N }
    assert!(json["sessions"].is_array(), "sessions field should be a JSON array");
    assert!(json["total"].is_number(), "total field should be a number");
}

// ---------------------------------------------------------------------------
// Admin API: GET /admin/api/stats
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_stats_returns_expected_fields() {
    let app = test_app().await;

    let request = Request::builder()
        .uri("/admin/api/stats")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verify the expected stat fields are present
    assert!(
        json["active_sessions"].is_number(),
        "active_sessions should be a number"
    );
    assert!(
        json["total_requests"].is_number(),
        "total_requests should be a number"
    );
    assert!(
        json["total_tokens"].is_number(),
        "total_tokens should be a number"
    );
    assert!(
        json["providers"].is_array(),
        "providers should be an array"
    );
    assert!(
        json["gateway_fingerprint"].is_string(),
        "gateway_fingerprint should be a string (SHA3-256 hex)"
    );

    // The fingerprint is a 64-char hex string (SHA3-256)
    let fp = json["gateway_fingerprint"].as_str().unwrap();
    assert_eq!(fp.len(), 64, "fingerprint should be 64 hex chars");
}
