use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt; // for oneshot

use qw_gateway::config::GatewayConfig;
use qw_gateway::router::{build_admin_router, build_router};
use qw_gateway::state::AppState;

/// Helper: build an AppState from defaults, applying `tweak` to the config
/// before initialization. Uses temporary directories isolated per test.
async fn test_state_with(tweak: impl FnOnce(&mut GatewayConfig)) -> AppState {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let key_dir = tmp.path().join("keys");
    let audit_dir = tmp.path().join("audit");

    std::fs::create_dir_all(&key_dir).unwrap();
    std::fs::create_dir_all(&audit_dir).unwrap();

    let mut config = GatewayConfig::default();
    config.identity.key_dir = key_dir.to_str().unwrap().to_string();
    config.audit.path = audit_dir.to_str().unwrap().to_string();
    // Isolate the SQLite store per test so parallel tests don't race on a
    // shared ./scans/quantawatch.db (and don't pollute the repo).
    config.scanner.store_path = tmp.path().to_str().unwrap().to_string();
    // Use permissive default policy for tests
    config.policy.default = "allow".to_string();
    tweak(&mut config);

    // Box the initializer future onto the heap: AppState::new generates
    // ML-DSA/ML-KEM keypairs (large stack arrays), and in debug builds the
    // combined future can overflow the test thread's stack if polled inline.
    let state = Box::pin(AppState::new(config))
        .await
        .expect("failed to create AppState");

    // Leak the tempdir so it is not cleaned up while the router is alive.
    // In a real test suite you would store it alongside the router.
    std::mem::forget(tmp);

    state
}

/// Helper: build an AppState from defaults using temporary directories.
async fn test_state() -> AppState {
    test_state_with(|_| {}).await
}

/// Helper: an Axum router over a fresh AppState, ready for `oneshot` calls.
async fn test_app() -> axum::Router {
    build_router(test_state().await)
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

    // The proxy handler was reached (not a 404 route-miss): with no API key
    // configured in the test it rejects with 401 before attempting the
    // upstream, which still proves the middleware pipeline + handler ran.
    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "proxy handler should be reached, got a 404 route-miss"
    );
}

// ---------------------------------------------------------------------------
// Data-path resilience: an open circuit fast-fails with 503
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_circuit_fast_fails_with_503() {
    let state = test_state().await;

    // Trip the openai upstream's circuit by recording enough failures. The
    // breaker registry is stable, so the proxy handler will observe the same
    // open breaker for this provider.
    let breaker = state.resilience.breaker("openai");
    for _ in 0..state.config.resilience.circuit_failure_threshold {
        breaker.record_failure();
    }

    let app = build_router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Fast-fail without touching the upstream at all.
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "open circuit should return 503, got {}",
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
    assert!(
        json["sessions"].is_array(),
        "sessions field should be a JSON array"
    );
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
    assert!(json["providers"].is_array(), "providers should be an array");
    assert!(
        json["gateway_fingerprint"].is_string(),
        "gateway_fingerprint should be a string (SHA3-256 hex)"
    );

    // The fingerprint is a 64-char hex string (SHA3-256)
    let fp = json["gateway_fingerprint"].as_str().unwrap();
    assert_eq!(fp.len(), 64, "fingerprint should be 64 hex chars");
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limit_returns_429_after_burst() {
    // Tiny budget so a handful of requests trips the limiter. oneshot has no
    // ConnectInfo, so every request shares the "api:unknown" bucket.
    let state = test_state_with(|c| {
        c.rate_limit.enabled = true;
        c.rate_limit.requests_per_minute = 60; // ~1/s refill
        c.rate_limit.burst = 3;
    })
    .await;
    let app = build_admin_router(state);

    // An open (no-auth) admin endpoint that returns 200 under budget.
    let hit = |app: axum::Router| async move {
        app.oneshot(
            Request::builder()
                .uri("/api/auth/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    };

    // First 3 (the burst) pass; the 4th is throttled.
    assert_eq!(hit(app.clone()).await, StatusCode::OK);
    assert_eq!(hit(app.clone()).await, StatusCode::OK);
    assert_eq!(hit(app.clone()).await, StatusCode::OK);
    assert_eq!(hit(app.clone()).await, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn rate_limit_exempts_health() {
    let state = test_state_with(|c| {
        c.rate_limit.enabled = true;
        c.rate_limit.requests_per_minute = 60;
        c.rate_limit.burst = 1;
    })
    .await;
    let app = build_admin_router(state);

    // Health is never throttled, even well past the burst.
    for _ in 0..5 {
        let status = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::OK);
    }
}
