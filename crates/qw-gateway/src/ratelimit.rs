//! Per-client token-bucket rate limiting for the public listeners.
//!
//! A flood of requests from one source shouldn't be able to exhaust the
//! gateway (it is in-path on every LLM call) or brute-force the login endpoint.
//! Each client key gets an independent token bucket: it refills at a steady
//! rate up to a burst ceiling, and a request that finds the bucket empty is
//! rejected with HTTP 429.
//!
//! Login/auth endpoints get a separate, much tighter bucket than the general
//! API, layering on top of the per-account lockout in [`crate::auth`].
//!
//! Keys are derived from the client IP — the connection peer, or the
//! left-most `X-Forwarded-For` / `X-Real-IP` hop when the gateway is configured
//! to trust a fronting proxy. State is in-memory (per replica); behind a load
//! balancer each replica limits the share of traffic it sees.

use std::net::SocketAddr;
use std::time::Instant;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dashmap::DashMap;
use serde_json::json;

use crate::config::RateLimitConfig;
use crate::state::AppState;

/// A refilling token bucket. `tokens` and `last` advance lazily on each check
/// (no background timer), so an idle bucket costs nothing until touched.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// The rate-limiting decision for one request class.
struct Limit {
    /// Tokens added per second.
    refill_per_sec: f64,
    /// Maximum tokens (the burst ceiling).
    burst: f64,
}

/// Shared, in-memory rate-limiter state. One instance lives in [`AppState`].
pub struct RateLimiter {
    enabled: bool,
    api: Limit,
    login: Limit,
    /// Trust `X-Forwarded-For` / `X-Real-IP` for the client identity. Only turn
    /// on behind a proxy that overwrites these headers, or a client can spoof
    /// its key by sending its own.
    trust_forwarded: bool,
    /// key -> bucket. Keyed as `"{class}:{ip}"` so the api and login buckets for
    /// one IP are independent.
    buckets: DashMap<String, Bucket>,
    /// Ceiling on distinct keys; oldest-idle keys are pruned past this to bound
    /// memory against a churn of source IPs.
    max_keys: usize,
}

/// Which limit a request falls under.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Api,
    Login,
}

impl Class {
    fn as_str(self) -> &'static str {
        match self {
            Class::Api => "api",
            Class::Login => "login",
        }
    }
}

impl RateLimiter {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        // A per-minute budget spread over 60s; burst defaults to ~a page-load
        // fan-out so a normal dashboard open is never throttled.
        let api = Limit {
            refill_per_sec: (cfg.requests_per_minute as f64 / 60.0).max(0.001),
            burst: cfg.burst.max(1) as f64,
        };
        let login = Limit {
            refill_per_sec: (cfg.login_per_minute as f64 / 60.0).max(0.001),
            burst: cfg.login_burst.max(1) as f64,
        };
        Self {
            enabled: cfg.enabled,
            api,
            login,
            trust_forwarded: cfg.trust_forwarded_for,
            buckets: DashMap::new(),
            max_keys: 50_000,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn limit_for(&self, class: Class) -> &Limit {
        match class {
            Class::Api => &self.api,
            Class::Login => &self.login,
        }
    }

    /// Consume one token for `key` in `class`. Returns `true` if allowed.
    /// `now` is injected so tests are deterministic.
    fn check_at(&self, class: Class, ip: &str, now: Instant) -> bool {
        if !self.enabled {
            return true;
        }
        let limit = self.limit_for(class);
        let key = format!("{}:{}", class.as_str(), ip);

        // Opportunistic memory bound: if the table has grown large, drop keys
        // that have had time to fully refill (i.e. are back at capacity and
        // idle), which are safe to forget.
        if self.buckets.len() > self.max_keys {
            let idle_secs = limit.burst / limit.refill_per_sec;
            self.buckets
                .retain(|_, b| now.duration_since(b.last).as_secs_f64() < idle_secs);
        }

        let mut bucket = self.buckets.entry(key).or_insert_with(|| Bucket {
            tokens: limit.burst,
            last: now,
        });
        // Refill for the elapsed time, capped at the burst ceiling.
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * limit.refill_per_sec).min(limit.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Consume one token for `key` in `class` at the current time.
    pub fn check(&self, class: Class, ip: &str) -> bool {
        self.check_at(class, ip, Instant::now())
    }
}

/// Classify a request path into the tighter login bucket or the general API one.
fn classify(path: &str) -> Class {
    if path.ends_with("/api/auth/login") || path.contains("/api/auth/oidc/") {
        Class::Login
    } else {
        Class::Api
    }
}

/// Resolve the client IP for rate-limiting. Prefers a trusted forwarded header,
/// then the connection peer, then a fixed fallback bucket so a request with no
/// resolvable IP is still limited (as a group) rather than exempt.
fn client_ip(req: &Request, trust_forwarded: bool) -> String {
    if trust_forwarded {
        if let Some(xff) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(first) = xff.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
        if let Some(xr) = req
            .headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
        {
            let ip = xr.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Axum middleware: enforce the per-client rate limit, emitting 429 with a
/// `Retry-After` header when the bucket is empty.
pub async fn rate_limit_layer(
    State(state): State<AppState>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let limiter = &state.rate_limiter;
    if !limiter.enabled() {
        return next.run(req).await;
    }

    // Health checks must never be throttled (liveness/readiness probes).
    let path = req.uri().path();
    if path.ends_with("/health") || path.ends_with("/api/health") {
        return next.run(req).await;
    }

    let class = classify(path);
    let ip = client_ip(&req, limiter.trust_forwarded);
    if limiter.check(class, &ip) {
        next.run(req).await
    } else {
        state.metrics.record_rate_limited(class.as_str());
        tracing::debug!(client = %ip, path = %path, "rate limited (429)");
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            Json(json!({ "error": "rate limit exceeded; slow down and retry" })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            requests_per_minute: 600, // 10/s
            burst: 5,
            login_per_minute: 60, // 1/s
            login_burst: 2,
            trust_forwarded_for: false,
        }
    }

    #[test]
    fn allows_up_to_burst_then_blocks() {
        let rl = RateLimiter::new(&cfg());
        let t = Instant::now();
        // Burst of 5 all pass on the same instant.
        for _ in 0..5 {
            assert!(rl.check_at(Class::Api, "1.2.3.4", t));
        }
        // 6th on the same instant is over budget.
        assert!(!rl.check_at(Class::Api, "1.2.3.4", t));
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(&cfg());
        let t = Instant::now();
        for _ in 0..5 {
            assert!(rl.check_at(Class::Api, "ip", t));
        }
        assert!(!rl.check_at(Class::Api, "ip", t));
        // 10/s refill => 0.2s buys back two tokens.
        let later = t + std::time::Duration::from_millis(200);
        assert!(rl.check_at(Class::Api, "ip", later));
        assert!(rl.check_at(Class::Api, "ip", later));
        assert!(!rl.check_at(Class::Api, "ip", later));
    }

    #[test]
    fn buckets_are_per_ip_and_per_class() {
        let rl = RateLimiter::new(&cfg());
        let t = Instant::now();
        for _ in 0..5 {
            assert!(rl.check_at(Class::Api, "a", t));
        }
        // A different IP is unaffected.
        assert!(rl.check_at(Class::Api, "b", t));
        // The login bucket for the same IP is independent (and tighter: burst 2).
        assert!(rl.check_at(Class::Login, "a", t));
        assert!(rl.check_at(Class::Login, "a", t));
        assert!(!rl.check_at(Class::Login, "a", t));
    }

    #[test]
    fn disabled_always_allows() {
        let mut c = cfg();
        c.enabled = false;
        let rl = RateLimiter::new(&c);
        let t = Instant::now();
        for _ in 0..1000 {
            assert!(rl.check_at(Class::Login, "x", t));
        }
    }

    #[test]
    fn login_endpoints_classify_as_login() {
        assert!(matches!(classify("/api/auth/login"), Class::Login));
        assert!(matches!(classify("/api/auth/oidc/callback"), Class::Login));
        assert!(matches!(classify("/api/scans"), Class::Api));
    }
}
