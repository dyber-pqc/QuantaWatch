//! Data-path resilience for the in-path proxy.
//!
//! The gateway sits on the critical path of every LLM request, so a degraded
//! upstream must not become a degraded product. This module provides:
//!
//! * a per-provider **circuit breaker** that fast-fails once an upstream is
//!   clearly down, instead of making every caller wait out the full timeout,
//! * a conservative **retry** helper that only retries failures which provably
//!   never reached the upstream (so a non-idempotent completion is never
//!   duplicated), with exponential backoff.
//!
//! Timeouts themselves are applied on the shared `reqwest::Client` (see
//! `state.rs`), configured from the same [`ResilienceConfig`].

use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::config::ResilienceConfig;

/// Circuit state for a single upstream provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Healthy — requests flow normally.
    Closed,
    /// Tripped — requests are rejected until the cooldown elapses.
    Open,
    /// Cooldown elapsed — a probe is allowed; success closes, failure re-opens.
    HalfOpen,
}

struct Inner {
    consecutive_failures: u32,
    state: CircuitState,
    open_until: Option<Instant>,
}

/// A per-provider circuit breaker. Cheap to clone via `Arc`.
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown: Duration,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cooldown,
            inner: Mutex::new(Inner {
                consecutive_failures: 0,
                state: CircuitState::Closed,
                open_until: None,
            }),
        }
    }

    /// Whether a request may proceed right now. Transitions `Open -> HalfOpen`
    /// once the cooldown has elapsed and lets a probe through.
    pub fn allow(&self) -> bool {
        self.allow_at(Instant::now())
    }

    fn allow_at(&self, now: Instant) -> bool {
        let mut b = self.inner.lock().unwrap();
        match b.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => match b.open_until {
                Some(until) if now >= until => {
                    b.state = CircuitState::HalfOpen;
                    true
                }
                Some(_) => false,
                None => true,
            },
        }
    }

    /// Record a healthy response — resets the failure count and closes the circuit.
    pub fn record_success(&self) {
        let mut b = self.inner.lock().unwrap();
        b.consecutive_failures = 0;
        b.state = CircuitState::Closed;
        b.open_until = None;
    }

    /// Record a failure (transport error or upstream 5xx). Crossing the
    /// threshold — or failing a half-open probe — opens the circuit.
    pub fn record_failure(&self) {
        self.record_failure_at(Instant::now());
    }

    fn record_failure_at(&self, now: Instant) {
        let mut b = self.inner.lock().unwrap();
        b.consecutive_failures += 1;
        if b.state == CircuitState::HalfOpen || b.consecutive_failures >= self.failure_threshold {
            b.state = CircuitState::Open;
            b.open_until = Some(now + self.cooldown);
        }
    }

    pub fn state(&self) -> CircuitState {
        self.inner.lock().unwrap().state
    }
}

/// Owns the resilience config plus one circuit breaker per provider.
pub struct Resilience {
    pub config: ResilienceConfig,
    breakers: DashMap<String, std::sync::Arc<CircuitBreaker>>,
}

impl Resilience {
    pub fn new(config: ResilienceConfig) -> Self {
        Self {
            config,
            breakers: DashMap::new(),
        }
    }

    /// Get (or lazily create) the circuit breaker for a provider.
    pub fn breaker(&self, provider: &str) -> std::sync::Arc<CircuitBreaker> {
        if let Some(b) = self.breakers.get(provider) {
            return b.clone();
        }
        self.breakers
            .entry(provider.to_string())
            .or_insert_with(|| {
                std::sync::Arc::new(CircuitBreaker::new(
                    self.config.circuit_failure_threshold,
                    Duration::from_secs(self.config.circuit_cooldown_secs),
                ))
            })
            .clone()
    }

    /// Send a request, retrying only failures that provably never reached the
    /// upstream (connect errors — and timeouts iff `retry_on_timeout`). This
    /// keeps non-idempotent completions from being duplicated. Returns the
    /// upstream response or the last transport error.
    pub async fn send_with_retry(
        &self,
        client: &reqwest::Client,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut attempt: u32 = 0;
        loop {
            // Clone for this attempt so `request` survives to the next iteration.
            // Bodies here are in-memory bytes, so try_clone always succeeds; the
            // fallback just single-shots if a body were ever unclonable.
            let Some(this) = request.try_clone() else {
                return client.execute(request).await;
            };
            match client.execute(this).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    let retryable =
                        e.is_connect() || (self.config.retry_on_timeout && e.is_timeout());
                    if retryable && attempt < self.config.max_retries {
                        let backoff = self.config.retry_backoff_ms.saturating_mul(1u64 << attempt);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(3, Duration::from_secs(30))
    }

    #[test]
    fn closed_allows_and_stays_closed_on_success() {
        let b = breaker();
        assert_eq!(b.state(), CircuitState::Closed);
        assert!(b.allow());
        b.record_success();
        assert_eq!(b.state(), CircuitState::Closed);
    }

    #[test]
    fn opens_after_threshold_consecutive_failures() {
        let b = breaker();
        b.record_failure();
        b.record_failure();
        assert_eq!(
            b.state(),
            CircuitState::Closed,
            "below threshold stays closed"
        );
        b.record_failure(); // 3rd failure hits threshold
        assert_eq!(b.state(), CircuitState::Open);
        assert!(!b.allow(), "open circuit rejects requests");
    }

    #[test]
    fn success_resets_failure_streak() {
        let b = breaker();
        b.record_failure();
        b.record_failure();
        b.record_success();
        b.record_failure();
        b.record_failure();
        assert_eq!(b.state(), CircuitState::Closed, "streak reset by success");
    }

    #[test]
    fn open_transitions_to_halfopen_after_cooldown() {
        let b = CircuitBreaker::new(1, Duration::from_secs(30));
        let now = Instant::now();
        b.record_failure_at(now);
        assert_eq!(b.state(), CircuitState::Open);
        // Before cooldown: still rejected.
        assert!(!b.allow_at(now + Duration::from_secs(10)));
        // After cooldown: a probe is allowed and state is half-open.
        assert!(b.allow_at(now + Duration::from_secs(31)));
        assert_eq!(b.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn halfopen_failure_reopens_immediately() {
        let b = CircuitBreaker::new(3, Duration::from_secs(30));
        let now = Instant::now();
        // Force open, then reach half-open.
        b.record_failure_at(now);
        b.record_failure_at(now);
        b.record_failure_at(now);
        assert!(b.allow_at(now + Duration::from_secs(31)));
        assert_eq!(b.state(), CircuitState::HalfOpen);
        // A single failed probe re-opens even though it's one failure.
        b.record_failure_at(now + Duration::from_secs(31));
        assert_eq!(b.state(), CircuitState::Open);
    }

    #[test]
    fn halfopen_success_closes() {
        let b = CircuitBreaker::new(1, Duration::from_secs(5));
        let now = Instant::now();
        b.record_failure_at(now);
        assert!(b.allow_at(now + Duration::from_secs(6)));
        b.record_success();
        assert_eq!(b.state(), CircuitState::Closed);
        assert!(b.allow());
    }

    #[test]
    fn registry_returns_stable_breaker_per_provider() {
        let r = Resilience::new(ResilienceConfig::default());
        let a1 = r.breaker("anthropic");
        let a2 = r.breaker("anthropic");
        let o1 = r.breaker("openai");
        assert!(
            std::sync::Arc::ptr_eq(&a1, &a2),
            "same provider -> same breaker"
        );
        assert!(
            !std::sync::Arc::ptr_eq(&a1, &o1),
            "different provider -> different breaker"
        );
    }
}
