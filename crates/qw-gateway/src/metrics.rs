//! Gateway self-observability — Prometheus metrics about QuantaWatch itself.
//!
//! The gateway is in-path on every LLM request, so operators need to see *its*
//! health, not just the posture of what it scans: request/error rates, latency
//! distribution, which upstream circuits are open, and how much the monitor is
//! actually blocking.
//!
//! Rendered in the Prometheus text exposition format (v0.0.4) directly — the
//! series set is small and fixed, so a client library would be more dependency
//! than it's worth.

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

/// Cumulative latency buckets, in seconds. Tuned for LLM calls (which are slow:
/// sub-second is fast, tens of seconds is normal for long completions).
const LATENCY_BUCKETS_SECS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

/// Escape a Prometheus label value (backslash, quote, newline).
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub struct Metrics {
    /// (provider, outcome) -> count
    proxy_requests: DashMap<(String, String), u64>,
    /// provider -> count of 5xx / transport failures
    upstream_errors: DashMap<String, u64>,
    /// threat category -> count
    threats: DashMap<String, u64>,
    /// Cumulative histogram buckets (+1 slot for +Inf).
    latency_buckets: Vec<AtomicU64>,
    latency_sum_millis: AtomicU64,
    latency_count: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            proxy_requests: DashMap::new(),
            upstream_errors: DashMap::new(),
            threats: DashMap::new(),
            latency_buckets: (0..=LATENCY_BUCKETS_SECS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            latency_sum_millis: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
        }
    }

    /// Record a completed proxy request. `status` is the upstream HTTP status.
    pub fn record_proxy(&self, provider: &str, status: u16, latency_ms: u64) {
        let outcome = match status {
            s if s < 400 => "success",
            s if s < 500 => "client_error",
            _ => "upstream_error",
        };
        *self
            .proxy_requests
            .entry((provider.to_string(), outcome.to_string()))
            .or_insert(0) += 1;
        if status >= 500 {
            *self
                .upstream_errors
                .entry(provider.to_string())
                .or_insert(0) += 1;
        }
        self.observe_latency(latency_ms);
    }

    /// Record an upstream failure where no HTTP response was received at all
    /// (transport error / retries exhausted).
    pub fn record_upstream_failure(&self, provider: &str, latency_ms: u64) {
        *self
            .proxy_requests
            .entry((provider.to_string(), "upstream_error".to_string()))
            .or_insert(0) += 1;
        *self
            .upstream_errors
            .entry(provider.to_string())
            .or_insert(0) += 1;
        self.observe_latency(latency_ms);
    }

    /// Record a request rejected because the provider's circuit was open.
    pub fn record_circuit_rejection(&self, provider: &str) {
        *self
            .proxy_requests
            .entry((provider.to_string(), "circuit_open".to_string()))
            .or_insert(0) += 1;
    }

    pub fn record_threat(&self, category: &str) {
        *self.threats.entry(category.to_string()).or_insert(0) += 1;
    }

    fn observe_latency(&self, ms: u64) {
        let secs = ms as f64 / 1000.0;
        // Cumulative: every bucket whose upper bound covers this observation.
        for (i, bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            if secs <= *bound {
                self.latency_buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf always counts.
        self.latency_buckets[LATENCY_BUCKETS_SECS.len()].fetch_add(1, Ordering::Relaxed);
        self.latency_sum_millis.fetch_add(ms, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Render this registry's series in the Prometheus text format.
    pub fn render(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP quantawatch_proxy_requests_total Proxied LLM requests by provider and outcome.\n");
        out.push_str("# TYPE quantawatch_proxy_requests_total counter\n");
        for e in self.proxy_requests.iter() {
            let (provider, outcome) = e.key();
            out.push_str(&format!(
                "quantawatch_proxy_requests_total{{provider=\"{}\",outcome=\"{}\"}} {}\n",
                escape(provider),
                escape(outcome),
                e.value()
            ));
        }

        out.push_str(
            "# HELP quantawatch_upstream_errors_total Upstream failures (5xx or transport).\n",
        );
        out.push_str("# TYPE quantawatch_upstream_errors_total counter\n");
        for e in self.upstream_errors.iter() {
            out.push_str(&format!(
                "quantawatch_upstream_errors_total{{provider=\"{}\"}} {}\n",
                escape(e.key()),
                e.value()
            ));
        }

        out.push_str(
            "# HELP quantawatch_threats_detected_total Threats detected by the security monitor.\n",
        );
        out.push_str("# TYPE quantawatch_threats_detected_total counter\n");
        for e in self.threats.iter() {
            out.push_str(&format!(
                "quantawatch_threats_detected_total{{category=\"{}\"}} {}\n",
                escape(e.key()),
                e.value()
            ));
        }

        out.push_str("# HELP quantawatch_proxy_latency_seconds Proxy request latency.\n");
        out.push_str("# TYPE quantawatch_proxy_latency_seconds histogram\n");
        for (i, bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            out.push_str(&format!(
                "quantawatch_proxy_latency_seconds_bucket{{le=\"{}\"}} {}\n",
                bound,
                self.latency_buckets[i].load(Ordering::Relaxed)
            ));
        }
        out.push_str(&format!(
            "quantawatch_proxy_latency_seconds_bucket{{le=\"+Inf\"}} {}\n",
            self.latency_buckets[LATENCY_BUCKETS_SECS.len()].load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "quantawatch_proxy_latency_seconds_sum {}\n",
            self.latency_sum_millis.load(Ordering::Relaxed) as f64 / 1000.0
        ));
        out.push_str(&format!(
            "quantawatch_proxy_latency_seconds_count {}\n",
            self.latency_count.load(Ordering::Relaxed)
        ));

        out
    }
}

/// Render a single gauge line.
pub fn gauge(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
    ));
}

/// Render a labelled gauge line (help/type emitted by the caller).
pub fn labelled_gauge(
    out: &mut String,
    name: &str,
    label: &str,
    key: &str,
    value: impl std::fmt::Display,
) {
    out.push_str(&format!("{name}{{{label}=\"{}\"}} {value}\n", escape(key)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_requests_by_outcome() {
        let m = Metrics::new();
        m.record_proxy("openai", 200, 120);
        m.record_proxy("openai", 200, 80);
        m.record_proxy("openai", 401, 30);
        m.record_proxy("openai", 503, 5000);
        let out = m.render();
        assert!(out.contains(
            r#"quantawatch_proxy_requests_total{provider="openai",outcome="success"} 2"#
        ));
        assert!(out.contains(
            r#"quantawatch_proxy_requests_total{provider="openai",outcome="client_error"} 1"#
        ));
        assert!(out.contains(
            r#"quantawatch_proxy_requests_total{provider="openai",outcome="upstream_error"} 1"#
        ));
        // Only the 5xx counts as an upstream error; the 401 is the caller's fault.
        assert!(out.contains(r#"quantawatch_upstream_errors_total{provider="openai"} 1"#));
    }

    #[test]
    fn latency_buckets_are_cumulative() {
        let m = Metrics::new();
        m.record_proxy("anthropic", 200, 80); // 0.08s
        m.record_proxy("anthropic", 200, 300); // 0.3s
        let out = m.render();
        // 0.08 <= 0.1 -> only the first observation.
        assert!(out.contains(r#"quantawatch_proxy_latency_seconds_bucket{le="0.1"} 1"#));
        // Both are <= 0.5.
        assert!(out.contains(r#"quantawatch_proxy_latency_seconds_bucket{le="0.5"} 2"#));
        assert!(out.contains(r#"quantawatch_proxy_latency_seconds_bucket{le="+Inf"} 2"#));
        assert!(out.contains("quantawatch_proxy_latency_seconds_count 2"));
        assert!(out.contains("quantawatch_proxy_latency_seconds_sum 0.38"));
    }

    #[test]
    fn transport_failure_and_circuit_rejection_are_distinct_outcomes() {
        let m = Metrics::new();
        m.record_upstream_failure("ollama", 10_000);
        m.record_circuit_rejection("ollama");
        let out = m.render();
        assert!(out.contains(
            r#"quantawatch_proxy_requests_total{provider="ollama",outcome="upstream_error"} 1"#
        ));
        assert!(out.contains(
            r#"quantawatch_proxy_requests_total{provider="ollama",outcome="circuit_open"} 1"#
        ));
        // A rejected request never hit the upstream, so it must not add latency.
        assert!(out.contains("quantawatch_proxy_latency_seconds_count 1"));
    }

    #[test]
    fn threats_counted_by_category() {
        let m = Metrics::new();
        m.record_threat("prompt_injection");
        m.record_threat("prompt_injection");
        m.record_threat("pii_exposure");
        let out = m.render();
        assert!(
            out.contains(r#"quantawatch_threats_detected_total{category="prompt_injection"} 2"#)
        );
        assert!(out.contains(r#"quantawatch_threats_detected_total{category="pii_exposure"} 1"#));
    }

    #[test]
    fn label_values_are_escaped() {
        let m = Metrics::new();
        m.record_threat("we\"ird\\one");
        let out = m.render();
        assert!(out.contains(r#"category="we\"ird\\one""#));
    }

    #[test]
    fn empty_registry_still_renders_valid_help_and_type() {
        let out = Metrics::new().render();
        assert!(out.contains("# TYPE quantawatch_proxy_requests_total counter"));
        assert!(out.contains("quantawatch_proxy_latency_seconds_count 0"));
    }
}
