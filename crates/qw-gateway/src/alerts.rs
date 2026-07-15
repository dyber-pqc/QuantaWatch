//! Alerting: rule-driven notifications delivered to webhook / Slack channels.
//!
//! Alert events are persisted (tenant-scoped) in the SQLite store; this manager
//! handles the rules + HTTP fan-out to configured channels.

use std::sync::Arc;

use qw_store::Store;

// Alert data types live in qw-store (persistence owns them).
pub use qw_store::{AlertEvent, AlertSeverity};

use crate::config::{AlertChannelConfig, AlertConfig};

pub struct AlertManager {
    config: AlertConfig,
    http: reqwest::Client,
    store: Arc<Store>,
    /// In air-gapped mode alerts are still recorded, but never delivered
    /// outbound — no webhook or Slack call leaves the enclave.
    air_gapped: bool,
}

impl AlertManager {
    pub fn new(
        config: AlertConfig,
        http: reqwest::Client,
        store: Arc<Store>,
        air_gapped: bool,
    ) -> Self {
        Self {
            config,
            http,
            store,
            air_gapped,
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn config_thresholds(&self) -> (f64, bool, u32) {
        (
            self.config.posture_drop_threshold,
            self.config.alert_on_critical,
            self.config.cert_expiry_days,
        )
    }

    /// Public view of configured channels (no secrets — URLs are omitted).
    pub fn channels(&self) -> Vec<(String, String)> {
        self.config
            .channels
            .iter()
            .map(|c| (c.id.clone(), c.channel_type.clone()))
            .collect()
    }

    /// Record an alert (under `tenant`) and deliver it to channels that meet its severity floor.
    ///
    /// Air-gapped deployments still record every alert (visible in the UI and
    /// via the pull-based SIEM export); only outbound delivery is suppressed.
    pub async fn fire(&self, tenant: &str, mut event: AlertEvent) {
        if self.config.enabled && !self.air_gapped {
            let mut delivered = 0u32;
            for ch in &self.config.channels {
                let floor = ch
                    .min_severity
                    .as_deref()
                    .map(AlertSeverity::from_label)
                    .unwrap_or(AlertSeverity::Info);
                if event.severity >= floor && self.deliver(ch, &event).await {
                    delivered += 1;
                }
            }
            event.delivered = delivered;
        }

        tracing::info!(tenant, kind = %event.kind, severity = event.severity.label(), delivered = event.delivered, "alert fired");
        self.store.record_alert(tenant, &event);
    }

    async fn deliver(&self, ch: &AlertChannelConfig, event: &AlertEvent) -> bool {
        let body = match ch.channel_type.as_str() {
            "slack" => {
                let emoji = match event.severity {
                    AlertSeverity::Critical => ":rotating_light:",
                    AlertSeverity::Warning => ":warning:",
                    AlertSeverity::Info => ":information_source:",
                };
                serde_json::json!({
                    "text": format!("{emoji} *QuantaWatch — {}*\n{}", event.title, event.message)
                })
            }
            // Generic webhook (Teams/PagerDuty/email-gateways/etc.): full event JSON.
            _ => serde_json::to_value(event).unwrap_or_default(),
        };

        match self.http.post(&ch.url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => true,
            Ok(resp) => {
                tracing::warn!(channel = %ch.id, status = %resp.status(), "alert delivery failed");
                false
            }
            Err(e) => {
                tracing::warn!(channel = %ch.id, error = %e, "alert delivery error");
                false
            }
        }
    }

    pub fn recent(&self, tenant: &str, limit: usize) -> Vec<AlertEvent> {
        self.store.recent_alerts(tenant, limit)
    }
}
