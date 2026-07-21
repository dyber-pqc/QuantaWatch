//! Background tasks: startup scanning, scheduled re-scans, and posture snapshots.

use std::time::Duration;

use qw_cbom::{PostureEngine, PostureSnapshot, ProviderCryptoInfo};
use qw_scanner::{PqcStatus, ScanTarget};

use crate::state::AppState;

/// Spawn all background tasks. Returns immediately; tasks run on the tokio runtime.
pub fn spawn(state: AppState) {
    // Initial scan shortly after startup so the dashboard has data immediately.
    if state.config.scanner.auto_scan_on_start {
        let s = state.clone();
        tokio::spawn(async move {
            // Brief delay so the server is listening first.
            tokio::time::sleep(Duration::from_secs(2)).await;
            // Discover + scan the external asset inventory first, so the graph
            // and posture reflect full infrastructure, not just AI providers.
            if !s.config.assets.is_empty() || !s.config.connectors.is_empty() {
                crate::assets::sync_assets(&s, qw_store::DEFAULT_TENANT).await;
            }
            run_full_scan(&s, qw_store::DEFAULT_TENANT, "startup").await;
        });
    }

    // Periodic cleanup of expired auth sessions / OIDC states. Validation
    // already drops expired sessions lazily; this reaps ones never presented
    // again so the tables don't grow unbounded. Cheap; every 15 minutes.
    if state.config.auth.enabled {
        let s = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(900));
            ticker.tick().await; // skip the immediate first tick
            loop {
                ticker.tick().await;
                s.auth_manager.purge_expired();
            }
        });
    }

    // Scheduled re-scan loop — runs across ALL tenants so every org gets
    // continuous monitoring, drift detection, and ticket status sync.
    let interval = state.config.schedule.scan_interval_secs;
    if interval > 0 {
        let s = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval));
            ticker.tick().await; // skip the immediate first tick
            let rediscover = !s.config.assets.is_empty() || !s.config.connectors.is_empty();
            loop {
                ticker.tick().await;
                for tenant in all_tenants(&s) {
                    // Re-run cloud/K8s discovery so newly-created KMS keys, certs,
                    // and ingresses surface without a restart, then scan.
                    if rediscover {
                        crate::assets::sync_assets(&s, &tenant).await;
                    }
                    run_full_scan(&s, &tenant, "scheduled").await;
                }
                // Reconcile external ticket/PR status after scanning.
                for tenant in all_tenants(&s) {
                    let _ = crate::admin::remediation::sync_ticket_status(&s, &tenant).await;
                }
            }
        });
        tracing::info!(
            interval_secs = interval,
            "Scheduled multi-tenant scanning enabled"
        );
    }

    // Scheduled signed evidence-pack delivery to an external sink.
    if let Some(ed) = state.config.auth.evidence_delivery.clone() {
        if ed.interval_secs > 0 {
            let interval_secs = ed.interval_secs;
            let s = state.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(ed.interval_secs));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    deliver_evidence(&s, &ed).await;
                }
            });
            tracing::info!(interval_secs, "Scheduled evidence-pack delivery enabled");
        }
    }

    // Per-tenant schedules: each org can run on its own cadence.
    for ts in state.config.tenant_schedules.clone() {
        if ts.scan_interval_secs == 0 {
            continue;
        }
        let org = ts.org.clone();
        let interval_secs = ts.scan_interval_secs;
        let s = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(ts.scan_interval_secs));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                run_full_scan(&s, &ts.org, "tenant-scheduled").await;
                let _ = crate::admin::remediation::sync_ticket_status(&s, &ts.org).await;
            }
        });
        tracing::info!(org = %org, interval_secs, "Per-tenant schedule enabled");
    }
}

/// Build and ship a signed evidence pack per tenant to the configured sink.
async fn deliver_evidence(state: &AppState, ed: &crate::config::EvidenceDeliveryConfig) {
    if state.config.air_gapped {
        tracing::info!(
            "air-gapped: skipping evidence pack delivery; download packs via the admin API instead"
        );
        return;
    }
    let Ok(sink) = std::env::var(&ed.sink_url_env) else {
        tracing::warn!(
            "evidence sink URL env '{}' not set; skipping delivery",
            ed.sink_url_env
        );
        return;
    };
    let tenants = if ed.tenants.is_empty() {
        vec![qw_store::DEFAULT_TENANT.to_string()]
    } else {
        ed.tenants.clone()
    };
    for tenant in tenants {
        let pack = crate::admin::evidence::build_pack(state, &tenant).await;
        match state.http_client.post(&sink).json(&pack).send().await {
            Ok(r) => {
                tracing::info!(tenant = %tenant, status = %r.status(), "evidence pack delivered")
            }
            Err(e) => tracing::warn!(tenant = %tenant, error = %e, "evidence delivery failed"),
        }
    }
}

/// Every tenant/org that has data or configuration.
pub fn all_tenants(state: &AppState) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut set: BTreeSet<String> = BTreeSet::new();
    set.insert(qw_store::DEFAULT_TENANT.to_string());
    for t in state.store.tenants() {
        set.insert(t);
    }
    for u in &state.config.auth.users {
        set.insert(u.org.clone());
    }
    for k in &state.config.auth.api_keys {
        set.insert(k.org.clone());
    }
    set.into_iter().collect()
}

/// Run every configured scanner against every derived target, persist results,
/// fingerprint provider endpoints, then recompute and snapshot posture.
pub async fn run_full_scan(state: &AppState, tenant: &str, trigger: &str) {
    tracing::info!(trigger, tenant, "Starting full scan");
    let mut targets: Vec<ScanTarget> = Vec::new();

    // Provider endpoints from configured upstream URLs.
    for (name, provider) in &state.config.providers {
        if let Some(host) = host_from_url(&provider.upstream) {
            let mut t = ScanTarget::tls(&format!("{host}:443"));
            t.metadata.insert("provider".to_string(), name.clone());
            targets.push(t);
        }
    }

    // Explicit TLS targets from scanner config.
    for addr in &state.config.scanner.tls.targets {
        targets.push(ScanTarget::tls(addr));
    }

    // Extra targets configured for this specific tenant.
    for ts in &state.config.tenant_schedules {
        if ts.org == tenant {
            for addr in &ts.targets {
                targets.push(ScanTarget::tls(addr));
            }
        }
    }

    // Dependency-file scanning over configured paths.
    if state.config.scanner.dependencies.enabled {
        for path in &state.config.scanner.dependencies.paths {
            for dep_file in dependency_files_in(path) {
                targets.push(ScanTarget::dependency_file(&dep_file));
            }
        }
    }

    // Code directories.
    if state.config.scanner.code.enabled {
        for path in &state.config.scanner.code.paths {
            targets.push(ScanTarget::code_directory(path));
        }
    }

    // Declared data stores (at-rest posture).
    if state.config.scanner.data_at_rest.enabled {
        for s in &state.config.scanner.data_at_rest.stores {
            let meta = std::collections::HashMap::from([
                ("kind".to_string(), s.kind.clone()),
                ("encryption".to_string(), s.encryption.clone()),
                ("key_wrap".to_string(), s.key_wrap.clone()),
                ("key_age_days".to_string(), s.key_age_days.to_string()),
                ("in_transit_tls".to_string(), s.in_transit_tls.to_string()),
                ("environment".to_string(), s.environment.clone()),
            ]);
            targets.push(ScanTarget::data_store(&s.address, meta));
        }
    }

    let mut all_results = Vec::new();
    for target in &targets {
        let results = state.scanner_registry.scan_all(target).await;
        for result in &results {
            state.store.record_scan(tenant, result, target);

            // Capture provider TLS fingerprint from TLS scans.
            if let Some(provider_name) = target.metadata.get("provider") {
                capture_provider_crypto(state, provider_name, target, result);
            }

            let _ = state
                .audit_logger
                .log(
                    "system",
                    qw_audit::AuditEvent::ScanCompleted {
                        scan_id: result.target_id.clone(),
                        scanner_id: result.scanner_id.clone(),
                        target: target.address.clone(),
                        finding_count: result.findings.len() as u32,
                        status: format!("{:?}", result.status),
                    },
                )
                .await;
        }
        all_results.extend(results);
    }

    let summary = recompute_and_snapshot(state, tenant, &all_results, trigger).await;
    evaluate_findings_alerts(state, tenant, &all_results).await;

    tracing::info!(
        trigger,
        targets = targets.len(),
        findings = all_results.iter().map(|r| r.findings.len()).sum::<usize>(),
        score = summary.overall_score,
        "Full scan complete"
    );
}

/// Recompute posture from the given scan results plus live provider crypto,
/// update the cache, append a history snapshot, and audit any score change.
pub async fn recompute_and_snapshot(
    state: &AppState,
    tenant: &str,
    results: &[qw_scanner::ScanResult],
    trigger: &str,
) -> qw_cbom::PostureSummary {
    let providers: Vec<ProviderCryptoInfo> = state
        .provider_crypto
        .iter()
        .map(|e| e.value().clone())
        .collect();
    let summary = PostureEngine::summarize(results, &providers);

    let previous_score = state.store.latest_posture(tenant).map(|s| s.overall_score);

    {
        let mut cache = state.posture_cache.write().await;
        *cache = Some(summary.clone());
    }
    state
        .store
        .record_posture(tenant, &PostureSnapshot::from_summary(&summary, trigger));

    if let Some(prev) = previous_score {
        if (prev - summary.overall_score).abs() >= f64::EPSILON {
            let _ = state
                .audit_logger
                .log(
                    "system",
                    qw_audit::AuditEvent::PostureChanged {
                        previous_score: prev,
                        new_score: summary.overall_score,
                        trigger: trigger.to_string(),
                    },
                )
                .await;
        }

        // Alert on a meaningful posture *drop*.
        let drop = prev - summary.overall_score;
        let (threshold, _, _) = state.alert_manager.config_thresholds();
        if drop >= threshold {
            let mut event = crate::alerts::AlertEvent::new(
                "posture_drop",
                crate::alerts::AlertSeverity::Warning,
                "Cryptographic posture dropped",
                format!(
                    "Overall posture fell {:.1} points ({:.1} → {:.1}) after a {trigger} scan.",
                    drop, prev, summary.overall_score
                ),
            );
            event
                .metadata
                .insert("previous".into(), format!("{:.1}", prev));
            event
                .metadata
                .insert("current".into(), format!("{:.1}", summary.overall_score));
            state.alert_manager.fire(tenant, event).await;
        }
    }

    // Snapshot the attack-path graph and alert on any newly-appeared paths (drift).
    crate::admin::graph::snapshot_and_alert(state, tenant).await;
    // Evaluate posture SLOs and alert on breaches.
    crate::admin::slos::check_and_alert(state, tenant).await;
    // Record a crypto-agility governance snapshot (drift trend).
    crate::admin::governance::record_snapshot(state, tenant).await;

    summary
}

/// Inspect fresh scan results and fire critical-finding / cert-expiry alerts.
pub async fn evaluate_findings_alerts(
    state: &AppState,
    tenant: &str,
    results: &[qw_scanner::ScanResult],
) {
    use qw_scanner::{FindingCategory, FindingSeverity};

    let (_, alert_on_critical, _) = state.alert_manager.config_thresholds();

    let mut critical = 0u32;
    let mut expiring = 0u32;
    let mut sample = String::new();
    for r in results {
        for f in &r.findings {
            if alert_on_critical && f.severity >= FindingSeverity::High {
                critical += 1;
                if sample.is_empty() {
                    sample = f.title.clone();
                }
            }
            if matches!(
                f.category,
                FindingCategory::ExpiringCertificate | FindingCategory::ExpiredCertificate
            ) {
                expiring += 1;
            }
        }
    }

    if critical > 0 {
        let event = crate::alerts::AlertEvent::new(
            "new_critical",
            crate::alerts::AlertSeverity::Critical,
            format!("{critical} high/critical finding(s) detected"),
            format!("A scan surfaced {critical} high or critical cryptographic finding(s), e.g. \"{sample}\"."),
        );
        state.alert_manager.fire(tenant, event).await;
    }
    if expiring > 0 {
        let event = crate::alerts::AlertEvent::new(
            "cert_expiring",
            crate::alerts::AlertSeverity::Warning,
            format!("{expiring} certificate(s) expiring or expired"),
            format!("{expiring} certificate finding(s) require renewal."),
        );
        state.alert_manager.fire(tenant, event).await;
    }
}

/// Pull TLS version + cipher + PQC status out of a TLS scan result and cache it
/// against the provider name for CBOM service entries.
fn capture_provider_crypto(
    state: &AppState,
    provider_name: &str,
    target: &ScanTarget,
    result: &qw_scanner::ScanResult,
) {
    // Find the TLS connection finding (has tls_version metadata).
    for finding in &result.findings {
        if let (Some(tls_version), Some(cipher)) = (
            finding.metadata.get("tls_version"),
            finding.metadata.get("cipher_suite"),
        ) {
            state.provider_crypto.insert(
                provider_name.to_string(),
                ProviderCryptoInfo {
                    provider_name: provider_name.to_string(),
                    endpoint: target.address.clone(),
                    tls_version: tls_version.clone(),
                    cipher_suite: cipher.clone(),
                    pqc_status: finding.pqc_status.clone(),
                    last_seen: chrono::Utc::now(),
                },
            );
            return;
        }
    }

    // Fallback: no detailed metadata, record unknown.
    let _ = PqcStatus::Unknown;
}

/// Extract the host portion from a base URL like "https://api.anthropic.com/v1".
fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Find common dependency manifest files directly under a directory.
fn dependency_files_in(dir: &str) -> Vec<String> {
    const NAMES: &[&str] = &[
        "Cargo.toml",
        "package.json",
        "requirements.txt",
        "go.mod",
        "Gemfile",
    ];
    let mut found = Vec::new();
    for name in NAMES {
        let path = std::path::Path::new(dir).join(name);
        if path.is_file() {
            found.push(path.to_string_lossy().to_string());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_from_url() {
        assert_eq!(
            host_from_url("https://api.anthropic.com/v1"),
            Some("api.anthropic.com".to_string())
        );
        assert_eq!(
            host_from_url("https://api.openai.com:443/v1"),
            Some("api.openai.com".to_string())
        );
        assert_eq!(
            host_from_url("http://localhost:11434"),
            Some("localhost".to_string())
        );
        assert_eq!(host_from_url(""), None);
    }
}
