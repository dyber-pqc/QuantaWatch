//! Asset inventory & agentless connectors.
//!
//! Discovers external crypto assets (TLS endpoints, K8s ingresses, load
//! balancers, KMS keys) from declared config and from agentless connectors,
//! scans the TLS-reachable ones, and persists the inventory (tenant-scoped).
//! This widens the attack-path graph beyond AI providers to full infrastructure.

use qw_scanner::{PqcStatus, ScanTarget};
use qw_store::AssetRow;

use crate::state::AppState;

/// Combine declared assets and connector-expanded assets into a flat inventory.
pub fn discover(state: &AppState) -> Vec<AssetRow> {
    let mut out: Vec<AssetRow> = Vec::new();

    for a in &state.config.assets {
        out.push(AssetRow {
            id: a.id.clone(),
            kind: a.kind.clone(),
            address: a.address.clone(),
            environment: a.environment.clone(),
            tags: a.tags.clone(),
            pqc_status: PqcStatus::Unknown.to_string(),
            tls_version: None,
            last_scanned: None,
            source: "config".to_string(),
        });
    }

    // Agentless connectors that provide a host list (kubernetes/generic).
    // aws/azure/gcp connectors call live APIs in cloud::discover instead.
    for c in &state.config.connectors {
        if matches!(c.connector_type.as_str(), "aws" | "azure" | "gcp") {
            continue;
        }
        let kind = match c.connector_type.as_str() {
            "kubernetes" => "k8s_ingress",
            _ => "tls_endpoint",
        };
        for (i, ep) in c.endpoints.iter().enumerate() {
            out.push(AssetRow {
                id: format!("{}-{i}", c.name),
                kind: kind.to_string(),
                address: ep.clone(),
                environment: c.environment.clone(),
                tags: c.tags.clone(),
                pqc_status: PqcStatus::Unknown.to_string(),
                tls_version: None,
                last_scanned: None,
                source: c.connector_type.clone(),
            });
        }
    }

    out
}

/// Discover, TLS-scan, and persist the asset inventory. Returns (total, scanned).
pub async fn sync_assets(state: &AppState, tenant: &str) -> (usize, usize) {
    let mut assets = discover(state);

    // Live cloud connectors (AWS KMS/ACM, Azure Key Vault) — real API calls,
    // no-op gracefully when credentials are absent.
    for c in &state.config.connectors {
        if matches!(c.connector_type.as_str(), "aws" | "azure" | "gcp") {
            assets.extend(crate::cloud::discover(&state.http_client, c).await);
        }
    }

    let total = assets.len();
    let mut scanned = 0;

    for mut asset in assets {
        // Scan anything with a host:port TLS surface.
        if matches!(
            asset.kind.as_str(),
            "tls_endpoint" | "k8s_ingress" | "load_balancer" | "certificate"
        ) && asset.address.contains(':')
        {
            let target = ScanTarget::tls(&asset.address);
            let results = state.scanner_registry.scan_all(&target).await;
            for r in &results {
                // Persist the findings under this tenant too (feeds compliance/graph).
                state.store.record_scan(tenant, r, &target);
                // Derive the asset's channel status from the TLS connection finding.
                if let Some(f) = r
                    .findings
                    .iter()
                    .find(|f| f.metadata.contains_key("tls_version"))
                {
                    asset.pqc_status = f.pqc_status.to_string();
                    asset.tls_version = f.metadata.get("tls_version").cloned();
                }
            }
            asset.last_scanned = Some(chrono::Utc::now());
            scanned += 1;
        }
        state.store.upsert_asset(tenant, &asset);
    }

    tracing::info!(tenant, total, scanned, "asset inventory synced");
    (total, scanned)
}
