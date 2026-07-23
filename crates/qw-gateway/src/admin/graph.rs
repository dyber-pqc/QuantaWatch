//! HTTP handlers for the Quantum Attack-Path Engine. The graph computation now
//! lives in the shared `qw-graph` crate (used by both the gateway and the
//! desktop app); this module assembles a `GraphInputs` snapshot from live
//! gateway state, runs the engine, and exposes the results over the admin API.

use std::collections::{BTreeSet, HashMap};

use axum::{extract::State, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;

use qw_graph::{enrich_paths, summarize, AttackPath, Graph, GraphInputs};
use qw_scanner::PqcStatus;
use qw_store::GraphSnapshot;

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

/// Assemble a graph snapshot from live gateway state and compute it with the
/// shared engine. `overrides` forces a provider's pqc_status (remediation sim).
pub fn build_graph(
    state: &AppState,
    tenant: &str,
    overrides: &HashMap<String, PqcStatus>,
) -> Graph {
    let providers = state
        .provider_crypto
        .iter()
        .map(|e| {
            let v = e.value();
            qw_graph::ProviderChannel {
                name: e.key().clone(),
                pqc_status: v.pqc_status.clone(),
                tls_version: v.tls_version.clone(),
                endpoint: v.endpoint.clone(),
            }
        })
        .collect();

    // CIEM identities, pre-filtered to the tenant (API keys prefixed `apikey:`).
    let is_default = tenant == qw_store::DEFAULT_TENANT;
    let mut identities = Vec::new();
    for u in &state.config.auth.users {
        if u.org == tenant || is_default {
            identities.push(qw_graph::IdentityInput {
                label: u.username.clone(),
                role: u.role.clone(),
            });
        }
    }
    for k in &state.config.auth.api_keys {
        if k.org == tenant || is_default {
            identities.push(qw_graph::IdentityInput {
                label: format!("apikey:{}", k.name),
                role: k.role.clone(),
            });
        }
    }

    let agents = state
        .config
        .agents
        .iter()
        .map(|(name, a)| qw_graph::AgentInput {
            name: name.clone(),
            offline: a.offline,
            allowed_tools: a.allowed_tools.clone(),
            allowed_models: a.allowed_models.clone(),
        })
        .collect();

    let flows = state.store.list_flows(tenant);
    let findings = state.store.all_findings(tenant);
    let assets = state.store.list_assets(tenant);
    let targets = state.store.list_targets(tenant);

    let inputs = GraphInputs {
        providers,
        identities,
        agents,
        flows: &flows,
        findings: &findings,
        assets: &assets,
        targets: &targets,
    };
    qw_graph::build_graph(&inputs, overrides)
}


pub async fn get_attack_paths(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let g = build_graph(&state, &tenant, &HashMap::new());
    Json(json!({
        "nodes": g.nodes,
        "edges": g.edges,
        "paths": enrich_paths(&g.paths),
        "summary": summarize(&g.paths),
    }))
}

#[derive(Deserialize)]
pub struct SimulateRequest {
    /// e.g. [{ "provider": "openai", "pqcStatus": "hybrid" }]
    pub overrides: Vec<SimOverride>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimOverride {
    pub provider: String,
    pub pqc_status: PqcStatus,
}

/// Remediation simulation: recompute the graph with forced provider crypto and
/// report the risk reduction ("what-if I enable hybrid KEM on OpenAI").
pub async fn simulate(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    Json(body): Json<SimulateRequest>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let overrides: HashMap<String, PqcStatus> = body
        .overrides
        .into_iter()
        .map(|o| (o.provider, o.pqc_status))
        .collect();

    let base = build_graph(&state, &tenant, &HashMap::new());
    let sim = build_graph(&state, &tenant, &overrides);

    let base_risk: f64 = base.paths.iter().map(|p| p.score).sum();
    let sim_risk: f64 = sim.paths.iter().map(|p| p.score).sum();
    let reduction = if base_risk > 0.0 {
        ((base_risk - sim_risk) / base_risk * 100.0 * 10.0).round() / 10.0
    } else {
        0.0
    };

    let sim_ids: BTreeSet<&str> = sim.paths.iter().map(|p| p.id.as_str()).collect();
    let mitigated: Vec<&AttackPath> = base
        .paths
        .iter()
        .filter(|p| !sim_ids.contains(p.id.as_str()))
        .collect();

    Json(json!({
        "before": summarize(&base.paths),
        "after": summarize(&sim.paths),
        "baseRisk": (base_risk * 10.0).round() / 10.0,
        "simRisk": (sim_risk * 10.0).round() / 10.0,
        "riskReduction": reduction,
        "mitigatedPaths": mitigated,
        "nodes": sim.nodes,
        "edges": sim.edges,
        "paths": enrich_paths(&sim.paths),
        "summary": summarize(&sim.paths),
    }))
}

pub async fn get_timeline(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);
    let timeline = state.store.graph_timeline(&tenant, 100);
    Json(json!({ "timeline": timeline, "total": timeline.len() }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediatePathRequest {
    pub integration_id: String,
    pub project: Option<String>,
}

/// Auto-remediation: open a tracked remediation ticket (Jira/Linear/…) directly
/// from an attack path, with the concrete hybrid-KEM fix as the actionable item.
pub async fn remediate_path(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
    axum::extract::Path(path_id): axum::extract::Path<String>,
    Json(body): Json<RemediatePathRequest>,
) -> impl IntoResponse {
    use axum::http::StatusCode;
    let tenant = tenant_of(&ctx);
    let g = build_graph(&state, &tenant, &HashMap::new());
    let ap = match g.paths.iter().find(|p| p.id == path_id) {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "attack path not found" })),
            )
                .into_response()
        }
    };
    let integration = match state.integration_registry.get(&body.integration_id) {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "integration not found" })),
            )
                .into_response()
        }
    };

    // Synthesize a Finding describing the attack path so we can reuse the
    // integration remediation pipeline.
    let sev = match ap.severity.as_str() {
        "critical" => qw_scanner::FindingSeverity::Critical,
        "high" => qw_scanner::FindingSeverity::High,
        "medium" => qw_scanner::FindingSeverity::Medium,
        _ => qw_scanner::FindingSeverity::Low,
    };
    let finding = qw_scanner::Finding {
        id: ap.id.clone(),
        category: qw_scanner::FindingCategory::MissingPqc,
        severity: sev,
        title: format!("[Attack Path] {}", ap.title),
        description: format!(
            "{}\n\nExposure score: {}. {}",
            ap.recommendation,
            ap.score,
            if ap.observed {
                format!("Observed in {} live request(s).", ap.request_count)
            } else {
                "Policy-derived exposure.".to_string()
            }
        ),
        asset: qw_scanner::CryptoAsset {
            id: ap.id.clone(),
            asset_type: qw_scanner::CryptoAssetType::TlsConnection,
            name: ap.provider.clone(),
            algorithm: None,
            key_length: None,
            protocol_version: ap.tls_version.clone(),
            location: qw_scanner::AssetLocation {
                source_type: "attack-path".into(),
                path: ap.provider.clone(),
                line: None,
            },
            discovered_by: "attack-path-engine".into(),
            discovered_at: chrono::Utc::now(),
        },
        remediation: Some(ap.recommendation.clone()),
        pqc_status: ap.channel_pqc.clone(),
        metadata: std::collections::HashMap::new(),
    };
    let opts = qw_integrations::RemediationOpts {
        project: body.project.clone(),
        ..Default::default()
    };

    match integration.create_remediation(&finding, &opts).await {
        Ok(ticket) => {
            state.store.record_remediation(&tenant, &ticket);
            let _ = state
                .audit_logger
                .log(
                    "system",
                    qw_audit::AuditEvent::IntegrationSync {
                        integration_id: body.integration_id.clone(),
                        action: "remediate_attack_path".to_string(),
                        detail: ticket.external_id.clone(),
                    },
                )
                .await;
            Json(ticket).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Snapshot the graph and alert on NEW attack paths (drift detection).
/// Called from the scan pipeline.
pub async fn snapshot_and_alert(state: &AppState, tenant: &str) {
    let g = build_graph(state, tenant, &HashMap::new());
    let path_ids: Vec<String> = g.paths.iter().map(|p| p.id.clone()).collect();

    let previous = state.store.latest_graph_snapshot(tenant);
    let new_paths: Vec<&AttackPath> = match &previous {
        Some(prev) => {
            let seen: BTreeSet<&str> = prev.path_ids.iter().map(|s| s.as_str()).collect();
            g.paths
                .iter()
                .filter(|p| !seen.contains(p.id.as_str()))
                .collect()
        }
        None => Vec::new(), // first snapshot: don't alert on the whole baseline
    };

    let c = |s: &str| g.paths.iter().filter(|p| p.severity == s).count() as u32;
    state.store.record_graph_snapshot(
        tenant,
        &GraphSnapshot {
            timestamp: chrono::Utc::now(),
            total: g.paths.len() as u32,
            critical: c("critical"),
            high: c("high"),
            hndl: g.paths.iter().filter(|p| p.hndl).count() as u32,
            path_ids,
        },
    );

    for np in new_paths
        .iter()
        .filter(|p| p.severity == "critical" || p.severity == "high")
    {
        let mut event = crate::alerts::AlertEvent::new(
            "new_attack_path",
            crate::alerts::AlertSeverity::Critical,
            "New quantum attack path detected",
            format!("{} (score {}).", np.title, np.score),
        );
        event.metadata.insert("path".into(), np.id.clone());
        state.alert_manager.fire(tenant, event).await;
    }
}
