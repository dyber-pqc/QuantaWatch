//! Agent-aware cryptographic posture.
//!
//! Joins three sources the platform already has — live gateway sessions, the
//! configured agent policies, and per-provider TLS crypto captured by the
//! scanner — into a posture score *per AI agent*. No other CPM tool understands
//! which of your agents talk over PQC-safe channels; this endpoint does.

use axum::{extract::State, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

use qw_cbom::PostureEngine;
use qw_scanner::PqcStatus;

use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentProviderPosture {
    provider: String,
    pqc_status: PqcStatus,
    tls_version: Option<String>,
    cipher_suite: Option<String>,
    score: f64,
    /// true if the agent has actually been observed talking to this provider
    /// (vs. merely allowed by policy).
    observed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentPosture {
    name: String,
    description: String,
    offline: bool,
    /// Conservative score: an agent is only as PQC-safe as its weakest channel.
    overall_score: f64,
    /// Representative status (the most at-risk channel).
    pqc_status: PqcStatus,
    session_count: u32,
    request_count: u64,
    model_count: u32,
    last_active: Option<DateTime<Utc>>,
    providers: Vec<AgentProviderPosture>,
}

/// Map an allowed-model glob (e.g. "claude-sonnet-*", "gpt-4o", "ollama/*") to the
/// upstream provider it would route to.
fn providers_for_models(models: &[String]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for m in models {
        let ml = m.to_lowercase();
        if ml.contains("claude") {
            set.insert("anthropic".to_string());
        }
        if ml.contains("gpt") || ml.starts_with("o1") || ml.starts_with("o3") || ml.contains("openai") {
            set.insert("openai".to_string());
        }
        if ml.contains("ollama") {
            set.insert("ollama".to_string());
        }
        if ml.contains("deepseek") {
            set.insert("deepseek".to_string());
        }
        if ml.contains("gemini") || ml.contains("google") {
            set.insert("google".to_string());
        }
    }
    set
}

#[derive(Default)]
struct Observed {
    providers: BTreeSet<String>,
    session_count: u32,
    request_count: u64,
    last_active: Option<DateTime<Utc>>,
}

pub async fn list_agents(State(state): State<AppState>) -> impl IntoResponse {
    // 1. Aggregate observed activity per agent from live sessions.
    let mut observed: BTreeMap<String, Observed> = BTreeMap::new();
    for entry in state.sessions.iter() {
        let s = entry.value();
        let o = observed.entry(s.agent_name.clone()).or_default();
        if !s.provider.is_empty() {
            o.providers.insert(s.provider.clone());
        }
        o.session_count += 1;
        o.request_count += s.request_count;
        o.last_active = Some(match o.last_active {
            Some(prev) if prev >= s.created_at => prev,
            _ => s.created_at,
        });
    }

    // 2. Union of configured agents and observed agents.
    let mut names: BTreeSet<String> = state.config.agents.keys().cloned().collect();
    names.extend(observed.keys().cloned());

    let mut agents: Vec<AgentPosture> = Vec::new();

    for name in names {
        let cfg = state.config.agents.get(&name);
        let obs = observed.get(&name);

        let mut allowed_providers = cfg
            .map(|c| providers_for_models(&c.allowed_models))
            .unwrap_or_default();
        let observed_providers = obs.map(|o| o.providers.clone()).unwrap_or_default();
        allowed_providers.extend(observed_providers.iter().cloned());

        // 3. Score each channel against captured provider crypto.
        let mut providers: Vec<AgentProviderPosture> = Vec::new();
        for provider in &allowed_providers {
            let (pqc_status, tls_version, cipher_suite, score) =
                match state.provider_crypto.get(provider) {
                    Some(info) => {
                        let info = info.value();
                        (
                            info.pqc_status.clone(),
                            Some(info.tls_version.clone()),
                            Some(info.cipher_suite.clone()),
                            PostureEngine::score_service(info),
                        )
                    }
                    None => (PqcStatus::Unknown, None, None, 40.0),
                };
            providers.push(AgentProviderPosture {
                provider: provider.clone(),
                pqc_status,
                tls_version,
                cipher_suite,
                score,
                observed: observed_providers.contains(provider),
            });
        }

        // 4. Overall = weakest channel (security is gated by the worst link).
        let (overall_score, pqc_status) = providers
            .iter()
            .min_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
            .map(|p| (p.score, p.pqc_status.clone()))
            .unwrap_or((100.0, PqcStatus::Unknown));

        providers.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));

        agents.push(AgentPosture {
            name: name.clone(),
            description: cfg.map(|c| c.description.clone()).unwrap_or_default(),
            offline: cfg.map(|c| c.offline).unwrap_or(false),
            overall_score: (overall_score * 10.0).round() / 10.0,
            pqc_status,
            session_count: obs.map(|o| o.session_count).unwrap_or(0),
            request_count: obs.map(|o| o.request_count).unwrap_or(0),
            model_count: cfg.map(|c| c.allowed_models.len() as u32).unwrap_or(0),
            last_active: obs.and_then(|o| o.last_active),
            providers,
        });
    }

    // Most at-risk agents first.
    agents.sort_by(|a, b| a.overall_score.partial_cmp(&b.overall_score).unwrap_or(std::cmp::Ordering::Equal));

    let total = agents.len();
    let at_risk = agents.iter().filter(|a| a.overall_score < 80.0).count();
    let avg_score = if agents.is_empty() {
        100.0
    } else {
        (agents.iter().map(|a| a.overall_score).sum::<f64>() / agents.len() as f64 * 10.0).round() / 10.0
    };

    Json(json!({
        "agents": agents,
        "total": total,
        "atRisk": at_risk,
        "avgScore": avg_score,
    }))
}
