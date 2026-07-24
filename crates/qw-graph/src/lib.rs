//! Quantum Attack-Path Engine — a cryptographic security graph.
//!
//! Correlates identities → AI agents → the data they handle → the providers &
//! external assets they reach → the TLS/certificate/dependency crypto on those
//! channels, using BOTH policy (allowed models/tools) and OBSERVED proxy traffic.
//! Computes ranked Harvest-Now-Decrypt-Later (HNDL) "toxic combinations", node
//! blast radius, remediation-simulation deltas, and graph drift over time.
//!
//! Pure and self-contained: it takes a [`GraphInputs`] snapshot (assembled from
//! the store + config) and returns a [`Graph`]. Shared by the gateway (live
//! state) and the desktop app (local store), so both compute identical graphs.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use serde_json::json;

use qw_scanner::types::FindingRecord;
use qw_scanner::{CryptoAssetType, FindingStatus, PqcStatus};
use qw_store::{AssetRow, FlowRow, TargetRow};

/// Everything the engine needs to build a graph, decoupled from any runtime.
/// Assemble it from live state (gateway) or the local store (desktop).
pub struct GraphInputs<'a> {
    /// Provider channels with their live crypto posture (overrides applied in-engine).
    pub providers: Vec<ProviderChannel>,
    /// Identities that can drive agents (config users + API keys), pre-filtered
    /// to the tenant. API-key labels are prefixed `apikey:`.
    pub identities: Vec<IdentityInput>,
    /// Policy-declared agents (allowed models/tools).
    pub agents: Vec<AgentInput>,
    pub flows: &'a [FlowRow],
    pub findings: &'a [FindingRecord],
    pub assets: &'a [AssetRow],
    pub targets: &'a [TargetRow],
}

pub struct ProviderChannel {
    pub name: String,
    pub pqc_status: PqcStatus,
    pub tls_version: String,
    pub endpoint: String,
}

pub struct IdentityInput {
    pub label: String,
    pub role: String,
}

pub struct AgentInput {
    pub name: String,
    pub offline: bool,
    pub allowed_tools: Vec<String>,
    pub allowed_models: Vec<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String, // identity | data | agent | provider | certificate | dependency | asset
    pub label: String,
    pub sublabel: String,
    pub pqc_status: String,
    pub risk: f64,
    /// Sensitivity that would be exposed if this node's crypto were broken.
    pub blast_radius: f64,
    /// True if this node has been exercised by real traffic.
    pub observed: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Edge {
    pub source: String,
    pub target: String,
    pub kind: String, // can-access | handles | routes-to | secured-by | depends-on
    pub observed: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttackPath {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub score: f64,
    pub hndl: bool,
    pub observed: bool,
    pub request_count: u64,
    /// data-exposure | access-risk | external-asset
    pub kind: String,
    pub data_class: String,
    pub agent: String,
    pub provider: String,
    pub tls_version: Option<String>,
    pub channel_pqc: PqcStatus,
    pub node_ids: Vec<String>,
    pub recommendation: String,
}

pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub paths: Vec<AttackPath>,
}

fn data_class_for(tools: &[String], offline: bool) -> (&'static str, f64) {
    let joined = tools.join(",").to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| joined.contains(n));
    let (label, mut weight) = if joined.contains('*') || has(&["admin", "exec", "shell"]) {
        ("Broad / Privileged Access", 1.0)
    } else if has(&["payment", "billing", "card", "finance", "invoice"]) {
        ("Financial Data", 1.0)
    } else if has(&[
        "crm", "customer", "email", "pii", "contact", "user_", "profile",
    ]) {
        ("Customer PII", 0.95)
    } else if has(&["db", "database", "sql", "file", "fs", "storage", "read"]) {
        ("Internal Data", 0.7)
    } else if has(&["code", "repo", "git", "source"]) {
        ("Source Code", 0.65)
    } else if has(&["web_search", "search", "public"]) {
        ("Public Data", 0.2)
    } else {
        ("General Data", 0.5)
    };
    if offline {
        weight *= 0.4;
    }
    (label, weight)
}

fn channel_weight(status: &PqcStatus) -> f64 {
    match status {
        PqcStatus::ClassicalWeak => 1.0,
        PqcStatus::ClassicalSecure => 0.85,
        PqcStatus::Unknown => 0.6,
        PqcStatus::Hybrid => 0.15,
        PqcStatus::PqcReady => 0.0,
    }
}

fn providers_for_models(models: &[String]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for m in models {
        let ml = m.to_lowercase();
        if ml.contains("claude") {
            set.insert("anthropic".to_string());
        }
        if ml.contains("gpt")
            || ml.starts_with("o1")
            || ml.starts_with("o3")
            || ml.contains("openai")
        {
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

fn severity_for(score: f64) -> &'static str {
    if score >= 70.0 {
        "critical"
    } else if score >= 50.0 {
        "high"
    } else if score >= 30.0 {
        "medium"
    } else {
        "low"
    }
}

fn host_of(addr: &str) -> String {
    addr.split("://")
        .last()
        .unwrap_or(addr)
        .split('/')
        .next()
        .unwrap_or(addr)
        .split(':')
        .next()
        .unwrap_or(addr)
        .to_string()
}

fn parse_status(s: &str) -> PqcStatus {
    match s {
        "pqc_ready" => PqcStatus::PqcReady,
        "hybrid" => PqcStatus::Hybrid,
        "classical_secure" => PqcStatus::ClassicalSecure,
        "classical_weak" => PqcStatus::ClassicalWeak,
        _ => PqcStatus::Unknown,
    }
}

/// An asset/host is air-gapped if tagged `air-gapped`. With no network path
/// there is no harvestable channel, so harvest-now-decrypt-later doesn't apply
/// and the quantum-channel attack path is suppressed.
fn is_air_gapped(tags: &[String]) -> bool {
    tags.iter()
        .any(|t| t.eq_ignore_ascii_case("air-gapped") || t.eq_ignore_ascii_case("airgapped"))
}

/// Build the full attack-path graph. `overrides` forces a provider's pqc_status
/// (used by remediation simulation).
pub fn build_graph(inputs: &GraphInputs, overrides: &HashMap<String, PqcStatus>) -> Graph {
    let mut nodes: Vec<Node> = Vec::new();
    let mut edges: Vec<Edge> = Vec::new();
    let mut paths: Vec<AttackPath> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut blast: BTreeMap<String, f64> = BTreeMap::new();

    let push = |nodes: &mut Vec<Node>, seen: &mut BTreeSet<String>, n: Node| {
        if seen.insert(n.id.clone()) {
            nodes.push(n);
        }
    };

    // Provider live crypto (with simulation overrides applied).
    let providers: BTreeMap<String, (PqcStatus, String, String)> = inputs
        .providers
        .iter()
        .map(|c| {
            let status = overrides.get(&c.name).cloned().unwrap_or(c.pqc_status);
            (
                c.name.clone(),
                (status, c.tls_version.clone(), c.endpoint.clone()),
            )
        })
        .collect();

    // Observed flows keyed by (agent, provider).
    let flows = inputs.flows;
    let flow_map: HashMap<(String, String), (u64, u64)> = flows
        .iter()
        .map(|f| {
            (
                (f.agent.clone(), f.provider.clone()),
                (f.requests, f.sensitive),
            )
        })
        .collect();
    let observed_providers: BTreeSet<String> = flows.iter().map(|f| f.provider.clone()).collect();

    // Suppressed findings (false positive / accepted risk) don't contribute
    // attack paths or graph nodes, but remain in the store for the audit trail.
    let findings: Vec<&FindingRecord> = inputs
        .findings
        .iter()
        .filter(|f| !matches!(f.status, FindingStatus::Suppressed))
        .collect();

    // Cert status per host (worst) from findings.
    let mut cert_by_host: BTreeMap<String, PqcStatus> = BTreeMap::new();
    for f in &findings {
        if matches!(f.asset_type, CryptoAssetType::Certificate) {
            let host = host_of(&f.location);
            let e = cert_by_host.entry(host).or_insert(PqcStatus::PqcReady);
            if channel_weight(&f.pqc_status) > channel_weight(e) {
                *e = f.pqc_status;
            }
        }
    }

    // Provider + certificate nodes.
    for (name, (status, tls, endpoint)) in &providers {
        let overridden = overrides.contains_key(name);
        push(
            &mut nodes,
            &mut seen,
            Node {
                id: format!("provider:{name}"),
                kind: "provider".into(),
                label: name.clone(),
                sublabel: if overridden {
                    format!("TLS {tls} (simulated)")
                } else {
                    format!("TLS {tls}")
                },
                pqc_status: status.to_string(),
                risk: channel_weight(status) * 100.0,
                blast_radius: 0.0,
                observed: observed_providers.contains(name),
            },
        );
        let host = host_of(endpoint);
        if let Some(cs) = cert_by_host.get(&host) {
            let cid = format!("cert:{host}");
            push(
                &mut nodes,
                &mut seen,
                Node {
                    id: cid.clone(),
                    kind: "certificate".into(),
                    label: format!("{host} cert"),
                    sublabel: "X.509 chain".into(),
                    pqc_status: cs.to_string(),
                    risk: channel_weight(cs) * 100.0,
                    blast_radius: 0.0,
                    observed: false,
                },
            );
            edges.push(Edge {
                source: format!("provider:{name}"),
                target: cid,
                kind: "secured-by".into(),
                observed: false,
            });
        }
    }

    // Identities (CIEM): supplied pre-filtered to the tenant. API-key labels are
    // already `apikey:`-prefixed by the caller.
    let identities: Vec<(String, String)> = inputs
        .identities
        .iter()
        .map(|i| (i.label.clone(), i.role.clone()))
        .collect();
    for (ident, role) in &identities {
        let iid = format!("identity:{ident}");
        let privileged = role == "admin" || role == "operator";
        push(
            &mut nodes,
            &mut seen,
            Node {
                id: iid,
                kind: "identity".into(),
                label: ident.clone(),
                sublabel: role.clone(),
                pqc_status: "n/a".into(),
                risk: if privileged { 55.0 } else { 20.0 },
                blast_radius: 0.0,
                observed: false,
            },
        );
    }

    // Agents + data + policy/observed toxic paths.
    for agent in &inputs.agents {
        let name = &agent.name;
        let agent_id = format!("agent:{name}");
        push(
            &mut nodes,
            &mut seen,
            Node {
                id: agent_id.clone(),
                kind: "agent".into(),
                label: name.clone(),
                sublabel: if agent.offline {
                    "isolated".into()
                } else {
                    "networked".into()
                },
                pqc_status: "n/a".into(),
                risk: 0.0,
                blast_radius: 0.0,
                observed: false,
            },
        );

        let (data_label, data_weight) = data_class_for(&agent.allowed_tools, agent.offline);
        let data_id = format!("data:{name}:{}", data_label.replace(' ', "_"));
        push(
            &mut nodes,
            &mut seen,
            Node {
                id: data_id.clone(),
                kind: "data".into(),
                label: data_label.into(),
                sublabel: format!("sensitivity {:.0}%", data_weight * 100.0),
                pqc_status: "n/a".into(),
                risk: data_weight * 100.0,
                blast_radius: 0.0,
                observed: false,
            },
        );
        edges.push(Edge {
            source: data_id.clone(),
            target: agent_id.clone(),
            kind: "handles".into(),
            observed: false,
        });

        // Identity → agent edges (who can drive this agent).
        for (ident, role) in &identities {
            edges.push(Edge {
                source: format!("identity:{ident}"),
                target: agent_id.clone(),
                kind: "can-access".into(),
                observed: false,
            });
            // Access-risk: an over-privileged non-human identity reaching a sensitive agent.
            if ident.starts_with("apikey:")
                && (role == "admin" || role == "operator")
                && data_weight >= 0.65
            {
                let score = (data_weight * 60.0 * 10.0).round() / 10.0;
                paths.push(AttackPath {
                    id: format!("access:{ident}->{name}"),
                    title: format!("Over-privileged key '{ident}' can drive {name} ({data_label})"),
                    severity: severity_for(score).into(), score, hndl: false, observed: false, request_count: 0,
                    kind: "access-risk".into(), data_class: data_label.into(), agent: name.clone(),
                    provider: "—".into(), tls_version: None, channel_pqc: PqcStatus::Unknown,
                    node_ids: vec![format!("identity:{ident}"), agent_id.clone(), data_id.clone()],
                    recommendation: format!("Scope the '{ident}' API key to least privilege; it can trigger flows handling {data_label}."),
                });
            }
        }

        // Union of policy-allowed and observed providers.
        let mut agent_providers = providers_for_models(&agent.allowed_models);
        for f in flows {
            if f.agent == *name {
                agent_providers.insert(f.provider.clone());
            }
        }

        for p in &agent_providers {
            let provider_id = format!("provider:{p}");
            if !seen.contains(&provider_id) {
                let st = overrides.get(p).cloned().unwrap_or(PqcStatus::Unknown);
                push(
                    &mut nodes,
                    &mut seen,
                    Node {
                        id: provider_id.clone(),
                        kind: "provider".into(),
                        label: p.clone(),
                        sublabel: "not yet scanned".into(),
                        pqc_status: st.to_string(),
                        risk: channel_weight(&st) * 100.0,
                        blast_radius: 0.0,
                        observed: observed_providers.contains(p),
                    },
                );
            }
            let (reqs, sens) = flow_map
                .get(&(name.clone(), p.clone()))
                .copied()
                .unwrap_or((0, 0));
            let observed = reqs > 0;
            edges.push(Edge {
                source: agent_id.clone(),
                target: provider_id.clone(),
                kind: "routes-to".into(),
                observed,
            });

            let channel_status = providers.get(p).map(|i| i.0).unwrap_or(PqcStatus::Unknown);
            let cw = channel_weight(&channel_status);
            if cw <= 0.0 {
                continue;
            }
            let exposure = if agent.offline { 0.35 } else { 1.0 };
            // Observed sensitive traffic amplifies the score (real, not just possible, exposure).
            let observed_boost = if sens > 0 {
                1.2
            } else if observed {
                1.08
            } else {
                1.0
            };
            let score = ((data_weight * cw * exposure * observed_boost).min(1.0) * 100.0 * 10.0)
                .round()
                / 10.0;
            if score < 15.0 {
                continue;
            }

            // Accumulate blast radius on the provider (and its cert).
            *blast.entry(provider_id.clone()).or_insert(0.0) +=
                data_weight * if observed { 1.3 } else { 1.0 };

            let hndl = matches!(
                channel_status,
                PqcStatus::ClassicalSecure | PqcStatus::ClassicalWeak
            );
            paths.push(AttackPath {
                id: format!("flow:{name}->{p}"),
                title: format!("{data_label} reaches {p} over a quantum-vulnerable channel"),
                severity: severity_for(score).into(), score, hndl, observed, request_count: reqs,
                kind: "data-exposure".into(), data_class: data_label.into(), agent: name.clone(),
                provider: p.clone(), tls_version: providers.get(p).map(|i| i.1.clone()),
                channel_pqc: channel_status,
                node_ids: vec![data_id.clone(), agent_id.clone(), provider_id],
                recommendation: if hndl {
                    format!("Enable hybrid ML-KEM (X25519+ML-KEM-768) on the {p} channel. {}{data_label} is exposed to harvest-now-decrypt-later capture.",
                        if observed { format!("{reqs} real request(s) observed. ") } else { String::new() })
                } else {
                    format!("Characterize the {p} channel; treat as quantum-vulnerable until proven PQC/hybrid.")
                },
            });
        }
    }

    // External assets: weak/classical dependencies discovered by the scanners.
    let mut dep_seen: BTreeSet<String> = BTreeSet::new();
    for f in &findings {
        if matches!(f.asset_type, CryptoAssetType::CryptoLibrary)
            && matches!(
                f.pqc_status,
                PqcStatus::ClassicalWeak | PqcStatus::ClassicalSecure
            )
        {
            let lib = f.title.replace("Crypto dependency: ", "");
            if !dep_seen.insert(lib.clone()) {
                continue;
            }
            let did = format!("dependency:{lib}");
            let cw = channel_weight(&f.pqc_status);
            push(
                &mut nodes,
                &mut seen,
                Node {
                    id: did.clone(),
                    kind: "dependency".into(),
                    label: lib.clone(),
                    sublabel: f.location.clone(),
                    pqc_status: f.pqc_status.to_string(),
                    risk: cw * 100.0,
                    blast_radius: 0.0,
                    observed: false,
                },
            );
            if matches!(f.pqc_status, PqcStatus::ClassicalWeak) {
                let score = (cw * 45.0 * 10.0).round() / 10.0;
                paths.push(AttackPath {
                    id: format!("asset:{lib}"),
                    title: format!("Weak cryptographic dependency: {lib}"),
                    severity: severity_for(score).into(),
                    score,
                    hndl: false,
                    observed: false,
                    request_count: 0,
                    kind: "external-asset".into(),
                    data_class: "Codebase".into(),
                    agent: "—".into(),
                    provider: "—".into(),
                    tls_version: None,
                    channel_pqc: f.pqc_status,
                    node_ids: vec![did],
                    recommendation: format!(
                        "Replace {lib} with a maintained, PQC-capable library ({}).",
                        f.location
                    ),
                });
            }
        }
    }

    // External infrastructure assets (from connectors / declared inventory).
    for a in inputs.assets {
        let status = parse_status(&a.pqc_status);
        let cw = channel_weight(&status);
        let air = is_air_gapped(&a.tags);
        let aid = format!("asset:{}", a.id);
        push(
            &mut nodes,
            &mut seen,
            Node {
                id: aid.clone(),
                kind: "asset".into(),
                label: a.id.clone(),
                sublabel: if air {
                    format!("{} · {} · air-gapped", a.kind, a.environment)
                } else {
                    format!("{} · {}", a.kind, a.environment)
                },
                pqc_status: a.pqc_status.clone(),
                // No network path -> no HNDL exposure, so no channel risk.
                risk: if air { 0.0 } else { cw * 100.0 },
                blast_radius: 0.0,
                observed: false,
            },
        );
        if cw > 0.0 && !air {
            let env_weight = if a.environment.to_lowercase().contains("prod")
                || a.tags
                    .iter()
                    .any(|t| t.contains("external") || t.contains("customer"))
            {
                0.95
            } else {
                0.6
            };
            let score = (cw * env_weight * 100.0 * 10.0).round() / 10.0;
            if score >= 15.0 {
                let hndl = matches!(
                    status,
                    PqcStatus::ClassicalSecure | PqcStatus::ClassicalWeak
                );
                paths.push(AttackPath {
                    id: format!("asset:{}", a.id),
                    title: format!("{} ({}) exposes a quantum-vulnerable channel", a.id, a.kind),
                    severity: severity_for(score).into(),
                    score,
                    hndl,
                    observed: false,
                    request_count: 0,
                    kind: "external-asset".into(),
                    data_class: a.environment.clone(),
                    agent: "—".into(),
                    provider: a.address.clone(),
                    tls_version: a.tls_version.clone(),
                    channel_pqc: status,
                    node_ids: vec![aid],
                    recommendation: format!(
                        "Enable hybrid ML-KEM on {} ({}). {}",
                        a.address,
                        a.environment,
                        if hndl {
                            "Quantum-vulnerable and harvestable today."
                        } else {
                            "Characterize and treat as vulnerable until proven PQC."
                        }
                    ),
                });
            }
        }
    }

    // Estate hosts — registered systems, their exposed/internal services, and
    // (from the authenticated deep inventory) the containers running on them.
    // A network sweep sees exposed ports; a deep scan adds the loopback-only
    // services and containers, so a single host fans out into a whole subgraph.
    for t in inputs.targets {
        // Key the host subgraph by the target's stable id, NOT its host address:
        // two distinct targets can share an IP (re-registration, NAT, a bastion
        // fronting several logical hosts), and keying by host would collapse them
        // into one node and mint duplicate path ids — which also corrupts drift
        // detection. The host address stays in the label/title for readability.
        let host_id = format!("host:{}", t.id);
        let host_status = parse_status(&t.pqc_status);
        let host_air = is_air_gapped(&t.tags);
        let prod = t.environment.to_lowercase().contains("prod")
            || t.tags
                .iter()
                .any(|x| x.contains("external") || x.contains("customer"));
        let env_weight = if prod { 0.95 } else { 0.6 };
        push(
            &mut nodes,
            &mut seen,
            Node {
                id: host_id.clone(),
                kind: "host".into(),
                label: t.name.clone(),
                sublabel: if host_air {
                    format!("{} · {} · air-gapped", t.host, t.environment)
                } else {
                    match &t.host_info {
                        Some(info) if !info.is_empty() => format!("{} · {}", t.host, info),
                        _ => format!("{} · {} · {}", t.host, t.kind, t.environment),
                    }
                },
                pqc_status: t.pqc_status.clone(),
                risk: if host_air {
                    0.0
                } else {
                    channel_weight(&host_status) * 100.0
                },
                blast_radius: 0.0,
                observed: false,
            },
        );

        for s in &t.exposed_services {
            let svc_status = parse_status(&s.pqc_status);
            let sid = format!("service:{}:{}", t.id, s.port);
            push(
                &mut nodes,
                &mut seen,
                Node {
                    id: sid.clone(),
                    kind: "service".into(),
                    label: format!(":{} {}", s.port, s.service),
                    sublabel: format!(
                        "{} · {}",
                        t.host,
                        if s.exposed {
                            "exposed"
                        } else {
                            "internal (loopback)"
                        }
                    ),
                    pqc_status: s.pqc_status.clone(),
                    risk: channel_weight(&svc_status) * 100.0,
                    blast_radius: 0.0,
                    observed: false,
                },
            );
            edges.push(Edge {
                source: host_id.clone(),
                target: sid.clone(),
                kind: "exposes".into(),
                observed: false,
            });

            // Only network-reachable services are attack *paths*; loopback-only
            // services are graph nodes (blast radius on host compromise) but not
            // externally exploitable, so they don't inflate the risk work-list.
            let cw = channel_weight(&svc_status);
            // Air-gapped host: no reachable channel, so no HNDL attack path.
            if !s.exposed || cw <= 0.0 || host_air {
                continue;
            }
            // Unknown crypto (not yet fingerprinted) is a "characterize", not a
            // confirmed weakness — discount it so it doesn't outrank real ones.
            let known = !matches!(svc_status, PqcStatus::Unknown);
            let known_mult = if known { 1.0 } else { 0.55 };
            let score = (cw * env_weight * known_mult * 100.0 * 10.0).round() / 10.0;
            if score < 15.0 {
                continue;
            }
            *blast.entry(host_id.clone()).or_insert(0.0) += cw * env_weight;
            let hndl = matches!(
                svc_status,
                PqcStatus::ClassicalSecure | PqcStatus::ClassicalWeak
            );
            paths.push(AttackPath {
                id: format!("service:{}:{}", t.id, s.port),
                title: format!("{}:{} ({}) exposes a quantum-vulnerable channel", t.host, s.port, s.service),
                severity: severity_for(score).into(),
                score,
                hndl,
                observed: false,
                request_count: 0,
                kind: "external-asset".into(),
                data_class: t.environment.clone(),
                agent: "—".into(),
                provider: format!("{}:{}", t.host, s.port),
                tls_version: None,
                channel_pqc: svc_status,
                node_ids: vec![host_id.clone(), sid],
                recommendation: if hndl {
                    format!("Terminate {}:{} behind the QuantaWatch PQC overlay or issue it a hybrid ML-DSA certificate — harvestable today.", t.host, s.port)
                } else {
                    format!("Fingerprint {}:{} and treat as quantum-vulnerable until proven PQC/hybrid.", t.host, s.port)
                },
            });
        }

        for c in &t.containers {
            let cid = format!("container:{}:{}", t.id, c.name);
            push(
                &mut nodes,
                &mut seen,
                Node {
                    id: cid.clone(),
                    kind: "container".into(),
                    label: c.name.clone(),
                    sublabel: c.image.clone(),
                    pqc_status: "n/a".into(),
                    risk: 0.0,
                    blast_radius: 0.0,
                    observed: false,
                },
            );
            edges.push(Edge {
                source: host_id.clone(),
                target: cid,
                kind: "runs".into(),
                observed: false,
            });
        }
    }

    // Fold blast radius back onto provider/cert nodes.
    for n in nodes.iter_mut() {
        if let Some(b) = blast.get(&n.id) {
            n.blast_radius = (b * 10.0).round() / 10.0;
        }
    }

    paths.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Graph {
        nodes,
        edges,
        paths,
    }
}

pub fn summarize(paths: &[AttackPath]) -> serde_json::Value {
    let c = |s: &str| paths.iter().filter(|p| p.severity == s).count();
    json!({
        "total": paths.len(),
        "critical": c("critical"), "high": c("high"), "medium": c("medium"), "low": c("low"),
        "hndl": paths.iter().filter(|p| p.hndl).count(),
        "observed": paths.iter().filter(|p| p.observed).count(),
    })
}

// ---- Exploitability + crypto kill-chain ----
//
// `score` measures crypto severity; `exploitability` measures how realistically
// an attacker can *execute* the path — reachability (observed / internet-facing)
// × data value × channel weakness. A PQC-ready channel scores ~0 exploitability
// even if adjacent findings look scary, because there is no crypto weakness to
// exploit. Paths are re-ranked by exploitability so the work list reflects
// real-world risk, not algorithm severity alone — a story a list-of-findings
// scanner can't tell.

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KillChainStage {
    pub stage: u8,
    pub key: &'static str,
    pub label: &'static str,
    pub detail: String,
    /// active | feasible | pending | blocked | na
    pub status: &'static str,
}

fn data_value_for_label(label: &str) -> f64 {
    match label {
        "Broad / Privileged Access" | "Financial Data" => 1.0,
        "Customer PII" => 0.95,
        "Production" | "production" => 0.9,
        "Internal Data" => 0.7,
        "Source Code" => 0.65,
        "Codebase" => 0.6,
        "General Data" => 0.5,
        "Staging" | "staging" => 0.45,
        "Public Data" => 0.2,
        _ => 0.6,
    }
}

/// Returns (exploitability, reachability), both 0–100.
fn exploitability_of(p: &AttackPath) -> (f64, f64) {
    let reach = if p.observed {
        1.0
    } else if p.kind == "external-asset" {
        0.85
    } else {
        0.55
    };
    let val = data_value_for_label(&p.data_class);
    let expl = if p.kind == "access-risk" {
        // Identity over-privilege is directly exploitable, not channel-gated.
        100.0 * reach * val * 0.75
    } else {
        100.0 * reach * val * channel_weight(&p.channel_pqc)
    };
    (expl.round(), (reach * 100.0).round())
}

/// The staged HNDL / access-abuse kill chain for one attack path — the same
/// stages the web dashboard renders, exposed so native callers can show them
/// without going through the JSON in [`enrich_paths`].
pub fn kill_chain(p: &AttackPath) -> Vec<KillChainStage> {
    kill_chain_of(p)
}

fn kill_chain_of(p: &AttackPath) -> Vec<KillChainStage> {
    if p.kind == "access-risk" {
        return vec![
            KillChainStage {
                stage: 1,
                key: "acquire",
                label: "Acquire credential",
                detail: format!("Compromise the over-privileged key driving {}.", p.agent),
                status: "feasible",
            },
            KillChainStage {
                stage: 2,
                key: "pivot",
                label: "Pivot through agent",
                detail: format!("Use the agent's authority to reach {}.", p.data_class),
                status: "feasible",
            },
            KillChainStage {
                stage: 3,
                key: "impact",
                label: "Impact",
                detail: format!("Misuse or exfiltrate {}.", p.data_class),
                status: "feasible",
            },
        ];
    }
    let weak = channel_weight(&p.channel_pqc);
    let harvestable = weak > 0.1;
    vec![
        KillChainStage {
            stage: 1,
            key: "harvest",
            label: "Harvest",
            detail: format!(
                "Capture ciphertext from the {} channel ({}).",
                p.provider, p.channel_pqc
            ),
            status: if p.observed {
                "active"
            } else if harvestable {
                "feasible"
            } else {
                "blocked"
            },
        },
        KillChainStage {
            stage: 2,
            key: "store",
            label: "Store",
            detail: "Archive the captured traffic for future decryption.".to_string(),
            status: if p.hndl {
                "active"
            } else if harvestable {
                "feasible"
            } else {
                "na"
            },
        },
        KillChainStage {
            stage: 3,
            key: "await_crqc",
            label: "Await CRQC",
            detail: "Wait for a cryptographically-relevant quantum computer.".to_string(),
            status: if harvestable { "pending" } else { "blocked" },
        },
        KillChainStage {
            stage: 4,
            key: "decrypt",
            label: "Decrypt",
            detail: "Recover the session key and plaintext once a CRQC exists.".to_string(),
            status: if weak > 0.5 {
                "feasible"
            } else if harvestable {
                "pending"
            } else {
                "blocked"
            },
        },
        KillChainStage {
            stage: 5,
            key: "impact",
            label: "Impact",
            detail: format!("Exposure of {}.", p.data_class),
            status: if harvestable { "feasible" } else { "blocked" },
        },
    ]
}

/// Serialize paths with exploitability + kill-chain, re-ranked by exploitability
/// (crypto severity breaks ties).
pub fn enrich_paths(paths: &[AttackPath]) -> Vec<serde_json::Value> {
    let mut rows: Vec<(f64, f64, serde_json::Value)> = paths
        .iter()
        .map(|p| {
            let (expl, reach) = exploitability_of(p);
            let mut val = serde_json::to_value(p).unwrap_or_else(|_| json!({}));
            if let Some(obj) = val.as_object_mut() {
                obj.insert("exploitability".into(), json!(expl));
                obj.insert("reachability".into(), json!(reach));
                obj.insert("killChain".into(), json!(kill_chain_of(p)));
            }
            (expl, p.score, val)
        })
        .collect();
    rows.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
    });
    rows.into_iter().map(|(_, _, v)| v).collect()
}

#[cfg(test)]
mod airgap_tests {
    use super::*;

    fn host(air_gapped: bool) -> qw_store::TargetRow {
        let tags = if air_gapped { "[\"air-gapped\"]" } else { "[]" };
        let json = format!(
            r#"{{
                "id":"h1","name":"web","host":"10.0.0.5","kind":"server",
                "reachability":["tls"],"environment":"production","tags":{tags},
                "exposedServices":[{{"port":443,"service":"https","pqcStatus":"classical_weak",
                    "detail":"TLS 1.2 RSA","source":"network","exposed":true}}],
                "containers":[],"pqcStatus":"classical_weak","createdAt":"2026-01-01T00:00:00Z"
            }}"#
        );
        serde_json::from_str(&json).expect("valid target json")
    }

    fn paths_touching_host(air_gapped: bool) -> usize {
        let t = host(air_gapped);
        let inputs = GraphInputs {
            providers: vec![],
            identities: vec![],
            agents: vec![],
            flows: &[],
            findings: &[],
            assets: &[],
            targets: std::slice::from_ref(&t),
        };
        let g = build_graph(&inputs, &HashMap::new());
        g.paths
            .iter()
            .filter(|p| p.node_ids.iter().any(|n| n == "host:h1"))
            .count()
    }

    #[test]
    fn exposed_weak_host_produces_an_attack_path() {
        assert!(
            paths_touching_host(false) > 0,
            "an internet-exposed quantum-weak service must yield an attack path"
        );
    }

    #[test]
    fn air_gapped_host_drops_the_attack_path() {
        assert_eq!(
            paths_touching_host(true),
            0,
            "an air-gapped host has no harvestable channel, so no attack path"
        );
    }
}
