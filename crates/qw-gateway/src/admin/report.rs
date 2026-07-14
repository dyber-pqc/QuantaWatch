//! Executive "Quantum Risk" board report — folds posture, attack paths,
//! compliance, migration roadmap, and a signed attestation into one deliverable.

use std::collections::HashMap;

use axum::{
    extract::State,
    http::header,
    response::{Html, IntoResponse},
    Extension,
};

use qw_cbom::{ComplianceEngine, PostureEngine};

use crate::auth::{tenant_of, AuthContext};
use crate::state::AppState;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn sev_color(s: &str) -> &'static str {
    match s {
        "critical" => "#c0353a",
        "high" => "#c2671a",
        "medium" => "#b9770a",
        _ => "#5b5fc7",
    }
}

pub async fn board_report(
    State(state): State<AppState>,
    ctx: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    let tenant = tenant_of(&ctx);

    // Posture.
    let providers: Vec<_> = state
        .provider_crypto
        .iter()
        .map(|e| e.value().clone())
        .collect();
    let posture = {
        let cache = state.posture_cache.read().await;
        cache
            .as_ref()
            .map(|p| p.overall_score)
            .unwrap_or_else(|| PostureEngine::summarize(&[], &providers).overall_score)
    };

    // Attack paths.
    let graph = crate::admin::graph::build_graph(&state, &tenant, &HashMap::new());
    let critical_paths = graph
        .paths
        .iter()
        .filter(|p| p.severity == "critical")
        .count();
    let hndl = graph.paths.iter().filter(|p| p.hndl).count();

    // Compliance.
    let findings = state.store.all_findings(&tenant);
    let compliance = ComplianceEngine::assess(&findings);

    // Attestation over the current CBOM.
    let bom = crate::admin::cbom::build_cbom(&state);
    let att = bom.attestation.clone();

    // Composite Quantum Risk Score: posture, compliance, and critical exposure.
    let exposure_penalty = (critical_paths as f64 * 8.0).min(40.0);
    let quantum_risk = ((posture * 0.5 + compliance.overall_compliance_pct * 0.5)
        - exposure_penalty)
        .clamp(0.0, 100.0);
    let grade = if quantum_risk >= 80.0 {
        ("A", "#1a7f52")
    } else if quantum_risk >= 60.0 {
        ("B", "#b9770a")
    } else if quantum_risk >= 40.0 {
        ("C", "#c2671a")
    } else {
        ("D", "#c0353a")
    };

    let path_rows: String = graph.paths.iter().take(8).map(|p| {
        format!("<tr><td><span class='pill' style='background:{}'>{}</span></td><td><strong>{}</strong>{}</td><td class='num'>{}</td><td>{}</td></tr>",
            sev_color(&p.severity), esc(&p.severity), esc(&p.title),
            if p.observed { format!("<div class='sub'>observed · {} request(s)</div>", p.request_count) } else { String::new() },
            p.score, if p.hndl { "HNDL" } else { "—" })
    }).collect();

    let fw_rows: String = compliance.frameworks.iter().map(|f| {
        format!("<tr><td><strong>{}</strong> <span class='sub'>{}</span></td><td class='num'>{:.0}%</td><td class='num'>{}</td></tr>",
            esc(&f.name), esc(&f.authority), f.compliance_pct, f.nearest_deadline.map(|y| y.to_string()).unwrap_or_else(|| "—".into()))
    }).collect();

    let mig_rows: String = compliance.migration_items.iter().take(6).map(|m| {
        format!("<tr><td><span class='pill' style='background:{}'>{}</span></td><td><strong>{}</strong><div class='sub'>&rarr; {}</div></td><td class='num'>{}</td><td class='num'>{}</td></tr>",
            if m.priority == "P0" { "#c0353a" } else if m.priority == "P1" { "#c2671a" } else { "#5b5fc7" },
            esc(&m.priority), esc(&m.title), esc(&m.target_state), m.affected_count, m.deadline_year)
    }).collect();

    let att_block = match &att {
        Some(a) => format!(
            "Cryptographically attested: {} signature over BOM digest {}… by gateway identity {}. Nonce {}.",
            esc(&a.algorithm), esc(&a.bom_digest[..a.bom_digest.len().min(20)]), esc(&a.signer_fingerprint[..a.signer_fingerprint.len().min(16)]), esc(&a.nonce[..a.nonce.len().min(12)])),
        None => "Attestation unavailable.".to_string(),
    };

    let date = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");

    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>QuantaWatch — Quantum Risk Board Report</title>
<style>
  @page {{ size: A4; margin: 16mm; }}
  html {{ color-scheme: light; background:#fff; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family:"Segoe UI",Arial,sans-serif; color:#1f2024; background:#fff; padding:32px; max-width:900px; margin:0 auto; }}
  .brand {{ display:flex; align-items:center; gap:12px; border-bottom:3px solid #5b5fc7; padding-bottom:16px; }}
  .logo {{ width:38px;height:38px;border-radius:8px;background:#5b5fc7;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:19px; }}
  h1 {{ font-size:21px; margin:0; }} .muted {{ color:#6b6b6f; font-size:12px; }}
  h2 {{ font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:#5b5fc7; margin:26px 0 8px; }}
  .hero {{ display:flex; gap:16px; margin-top:20px; align-items:stretch; }}
  .grade {{ width:130px; border-radius:12px; color:#fff; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:14px; }}
  .grade .g {{ font-size:44px; font-weight:800; line-height:1; }}
  .kpis {{ flex:1; display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }}
  .kpi {{ border:1px solid #e3e3e8; border-radius:10px; padding:12px; }}
  .kpi .n {{ font-size:26px; font-weight:700; }} .kpi .l {{ font-size:10px; text-transform:uppercase; letter-spacing:.05em; color:#6b6b6f; }}
  table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  th {{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.04em; color:#6b6b6f; border-bottom:1px solid #e3e3e8; padding:7px 9px; }}
  td {{ padding:9px; border-bottom:1px solid #eee; vertical-align:top; }} td.num {{ text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }}
  .sub {{ color:#6b6b6f; font-size:10.5px; margin-top:2px; }}
  .pill {{ color:#fff; font-weight:700; font-size:10px; padding:2px 7px; border-radius:6px; }}
  .foot {{ margin-top:28px; border-top:1px solid #e3e3e8; padding-top:12px; font-size:10px; color:#7a7a7e; }}
  .noprint {{ margin-bottom:14px; }} button {{ background:#5b5fc7;color:#fff;border:0;border-radius:6px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer; }}
  @media print {{ .noprint {{ display:none; }} body {{ padding:0; }} }}
</style></head><body>
  <div class="noprint"><button onclick="window.print()">Print / Save as PDF</button></div>
  <div class="brand"><div class="logo">Q</div><div>
    <h1>Quantum Risk — Board Report</h1>
    <div class="muted">QuantaWatch · Post-Quantum Posture Management · tenant "{tenant}" · {date}</div></div></div>

  <div class="hero">
    <div class="grade" style="background:{grade_color}"><div class="g">{grade}</div><div style="font-size:11px;margin-top:4px">QUANTUM RISK</div><div style="font-size:20px;font-weight:700;margin-top:6px">{quantum_risk:.0}</div></div>
    <div class="kpis">
      <div class="kpi"><div class="l">Posture</div><div class="n">{posture:.0}</div></div>
      <div class="kpi"><div class="l">CNSA 2.0</div><div class="n">{compliance:.0}%</div></div>
      <div class="kpi"><div class="l">Critical Paths</div><div class="n">{critical_paths}</div></div>
      <div class="kpi"><div class="l">HNDL Exposures</div><div class="n">{hndl}</div></div>
    </div>
  </div>

  <h2>Top Attack Paths (Harvest-Now-Decrypt-Later)</h2>
  <table><thead><tr><th>Severity</th><th>Exposure Path</th><th class="num">Score</th><th>HNDL</th></tr></thead><tbody>{path_rows}</tbody></table>

  <h2>Framework Compliance</h2>
  <table><thead><tr><th>Framework</th><th class="num">Compliant</th><th class="num">Deadline</th></tr></thead><tbody>{fw_rows}</tbody></table>

  <h2>Prioritized Migration Roadmap</h2>
  <table><thead><tr><th>Priority</th><th>Action</th><th class="num">Assets</th><th class="num">By</th></tr></thead><tbody>{mig_rows}</tbody></table>

  <div class="foot">{att_block}<br/>Generated from live, continuously-attested inventory. {total} cryptographic findings assessed against CNSA 2.0, NIST IR 8547 and FIPS 203/204.</div>
</body></html>"#,
        tenant = esc(&tenant),
        date = date,
        grade = grade.0,
        grade_color = grade.1,
        quantum_risk = quantum_risk,
        posture = posture,
        compliance = compliance.overall_compliance_pct,
        critical_paths = critical_paths,
        hndl = hndl,
        path_rows = if path_rows.is_empty() {
            "<tr><td colspan=4 class='sub'>No attack paths detected.</td></tr>".into()
        } else {
            path_rows
        },
        fw_rows = fw_rows,
        mig_rows = if mig_rows.is_empty() {
            "<tr><td colspan=4 class='sub'>No migration actions required.</td></tr>".into()
        } else {
            mig_rows
        },
        att_block = att_block,
        total = compliance.total_findings,
    );

    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(html),
    )
}
