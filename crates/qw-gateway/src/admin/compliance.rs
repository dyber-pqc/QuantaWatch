//! Compliance & migration intelligence endpoints.

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    http::header,
    Json,
};
use serde_json::json;

use qw_cbom::{ComplianceEngine, ComplianceReport, PostureEngine};

use crate::state::AppState;

async fn build_report(state: &AppState, tenant: &str) -> ComplianceReport {
    let findings = state.store.all_findings(tenant);
    ComplianceEngine::assess(&findings)
}

pub async fn get_compliance(
    State(state): State<AppState>,
    ctx: Option<axum::Extension<crate::auth::AuthContext>>,
) -> impl IntoResponse {
    let tenant = crate::auth::tenant_of(&ctx);
    Json(json!(build_report(&state, &tenant).await))
}

/// Executive, print-ready HTML report. The browser's "Save as PDF" turns this
/// into a polished PDF without a server-side PDF dependency.
pub async fn get_report(
    State(state): State<AppState>,
    ctx: Option<axum::Extension<crate::auth::AuthContext>>,
) -> impl IntoResponse {
    let tenant = crate::auth::tenant_of(&ctx);
    let report = build_report(&state, &tenant).await;

    // Pull the live posture score for the headline if available.
    let posture_score = {
        let cache = state.posture_cache.read().await;
        cache.as_ref().map(|p| p.overall_score)
    };
    let providers: Vec<_> = state.provider_crypto.iter().map(|e| e.value().clone()).collect();
    let posture = posture_score
        .unwrap_or_else(|| PostureEngine::summarize(&[], &providers).overall_score);

    let html = render_report_html(&report, posture, &state.gateway_identity.fingerprint);
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(html),
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn priority_color(p: &str) -> &'static str {
    match p {
        "P0" => "#e76a6e",
        "P1" => "#f7894a",
        _ => "#8b8ef0",
    }
}

fn render_report_html(report: &ComplianceReport, posture: f64, fingerprint: &str) -> String {
    let date = report.generated_at.format("%Y-%m-%d %H:%M UTC");

    let framework_rows: String = report
        .frameworks
        .iter()
        .map(|f| {
            let deadline = f
                .nearest_deadline
                .map(|y| y.to_string())
                .unwrap_or_else(|| "—".to_string());
            format!(
                "<tr><td><strong>{}</strong><div class='sub'>{}</div></td>\
                 <td class='num'>{:.0}%</td>\
                 <td class='num ok'>{}</td><td class='num warn'>{}</td><td class='num bad'>{}</td>\
                 <td class='num'>{}</td></tr>",
                esc(&f.name),
                esc(&f.authority),
                f.compliance_pct,
                f.compliant,
                f.at_risk,
                f.non_compliant,
                deadline
            )
        })
        .collect();

    let migration_rows: String = report
        .migration_items
        .iter()
        .map(|m| {
            format!(
                "<tr>\
                 <td><span class='pill' style='background:{}'>{}</span></td>\
                 <td><strong>{}</strong><div class='sub'>{}</div>\
                   <div class='target'>&rarr; {}</div></td>\
                 <td class='num'>{}</td>\
                 <td class='num'>{}</td>\
                 <td>{}</td></tr>",
                priority_color(&m.priority),
                esc(&m.priority),
                esc(&m.title),
                esc(&m.current_state),
                esc(&m.target_state),
                m.affected_count,
                m.deadline_year,
                esc(&m.frameworks.join(", "))
            )
        })
        .collect();

    let migration_section = if report.migration_items.is_empty() {
        "<p class='empty'>No migration actions required — all assessed assets are quantum-safe.</p>".to_string()
    } else {
        format!(
            "<table><thead><tr><th>Priority</th><th>Action</th><th>Assets</th><th>Deadline</th><th>Frameworks</th></tr></thead><tbody>{migration_rows}</tbody></table>"
        )
    };

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>QuantaWatch — Cryptographic Compliance Report</title>
<style>
  @page {{ size: A4; margin: 18mm; }}
  * {{ box-sizing: border-box; }}
  html {{ color-scheme: light; background:#ffffff; }}
  body {{ font-family: "Segoe UI", Arial, sans-serif; color: #1f2024; background:#ffffff; padding: 32px; max-width: 900px; margin: 0 auto; }}
  .brand {{ display:flex; align-items:center; gap:12px; border-bottom:3px solid #5b5fc7; padding-bottom:16px; }}
  .logo {{ width:36px;height:36px;border-radius:8px;background:#5b5fc7;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px; }}
  h1 {{ font-size:20px; margin:0; }}
  .muted {{ color:#6b6b6f; font-size:12px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.06em; color:#5b5fc7; margin:28px 0 10px; }}
  .cards {{ display:flex; gap:14px; margin-top:18px; }}
  .card {{ flex:1; border:1px solid #e3e3e8; border-radius:10px; padding:14px; }}
  .card .big {{ font-size:30px; font-weight:700; }}
  .card .lbl {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#6b6b6f; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:#6b6b6f; border-bottom:1px solid #e3e3e8; padding:8px 10px; }}
  td {{ padding:10px; border-bottom:1px solid #eee; vertical-align:top; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }}
  .ok {{ color:#1a7f52; }} .warn {{ color:#b9770a; }} .bad {{ color:#c0353a; }}
  .sub {{ color:#6b6b6f; font-size:11px; margin-top:2px; }}
  .target {{ color:#4f52b2; font-size:11px; margin-top:3px; }}
  .pill {{ color:#fff; font-weight:700; font-size:11px; padding:2px 8px; border-radius:6px; }}
  .empty {{ color:#1a7f52; }}
  .foot {{ margin-top:30px; border-top:1px solid #e3e3e8; padding-top:12px; font-size:10px; color:#8a8a8e; }}
  .noprint {{ margin:18px 0; }}
  button {{ background:#5b5fc7;color:#fff;border:0;border-radius:6px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer; }}
  @media print {{ .noprint {{ display:none; }} body {{ padding:0; }} }}
</style></head>
<body>
  <div class="noprint"><button onclick="window.print()">Print / Save as PDF</button></div>
  <div class="brand">
    <div class="logo">Q</div>
    <div><h1>Cryptographic Compliance Report</h1>
    <div class="muted">QuantaWatch — Post-Quantum Posture Management · generated {date}</div></div>
  </div>

  <div class="cards">
    <div class="card"><div class="lbl">Overall Posture</div><div class="big">{posture:.0}</div></div>
    <div class="card"><div class="lbl">CNSA 2.0 Compliance</div><div class="big">{compliance:.0}%</div></div>
    <div class="card"><div class="lbl">Non-Compliant Assets</div><div class="big">{noncompliant}</div></div>
    <div class="card"><div class="lbl">Migration Actions</div><div class="big">{actions}</div></div>
  </div>

  <h2>Framework Compliance</h2>
  <table><thead><tr><th>Framework</th><th class="num">Compliant</th><th class="num">Pass</th><th class="num">At Risk</th><th class="num">Fail</th><th class="num">Deadline</th></tr></thead>
  <tbody>{framework_rows}</tbody></table>

  <h2>Prioritized Migration Roadmap</h2>
  {migration_section}

  <div class="foot">
    Assessed {total} cryptographic findings against CNSA 2.0, NIST IR 8547, and FIPS 203/204.
    Report integrity anchored to gateway ML-DSA-65 identity {fp}.
    This document is generated from live, continuously-attested inventory.
  </div>
</body></html>"#,
        date = date,
        posture = posture,
        compliance = report.overall_compliance_pct,
        noncompliant = report.non_compliant,
        actions = report.migration_items.len(),
        framework_rows = framework_rows,
        migration_section = migration_section,
        total = report.total_findings,
        fp = &fingerprint[..fingerprint.len().min(16)],
    )
}
