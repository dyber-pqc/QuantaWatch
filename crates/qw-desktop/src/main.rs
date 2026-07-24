//! QuantaWatch Desktop - a native (egui) view onto the local QuantaWatch store.
//!
//! Air-gap posture: this binary links `qw-store`/`qw-scanner`/`qw-cbom` directly
//! and reads the on-disk SQLite store **in-process**. There is no embedded
//! browser, no webview, and no network listener of any kind - nothing is served
//! and nothing is fetched. Point it at a data directory (arg 1, default
//! `./data`) that a gateway or the CLI has populated, or at a fresh one.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use chrono::{DateTime, Local, Utc};
use eframe::egui;

mod graphview;

use std::sync::mpsc::Receiver;
use std::sync::Arc;

use graphview::GraphView;
use qw_pki::CertAuthority;
use qw_audit::{AuditBackend, AuditEntry, AuditEvent};
use qw_cbom::{frameworks, soc2};
use qw_cbom::{ComplianceEngine, PostureEngine, PostureSnapshot};
use qw_scanner::types::{
    AssetLocation, CryptoAsset, Finding, FindingRecord, FindingSeverity, FindingStatus, PqcStatus,
    ScanRecord,
};
use qw_scanner::{build_scanner_registry, ScanTarget, ScannerConfig};
use qw_integrations::{IntegrationConfig, RemediationOpts, RemediationTicket};
use qw_store::{
    AlertEvent, AlertSeverity, AssetRow, CertificateRow, ConnectionRow, DbUser, EndpointRow,
    FlowRow, GovernanceSnapshot, OverlayRouteRow, SessionRow, SloSnapshot, Store, TargetRow,
    DEFAULT_TENANT,
};

const TENANT: &str = DEFAULT_TENANT;

/// "v0.1.0 · <githash> · 2026-07-23 17:20" - identifies the exact running build.
fn build_stamp() -> String {
    let unix: i64 = env!("QW_BUILD_UNIX").parse().unwrap_or(0);
    let when = chrono::DateTime::from_timestamp(unix, 0)
        .map(|d| d.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "?".to_string());
    format!("v{} · {} · {when}", env!("CARGO_PKG_VERSION"), env!("QW_GIT_HASH"))
}

/// Add-asset templates: (label, kind, default environment).
const ASSET_TEMPLATES: &[(&str, &str, &str)] = &[
    ("TLS endpoint", "tls_endpoint", "production"),
    ("Load balancer", "load_balancer", "production"),
    ("K8s ingress", "k8s_ingress", "production"),
    ("Object store (S3/GCS)", "object_store", "production"),
    ("Database", "database", "production"),
    ("KMS key", "kms_key", "production"),
    ("Certificate", "certificate", "production"),
];

/// Register-host templates: (label, kind, default environment).
const HOST_TEMPLATES: &[(&str, &str, &str)] = &[
    ("Server (SSH/TLS)", "server", "production"),
    ("Database host", "database", "production"),
    ("Network device", "network_device", "production"),
    ("Container host", "container", "production"),
    ("Endpoint / workstation", "endpoint", "corp"),
    ("VM", "vm", "production"),
];

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Headless self-check: exercise the exact main-thread crypto path (CA
    // identity load + hybrid certificate issue) that historically overflowed the
    // Windows main-thread stack, then exit. No window is created, so this runs in
    // CI without a display and guards the stack-size fix in qw-desktop/build.rs.
    if args.iter().any(|a| a == "--selfcheck") {
        std::process::exit(match self_check() {
            Ok(()) => {
                println!("selfcheck OK - main-thread ML-DSA cert issue succeeded");
                0
            }
            Err(e) => {
                eprintln!("selfcheck FAILED: {e:#}");
                1
            }
        });
    }

    let data_dir = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "./data".to_string());
    let db_path = std::path::Path::new(&data_dir).join("quantawatch.db");

    // Open the on-disk store; fall back to an empty in-memory one so the app
    // always launches (and says so) rather than failing on a missing DB.
    let (store, source) = match std::fs::create_dir_all(&data_dir)
        .map_err(anyhow::Error::from)
        .and_then(|_| Store::open(&db_path))
    {
        Ok(s) => (s, format!("{}", db_path.display())),
        Err(e) => (
            Store::open_in_memory().expect("in-memory store must open"),
            format!("(no store at {} - {e}; empty view)", db_path.display()),
        ),
    };

    // Headless board-report generation: assemble the executive report from the
    // local store and exit, no window. Useful for automation / air-gapped hosts.
    if args.iter().any(|a| a == "--board-report") {
        let mut app = App::new(store, source);
        app.export_board_report();
        println!("{}", app.export_status);
        std::process::exit(if app.export_status.contains("failed") { 1 } else { 0 });
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 820.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title(format!("QuantaWatch Desktop - {}", build_stamp())),
        ..Default::default()
    };

    eframe::run_native(
        "QuantaWatch Desktop",
        options,
        Box::new(move |cc| {
            setup_fonts(&cc.egui_ctx);
            install_theme(&cc.egui_ctx);
            Ok(Box::new(App::new(store, source)))
        }),
    )
}

/// Run the CA identity + hybrid-certificate-issue path on the process main
/// thread (in a throwaway temp dir) and verify it produces a hybrid cert.
///
/// This is deliberately the same sequence the UI runs on click, so if the
/// main-thread stack reserve (set in `build.rs`) is ever removed or shrunk below
/// what ML-DSA-65 needs, this fails with STATUS_STACK_OVERFLOW instead of the
/// regression reaching users. Invoked via `--selfcheck` from CI.
fn self_check() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("qw-desktop-selfcheck-{}", std::process::id()));
    let pki = dir.join("pki");
    std::fs::create_dir_all(&pki)?;
    let id = qw_crypto::GatewayIdentity::load_or_generate(&pki)?;
    let ca = qw_pki::CertAuthority::load_or_create(
        "QuantaWatch Desktop CA",
        &pki,
        std::sync::Arc::new(id),
    )?;
    let (row, key_pem) = ca.issue("selfcheck.internal", &[], 90, true)?;
    anyhow::ensure!(row.key_type == "hybrid", "expected hybrid cert");
    anyhow::ensure!(row.mldsa_signature.is_some(), "missing ML-DSA binding");
    anyhow::ensure!(key_pem.contains("PRIVATE KEY"), "missing leaf key");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ----------------------------------------------------------------------------- theme

pub(crate) mod theme {
    use eframe::egui::Color32;
    // Microsoft Teams / Fluent dark palette (matches the web dashboard).
    pub const BG: Color32 = Color32::from_rgb(0x1f, 0x1f, 0x1f);
    pub const PANEL: Color32 = Color32::from_rgb(0x2d, 0x2d, 0x2d);
    pub const CARD: Color32 = Color32::from_rgb(0x29, 0x29, 0x29);
    pub const ACCENT: Color32 = Color32::from_rgb(0x62, 0x64, 0xa7); // Teams purple
    pub const TEXT: Color32 = Color32::from_rgb(0xe6, 0xe6, 0xe6);
    pub const MUTED: Color32 = Color32::from_rgb(0x9a, 0x9a, 0x9a);
    pub const CRIT: Color32 = Color32::from_rgb(0xe7, 0x4c, 0x3c);
    pub const HIGH: Color32 = Color32::from_rgb(0xe6, 0x7e, 0x22);
    pub const MED: Color32 = Color32::from_rgb(0xd9, 0xb3, 0x06);
    pub const LOW: Color32 = Color32::from_rgb(0x3f, 0x9d, 0xd6);
    pub const GOOD: Color32 = Color32::from_rgb(0x2e, 0xcc, 0x71);
}

/// Bundle Cascadia Code (SIL OFL 1.1) as an extra glyph source: a symbol
/// fallback for proportional text and the primary monospace. egui's default
/// chain already carries NotoEmoji + emoji-icon-font for pictographic icons;
/// Cascadia adds the dashes/arrows/geometric symbols Ubuntu-Light lacks.
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "cascadia".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/CascadiaCode.ttf")),
    );
    if let Some(prop) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        prop.insert(1, "cascadia".to_owned()); // after Ubuntu-Light, before emoji
    }
    if let Some(mono) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
        mono.insert(0, "cascadia".to_owned());
    }
    ctx.set_fonts(fonts);
}

fn install_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(theme::TEXT);
    visuals.panel_fill = theme::BG;
    visuals.window_fill = theme::PANEL;
    visuals.extreme_bg_color = theme::CARD;
    visuals.widgets.noninteractive.bg_fill = theme::PANEL;
    visuals.selection.bg_fill = theme::ACCENT.linear_multiply(0.6);
    visuals.hyperlink_color = theme::ACCENT;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    ctx.set_style(style);
}

// ----------------------------------------------------------------------------- data

#[derive(Default)]
struct Snapshot {
    posture: Option<PostureSnapshot>,
    findings: Vec<FindingRecord>,
    targets: Vec<TargetRow>,
    certs: Vec<CertificateRow>,
    scans: Vec<ScanRecord>,
    flows: Vec<FlowRow>,
    assets: Vec<AssetRow>,
    endpoints: Vec<EndpointRow>,
    sessions: Vec<SessionRow>,
    connections: Vec<ConnectionRow>,
    overlay_routes: Vec<OverlayRouteRow>,
    remediations: Vec<RemediationTicket>,
    users: Vec<DbUser>,
    audit: Vec<AuditEntry>,
    alerts: Vec<AlertEvent>,
    slo_hist: Vec<SloSnapshot>,
    gov_hist: Vec<GovernanceSnapshot>,
    history: Vec<f64>,
    loaded_at: Option<DateTime<Local>>,
}

impl Snapshot {
    fn load(store: &Store) -> Self {
        let mut findings = store.all_findings(TENANT);
        // Worst-first so the table leads with what matters.
        findings.sort_by(|a, b| sev_rank(b.severity).cmp(&sev_rank(a.severity)));
        let mut scans = store.list_scans(TENANT, 200);
        scans.sort_by(|a, b| b.completed_at.cmp(&a.completed_at));
        // posture_history is newest-first; reverse to chronological for the chart.
        let mut hist: Vec<f64> = store
            .posture_history(TENANT, 60)
            .iter()
            .map(|s| s.overall_score)
            .collect();
        hist.reverse();
        Self {
            posture: store.latest_posture(TENANT),
            findings,
            targets: store.list_targets(TENANT),
            certs: store.list_certificates(TENANT),
            scans,
            flows: store.list_flows(TENANT),
            assets: store.list_assets(TENANT),
            endpoints: store.list_endpoints(TENANT),
            sessions: store.list_sessions(TENANT, 200),
            connections: store.list_connections(TENANT),
            overlay_routes: store.list_all_overlay_routes(),
            remediations: store.list_remediations(TENANT),
            users: store.list_users(),
            audit: store.list_entries(500),
            alerts: store.recent_alerts(TENANT, 200),
            // Histories come back newest-first; reverse to chronological for trends.
            slo_hist: {
                let mut h = store.slo_history(TENANT, 90);
                h.reverse();
                h
            },
            gov_hist: {
                let mut h = store.governance_history(TENANT, 90);
                h.reverse();
                h
            },
            history: hist,
            loaded_at: Some(Utc::now().with_timezone(&Local)),
        }
    }

    fn severity_counts(&self) -> [usize; 5] {
        let mut c = [0usize; 5]; // info, low, med, high, crit
        for f in &self.findings {
            c[sev_rank(f.severity) as usize] += 1;
        }
        c
    }
}

// ----------------------------------------------------------------------------- scan

/// Result of an in-process scan, handed back to the UI thread.
struct ScanOutcome {
    findings: usize,
    score: f64,
    error: Option<String>,
}

/// Run a fully-local scan of a code directory and persist the findings +
/// recomputed posture to the store. Runs on a worker thread (it owns its own
/// tokio runtime to drive the async scanners); reads local files only - no
/// network. Only the code + dependency scanners are enabled, and `scan_all`
/// runs just the scanners that support the target, so this never opens a socket.
fn run_scan_blocking(store: &Store, path: &str) -> ScanOutcome {
    let mut cfg = ScannerConfig::default();
    cfg.code.enabled = true;
    cfg.dependencies.enabled = true;
    let registry = build_scanner_registry(&cfg);

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            return ScanOutcome {
                findings: 0,
                score: 0.0,
                error: Some(format!("runtime: {e}")),
            }
        }
    };

    let target = ScanTarget::code_directory(path);
    let results = rt.block_on(registry.scan_all(&target));

    let mut total = 0usize;
    for r in &results {
        total += r.findings.len();
        store.record_scan(TENANT, r, &target);
    }
    let summary = PostureEngine::summarize(&results, &[]);
    store.record_posture(TENANT, &PostureSnapshot::from_summary(&summary, "desktop-scan"));

    ScanOutcome {
        findings: total,
        score: summary.overall_score,
        error: None,
    }
}

// ------------------------------------------------------------------- network ops

/// An outbound integration operation. These are the *only* things the desktop
/// does over the network, and only when Online mode is enabled.
enum NetOp {
    /// Verify a stored connection's token against its provider API.
    TestConnection { conn_id: String },
    /// Discover + scan a connection's repos for quantum-vulnerable crypto.
    ScanConnection { conn_id: String },
    /// File a remediation ticket/PR for a finding via a connected tracker.
    OpenTicket { finding_id: String, conn_id: String },
}

struct NetOutcome {
    message: String,
}

/// Convert a stored connection (with its decrypted token) into the config the
/// integration registry expects. Mirrors the gateway's `to_config`.
fn conn_to_config(c: &ConnectionRow) -> IntegrationConfig {
    let mut settings = std::collections::HashMap::new();
    if let Some(org) = &c.org {
        settings.insert("org".to_string(), org.clone());
    }
    if let Some(repo) = &c.repo {
        settings.insert("repo".to_string(), repo.clone());
    }
    IntegrationConfig {
        id: c.id.clone(),
        integration_type: c.integration_type.clone(),
        base_url: c.base_url.clone(),
        api_token_env: String::new(),
        token: Some(c.token.clone()),
        default_project: c.project.clone(),
        webhook_secret_env: None,
        settings,
    }
}

/// Reconstruct a scanner `Finding` from a stored record so it can be handed to
/// an integration's `create_remediation`. Mirrors the gateway's
/// `finding_from_record`.
fn finding_from_record(r: &FindingRecord) -> Finding {
    Finding {
        id: r.id.clone(),
        category: r.category.clone(),
        severity: r.severity.clone(),
        title: r.title.clone(),
        description: r.description.clone(),
        asset: CryptoAsset {
            id: format!("asset-{}", r.id),
            asset_type: r.asset_type.clone(),
            name: r.title.clone(),
            algorithm: r.algorithm.clone(),
            key_length: None,
            protocol_version: None,
            location: AssetLocation {
                source_type: "finding".to_string(),
                path: r.location.clone(),
                line: None,
            },
            discovered_by: "store".to_string(),
            discovered_at: r.created_at,
        },
        remediation: r.remediation.clone(),
        pqc_status: r.pqc_status,
        metadata: std::collections::HashMap::new(),
    }
}

/// Run one outbound integration op on a worker thread (owns its own tokio
/// runtime; the desktop's main thread never blocks). All store writes happen
/// here; the UI just refreshes on completion.
fn run_net_op_blocking(store: &Store, op: NetOp) -> NetOutcome {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return NetOutcome { message: format!("runtime error: {e}") },
    };
    match op {
        NetOp::TestConnection { conn_id } => {
            let Some(mut row) = store.get_connection(TENANT, &conn_id) else {
                return NetOutcome { message: "connection not found".to_string() };
            };
            let Some(integ) = qw_integrations::build_one(&conn_to_config(&row)) else {
                return NetOutcome { message: "could not construct integration".to_string() };
            };
            let msg = match rt.block_on(integ.test_connection()) {
                Ok(status) => {
                    row.last_status = Some(if status.connected { "connected" } else { "failed" }.to_string());
                    row.last_user = status.user.clone();
                    if status.connected {
                        format!(
                            "{} connected{}",
                            row.display_name,
                            status.user.map(|u| format!(" as {u}")).unwrap_or_default()
                        )
                    } else {
                        format!("{} failed: {}", row.display_name, status.error.unwrap_or_default())
                    }
                }
                Err(e) => {
                    row.last_status = Some("failed".to_string());
                    format!("{} test failed: {e}", row.display_name)
                }
            };
            row.last_tested = Some(Utc::now());
            store.upsert_connection(TENANT, &row);
            NetOutcome { message: msg }
        }
        NetOp::ScanConnection { conn_id } => {
            let Some(mut row) = store.get_connection(TENANT, &conn_id) else {
                return NetOutcome { message: "connection not found".to_string() };
            };
            let Some(integ) = qw_integrations::build_one(&conn_to_config(&row)) else {
                return NetOutcome { message: "could not construct integration".to_string() };
            };
            let mut cfg = ScannerConfig::default();
            cfg.code.enabled = true;
            cfg.dependencies.enabled = true;
            let registry = build_scanner_registry(&cfg);
            let res: Result<(usize, usize), String> = rt.block_on(async {
                let targets = integ.discover_targets().await.map_err(|e| e.to_string())?;
                let mut files = 0usize;
                let mut all = Vec::new();
                for target in &targets {
                    let content = match integ.fetch_content(target).await {
                        Ok(Some(c)) => c,
                        Ok(None) => continue,
                        Err(_) => continue,
                    };
                    let mut t = target.clone();
                    t.metadata.insert("content".to_string(), content);
                    let results = registry.scan_all(&t).await;
                    files += 1;
                    for r in &results {
                        store.record_scan(TENANT, r, &t);
                    }
                    all.extend(results);
                }
                let findings: usize = all.iter().map(|r| r.findings.len()).sum();
                let summary = PostureEngine::summarize(&all, &[]);
                store.record_posture(TENANT, &PostureSnapshot::from_summary(&summary, "desktop-connection-scan"));
                Ok((files, findings))
            });
            match res {
                Ok((files, findings)) => {
                    row.last_scanned = Some(Utc::now());
                    row.findings_count = Some(findings as u32);
                    store.upsert_connection(TENANT, &row);
                    NetOutcome {
                        message: format!("Scanned {}: {files} files, {findings} findings", row.display_name),
                    }
                }
                Err(e) => NetOutcome { message: format!("Scan of {} failed: {e}", row.display_name) },
            }
        }
        NetOp::OpenTicket { finding_id, conn_id } => {
            let Some(record) = store.get_finding(TENANT, &finding_id) else {
                return NetOutcome { message: "finding not found".to_string() };
            };
            let Some(row) = store.get_connection(TENANT, &conn_id) else {
                return NetOutcome { message: "connection not found".to_string() };
            };
            let Some(integ) = qw_integrations::build_one(&conn_to_config(&row)) else {
                return NetOutcome { message: "could not construct integration".to_string() };
            };
            // Attach the concrete PQC migration plan so the ticket carries the
            // specific fix, not a generic recommendation.
            let mut finding = finding_from_record(&record);
            if let Some(plan) = qw_cbom::plan_migration(&record) {
                finding.remediation = Some(qw_cbom::plan_to_markdown(&plan));
            }
            let opts = RemediationOpts {
                project: row.project.clone(),
                ..RemediationOpts::default()
            };
            match rt.block_on(integ.create_remediation(&finding, &opts)) {
                Ok(ticket) => {
                    store.record_remediation(TENANT, &ticket);
                    NetOutcome {
                        message: format!("Opened {} in {}", ticket.external_id, row.display_name),
                    }
                }
                Err(e) => NetOutcome { message: format!("Ticket failed: {e}") },
            }
        }
    }
}

// ----------------------------------------------------------------------------- app

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Overview,
    AttackPaths,
    Estate,
    Endpoints,
    Assets,
    Findings,
    Certificates,
    Cbom,
    Compliance,
    CryptoPolicies,
    Frameworks,
    Soc2,
    Governance,
    Scans,
    Remediations,
    Overlay,
    Connections,
    Agents,
    Sessions,
    Threats,
    Alerts,
    Audit,
    Access,
    Settings,
    About,
}

/// Result of a reachability probe. `reachable == None` means in progress.
#[derive(Clone)]
struct ProbeState {
    reachable: Option<bool>,
    detail: String,
}

/// What the right-hand detail panel is showing (by record id).
#[derive(Clone)]
enum Selection {
    Finding(String),
    Asset(String),
    Host(String),
    Scan(String),
    Endpoint(String),
    Session(String),
    Connection(String),
    Remediation(String),
    Cert(String),
    Alert(String),
}

enum TabAction {
    Select(Page),
    Close(Page),
    CloseRight(usize),
    CloseOthers(Page),
    CloseAll,
}

#[derive(Default)]
struct AssetForm {
    id: String,
    address: String,
    kind: String,
    environment: String,
    air_gapped: bool,
}

#[derive(Default)]
struct TargetForm {
    name: String,
    host: String,
    kind: String,
    environment: String,
    air_gapped: bool,
}

struct App {
    store: Store,
    source: String,
    page: Page,
    data: Snapshot,
    filter: String,
    selected: Option<Selection>,
    graph: GraphView,
    export_status: String,
    // IDE shell: editor tabs + bottom terminal.
    open_tabs: Vec<Page>,
    terminal_open: bool,
    terminal_float: bool,
    terminal_input: String,
    terminal_lines: Vec<String>,
    // Opt-in network reachability probes (leaves the air gap when enabled).
    net_probes_enabled: bool,
    probe_rx: Option<std::sync::mpsc::Receiver<(String, ProbeState)>>,
    probe_results: std::collections::HashMap<String, ProbeState>,
    // Async terminal output (e.g. tshark captures push lines here).
    term_tx: std::sync::mpsc::Sender<String>,
    term_rx: std::sync::mpsc::Receiver<String>,
    tshark_ver: Option<String>,
    asset_form: AssetForm,
    target_form: TargetForm,
    edit_status: String,
    // In-process scanning.
    scan_path: String,
    scanning: bool,
    scan_rx: Option<Receiver<ScanOutcome>>,
    scan_status: String,
    // Local PQC certificate authority (lazily created under <data>/pki on first
    // issue). Fully offline - issuing/renewing/revoking is local crypto.
    ca: Option<Arc<CertAuthority>>,
    cert_form: CertForm,
    cert_status: String,
    // The most recently issued leaf private key, shown exactly once (never stored).
    issued_key: Option<(String, String)>,
    // Outbound integration ops (Online mode only): connection tests, repo scans,
    // ticket creation. One at a time; result arrives on net_rx.
    net_rx: Option<Receiver<NetOutcome>>,
    net_busy: bool,
    net_status: String,
}

#[derive(Default)]
struct CertForm {
    subject: String,
    sans: String,
    validity_days: String,
    hybrid: bool,
}

/// A deferred action from a per-row certificate button, applied after the
/// (immutably-borrowed) table has finished rendering.
enum CertAction {
    Renew(String),
    Revoke(String),
}

impl App {
    fn new(store: Store, source: String) -> Self {
        // Collapse findings accumulated across scans (same as the gateway does at
        // startup): the store keys findings by a stable sha3(location|title) id,
        // so re-scans shouldn't pile up — but a store written before that was
        // enforced can carry duplicates. Clean them once here.
        let _ = store.dedupe_findings();
        let data = Snapshot::load(&store);
        let (term_tx, term_rx) = std::sync::mpsc::channel();
        Self {
            store,
            source,
            page: Page::Overview,
            data,
            filter: String::new(),
            selected: None,
            graph: GraphView::default(),
            export_status: String::new(),
            open_tabs: vec![Page::Overview],
            terminal_open: false,
            terminal_float: false,
            terminal_input: String::new(),
            terminal_lines: vec!["QuantaWatch console - type 'help' for commands.".to_string()],
            net_probes_enabled: false,
            probe_rx: None,
            probe_results: std::collections::HashMap::new(),
            term_tx,
            term_rx,
            tshark_ver: None,
            asset_form: AssetForm::default(),
            target_form: TargetForm::default(),
            edit_status: String::new(),
            scan_path: ".".to_string(),
            scanning: false,
            scan_rx: None,
            scan_status: String::new(),
            ca: None,
            cert_form: CertForm { validity_days: "90".to_string(), hybrid: true, ..Default::default() },
            cert_status: String::new(),
            issued_key: None,
            net_rx: None,
            net_busy: false,
            net_status: String::new(),
        }
    }

    fn refresh(&mut self) {
        self.data = Snapshot::load(&self.store);
    }

    /// Kick off a scan on a worker thread; the UI polls `scan_rx` for the result.
    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.scanning {
            return;
        }
        let path = self.scan_path.trim().to_string();
        if path.is_empty() {
            self.scan_status = "Enter a directory to scan.".to_string();
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.scan_rx = Some(rx);
        self.scanning = true;
        self.scan_status = format!("Scanning {path} ...");
        let store = self.store.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let outcome = run_scan_blocking(&store, &path);
            let _ = tx.send(outcome);
            ctx.request_repaint(); // wake the UI when the scan finishes
        });
    }

    /// Kick off an outbound integration op on a worker thread. Refuses unless
    /// Online mode is on (the air gap is explicit), and runs one at a time.
    fn spawn_net_op(&mut self, ctx: &egui::Context, op: NetOp, label: &str) {
        if !self.net_probes_enabled {
            self.net_status = "Online mode is off - enable it in Settings to make network calls.".to_string();
            return;
        }
        if self.net_busy {
            self.net_status = "A network operation is already running.".to_string();
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.net_rx = Some(rx);
        self.net_busy = true;
        self.net_status = format!("{label} ...");
        let store = self.store.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let outcome = run_net_op_blocking(&store, op);
            let _ = tx.send(outcome);
            ctx.request_repaint();
        });
    }

    fn poll_net(&mut self) {
        if let Some(rx) = &self.net_rx {
            if let Ok(outcome) = rx.try_recv() {
                self.net_status = outcome.message;
                self.net_busy = false;
                self.net_rx = None;
                self.refresh();
            }
        }
    }

    /// Write the current findings to a JSON file next to the store (local file,
    /// no network).
    fn export_findings(&mut self) {
        let dir = std::path::Path::new(&self.source)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join("quantawatch-findings.json");
        self.export_status = match serde_json::to_string_pretty(&self.data.findings) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(_) => format!("Exported {} findings to {}", self.data.findings.len(), path.display()),
                Err(e) => format!("Export failed: {e}"),
            },
            Err(e) => format!("Serialize failed: {e}"),
        };
    }

    /// Create/replace an asset in the store from the add-form.
    fn add_asset(&mut self) {
        let f = &self.asset_form;
        let (id, addr) = (f.id.trim(), f.address.trim());
        if id.is_empty() || addr.is_empty() {
            self.edit_status = "An asset needs an ID and an address.".to_string();
            return;
        }
        let asset = AssetRow {
            id: id.to_string(),
            kind: non_empty(&f.kind, "tls_endpoint"),
            address: addr.to_string(),
            environment: non_empty(&f.environment, "default"),
            tags: if f.air_gapped { vec!["air-gapped".to_string()] } else { Vec::new() },
            pqc_status: "unknown".to_string(),
            tls_version: None,
            last_scanned: None,
            source: "desktop".to_string(),
        };
        self.store.upsert_asset(TENANT, &asset);
        self.edit_status = format!("Saved asset {}", asset.id);
        self.asset_form = AssetForm::default();
        self.refresh();
    }

    /// Register/replace an estate host in the store from the add-form.
    fn add_target(&mut self) {
        let f = &self.target_form;
        let (name, host) = (f.name.trim(), f.host.trim());
        if name.is_empty() || host.is_empty() {
            self.edit_status = "A host needs a name and an address.".to_string();
            return;
        }
        let id = host.replace([':', '.', '/', ' '], "-");
        let target = TargetRow {
            id,
            name: name.to_string(),
            host: host.to_string(),
            kind: non_empty(&f.kind, "server"),
            reachability: vec!["tls".to_string()],
            environment: non_empty(&f.environment, "default"),
            tags: if f.air_gapped { vec!["air-gapped".to_string()] } else { Vec::new() },
            exposed_services: Vec::new(),
            containers: Vec::new(),
            host_info: None,
            deep_scanned: false,
            pqc_status: "unknown".to_string(),
            last_scanned: None,
            created_at: Utc::now(),
        };
        self.store.upsert_target(TENANT, &target);
        self.edit_status = format!("Registered host {}", target.name);
        self.target_form = TargetForm::default();
        self.refresh();
    }

    /// Flip an asset's air-gapped tag and persist.
    fn toggle_asset_airgap(&mut self, id: &str) {
        if let Some(mut a) = self.data.assets.iter().find(|a| a.id == id).cloned() {
            let on = toggle_tag(&mut a.tags, "air-gapped");
            self.store.upsert_asset(TENANT, &a);
            self.edit_status = format!("{} is now {}", a.id, if on { "air-gapped" } else { "exposed" });
            self.refresh();
        }
    }

    /// Flip a host's air-gapped tag and persist.
    fn toggle_target_airgap(&mut self, id: &str) {
        if let Some(mut t) = self.data.targets.iter().find(|t| t.id == id).cloned() {
            let on = toggle_tag(&mut t.tags, "air-gapped");
            self.store.upsert_target(TENANT, &t);
            self.edit_status = format!("{} is now {}", t.name, if on { "air-gapped" } else { "exposed" });
            self.refresh();
        }
    }

    /// Kick off a reachability probe (opt-in; leaves the air gap). Reports the
    /// result and cross-checks the air-gapped flag.
    fn start_probe(&mut self, id: String, addr: String, air_gapped: bool, ctx: &egui::Context) {
        if !self.net_probes_enabled {
            self.edit_status =
                "Network probes are off - enable them in Settings to verify reachability.".to_string();
            return;
        }
        self.probe_results.insert(
            id.clone(),
            ProbeState { reachable: None, detail: "probing...".to_string() },
        );
        let (tx, rx) = std::sync::mpsc::channel();
        // Keep a single receiver; a fresh probe replaces it (results still drain).
        self.probe_rx = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut st = probe_addr(&addr);
            // Contradiction check: air-gapped but actually reachable.
            if air_gapped && st.reachable == Some(true) {
                st.detail = format!("(!) tagged air-gapped but REACHABLE - {}", st.detail);
            }
            let _ = tx.send((id, st));
            ctx.request_repaint();
        });
    }

    fn poll_probes(&mut self) {
        if let Some(rx) = &self.probe_rx {
            while let Ok((id, st)) = rx.try_recv() {
                self.probe_results.insert(id, st);
            }
        }
    }

    /// Drain a finished scan (if any) and refresh from the store.
    fn poll_scan(&mut self) {
        if let Some(rx) = &self.scan_rx {
            if let Ok(o) = rx.try_recv() {
                self.scanning = false;
                self.scan_rx = None;
                self.scan_status = match o.error {
                    Some(e) => format!("Scan failed: {e}"),
                    None => format!("Scan complete - {} findings, posture {:.0}", o.findings, o.score),
                };
                self.refresh();
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        self.poll_probes();
        self.poll_net();
        // Drain async terminal output (tshark captures, etc.).
        while let Ok(line) = self.term_rx.try_recv() {
            self.terminal_lines.push(line);
        }
        // Ctrl+` toggles the terminal, like the web IDE shell.
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::Backtick)) {
            self.terminal_open = !self.terminal_open;
        }
        self.top_bar(ctx);
        self.activity_bar(ctx);
        self.side_nav(ctx);
        // The active page is always an open editor tab.
        if !self.open_tabs.contains(&self.page) {
            self.open_tabs.push(self.page);
        }
        self.tab_strip(ctx);
        self.terminal_panel(ctx);
        self.detail_panel(ctx); // right panel; must precede CentralPanel
        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Overview => self.overview(ui),
            Page::AttackPaths => self.attack_paths(ui),
            Page::Estate => self.estate(ui),
            Page::Endpoints => self.endpoints(ui),
            Page::Assets => self.assets(ui),
            Page::Findings => self.findings(ui),
            Page::Certificates => self.certificates(ui),
            Page::Cbom => self.cbom(ui),
            Page::Compliance => self.compliance(ui),
            Page::CryptoPolicies => self.crypto_policies(ui),
            Page::Frameworks => self.frameworks(ui),
            Page::Soc2 => self.soc2(ui),
            Page::Governance => self.governance(ui),
            Page::Scans => self.scans(ui),
            Page::Remediations => self.remediations(ui),
            Page::Overlay => self.overlay(ui),
            Page::Connections => self.connections(ui),
            Page::Agents => self.agents(ui),
            Page::Sessions => self.sessions(ui),
            Page::Threats => self.threats(ui),
            Page::Alerts => self.alerts(ui),
            Page::Audit => self.audit(ui),
            Page::Access => self.access(ui),
            Page::Settings => self.settings(ui),
            Page::About => self.about(ui),
        });
        // While a scan or a network op runs, keep the frame loop alive so the
        // poll_* methods see the result.
        if self.scanning || self.net_busy {
            ctx.request_repaint();
        }
    }
}

impl App {
    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("QuantaWatch").strong().size(18.0));
                ui.label(egui::RichText::new("Desktop").color(theme::ACCENT).size(18.0));
                ui.label(egui::RichText::new(build_stamp()).color(theme::MUTED).small())
                    .on_hover_text("running build - version · git hash · build time");
                ui.separator();
                // Honest mode badge: pure-offline by default; probes are opt-in.
                if self.net_probes_enabled {
                    ui.label(egui::RichText::new("PROBES ON").color(theme::HIGH).small());
                    ui.label(egui::RichText::new("reachability checks enabled · no browser").color(theme::MUTED).small());
                } else {
                    ui.label(egui::RichText::new("OFFLINE").color(theme::GOOD).small());
                    ui.label(egui::RichText::new("no network · no browser").color(theme::MUTED).small());
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Refresh").clicked() {
                        self.refresh();
                    }
                    if ui.selectable_label(self.terminal_open, "Terminal").on_hover_text("Ctrl+`").clicked() {
                        self.terminal_open = !self.terminal_open;
                    }
                    if let Some(t) = self.data.loaded_at {
                        ui.label(
                            egui::RichText::new(format!("loaded {}", t.format("%H:%M:%S")))
                                .color(theme::MUTED)
                                .small(),
                        );
                    }
                });
            });
            ui.add_space(4.0);
        });
    }

    fn side_nav(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav")
            .exact_width(200.0)
            .resizable(false)
            .show(ctx, |ui| {
                let d = &self.data;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_space(8.0);
                    nav_item(ui, &mut self.page, Page::Overview, "📊  Overview", None);

                    nav_group(ui, "POSTURE");
                    nav_item(ui, &mut self.page, Page::AttackPaths, "🎯  Attack paths", None);
                    nav_item(ui, &mut self.page, Page::Estate, "🌐  Estate", Some(d.targets.len()));
                    nav_item(ui, &mut self.page, Page::Endpoints, "💻  Endpoints", Some(d.endpoints.len()));
                    nav_item(ui, &mut self.page, Page::Assets, "📦  Assets", Some(d.assets.len()));
                    nav_item(ui, &mut self.page, Page::Findings, "⚠  Findings", Some(d.findings.len()));
                    nav_item(ui, &mut self.page, Page::Certificates, "🔒  Certificates", Some(d.certs.len()));
                    nav_item(ui, &mut self.page, Page::Cbom, "📇  Crypto (CBOM)", None);

                    nav_group(ui, "GOVERNANCE");
                    nav_item(ui, &mut self.page, Page::Compliance, "📋  Compliance", None);
                    nav_item(ui, &mut self.page, Page::CryptoPolicies, "📐  Crypto policies", None);
                    nav_item(ui, &mut self.page, Page::Frameworks, "📚  Frameworks", None);
                    nav_item(ui, &mut self.page, Page::Soc2, "✅  SOC 2", None);
                    nav_item(ui, &mut self.page, Page::Governance, "📈  Governance/SLO", None);

                    nav_group(ui, "OPERATE");
                    nav_item(ui, &mut self.page, Page::Scans, "🔍  Scans", Some(d.scans.len()));
                    nav_item(ui, &mut self.page, Page::Remediations, "🔧  Remediations", Some(d.remediations.len()));
                    nav_item(ui, &mut self.page, Page::Overlay, "🔐  PQC Overlay", Some(d.overlay_routes.len()));
                    nav_item(ui, &mut self.page, Page::Connections, "🔌  Connections", Some(d.connections.len()));

                    nav_group(ui, "MONITOR");
                    nav_item(ui, &mut self.page, Page::Agents, "🤖  Agents", Some(d.flows.len()));
                    nav_item(ui, &mut self.page, Page::Sessions, "📝  Sessions", Some(d.sessions.len()));
                    nav_item(ui, &mut self.page, Page::Threats, "🚨  Threats", None);
                    nav_item(ui, &mut self.page, Page::Alerts, "🔔  Alerts", Some(d.alerts.len()));
                    nav_item(ui, &mut self.page, Page::Audit, "📜  Audit log", Some(d.audit.len()));

                    nav_group(ui, "ADMIN");
                    nav_item(ui, &mut self.page, Page::Access, "🔑  Access (RBAC)", Some(d.users.len()));
                    nav_item(ui, &mut self.page, Page::Settings, "⚙  Settings", None);
                    nav_item(ui, &mut self.page, Page::About, "📖  About", None);
                    ui.add_space(12.0);
                    ui.separator();
                    ui.label(egui::RichText::new("store").color(theme::MUTED).small());
                    ui.label(egui::RichText::new(&self.source).color(theme::MUTED).small());
                });
            });
    }

    fn tab_strip(&mut self, ctx: &egui::Context) {
        let tabs = self.open_tabs.clone();
        let active = self.page;
        let n = tabs.len();
        let mut act: Option<TabAction> = None;
        let mut reorder: Option<(usize, usize)> = None;
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_space(2.0);
            egui::ScrollArea::horizontal().show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (idx, tab) in tabs.iter().enumerate() {
                        let tab = *tab;
                        let is_active = tab == active;
                        egui::Frame::none()
                            .fill(if is_active { theme::BG } else { theme::PANEL })
                            .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                            .rounding(4.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let col = if is_active { theme::TEXT } else { theme::MUTED };
                                    // One widget with BOTH click and drag sense: click
                                    // selects, drag reorders. (A dnd_drag_source has only
                                    // drag sense, which is why clicks stopped working.)
                                    let lab = ui.label(egui::RichText::new(page_title(tab)).color(col));
                                    let resp = ui
                                        .interact(lab.rect, egui::Id::new(("tab", idx)), egui::Sense::click_and_drag())
                                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                                    resp.dnd_set_drag_payload(idx);
                                    if resp.clicked() {
                                        act = Some(TabAction::Select(tab));
                                    }
                                    if resp.middle_clicked() {
                                        act = Some(TabAction::Close(tab));
                                    }
                                    resp.context_menu(|ui| {
                                        if ui.button("Close").clicked() { act = Some(TabAction::Close(tab)); ui.close_menu(); }
                                        if ui.button("Close others").clicked() { act = Some(TabAction::CloseOthers(tab)); ui.close_menu(); }
                                        if ui.button("Close to the right").clicked() { act = Some(TabAction::CloseRight(idx)); ui.close_menu(); }
                                        if ui.button("Close all").clicked() { act = Some(TabAction::CloseAll); ui.close_menu(); }
                                        ui.separator();
                                        if idx > 0 && ui.button("Move left").clicked() { reorder = Some((idx, idx - 1)); ui.close_menu(); }
                                        if idx + 1 < n && ui.button("Move right").clicked() { reorder = Some((idx, idx + 1)); ui.close_menu(); }
                                    });
                                    if let Some(payload) = resp.dnd_release_payload::<usize>() {
                                        reorder = Some((*payload, idx));
                                    }
                                    if ui.small_button("×").on_hover_text("close").clicked() {
                                        act = Some(TabAction::Close(tab));
                                    }
                                });
                            });
                    }
                });
            });
            ui.add_space(2.0);
        });
        if let Some((from, to)) = reorder {
            if from < self.open_tabs.len() && from != to {
                let t = self.open_tabs.remove(from);
                self.open_tabs.insert(to.min(self.open_tabs.len()), t);
            }
        }
        match act {
            Some(TabAction::Select(t)) => self.page = t,
            Some(TabAction::Close(t)) => self.close_tab(t),
            Some(TabAction::CloseRight(i)) => {
                self.open_tabs.truncate(i + 1);
                if !self.open_tabs.contains(&self.page) {
                    self.page = *self.open_tabs.last().unwrap();
                }
            }
            Some(TabAction::CloseOthers(t)) => {
                self.open_tabs = vec![t];
                self.page = t;
            }
            Some(TabAction::CloseAll) => {
                self.open_tabs = vec![Page::Overview];
                self.page = Page::Overview;
            }
            None => {}
        }
    }

    fn close_tab(&mut self, p: Page) {
        self.open_tabs.retain(|&t| t != p);
        if self.open_tabs.is_empty() {
            self.open_tabs.push(Page::Overview);
        }
        if self.page == p {
            self.page = *self.open_tabs.last().unwrap();
        }
    }

    fn terminal_panel(&mut self, ctx: &egui::Context) {
        if !self.terminal_open {
            return;
        }
        if self.terminal_float {
            // Moveable + resizable floating window.
            egui::Window::new("Terminal")
                .id(egui::Id::new("terminal_window"))
                .default_size([580.0, 280.0])
                .min_width(320.0)
                .resizable(true)
                .collapsible(false)
                .show(ctx, |ui| self.terminal_body(ui));
        } else {
            // Docked, resizable bottom panel.
            egui::TopBottomPanel::bottom("terminal")
                .resizable(true)
                .default_height(220.0)
                .min_height(120.0)
                .show(ctx, |ui| self.terminal_body(ui));
        }
    }

    fn terminal_body(&mut self, ui: &mut egui::Ui) {
        // Pinned header (top) + input (bottom); output fills the middle. Using
        // nested panels keeps the height stable instead of drifting each frame.
        egui::TopBottomPanel::top("term_header").resizable(false).show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("TERMINAL").small().strong().color(theme::MUTED));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("close").clicked() {
                        self.terminal_open = false;
                    }
                    let float_lbl = if self.terminal_float { "dock" } else { "float" };
                    if ui.small_button(float_lbl).on_hover_text("dock / float the terminal").clicked() {
                        self.terminal_float = !self.terminal_float;
                    }
                    if ui.small_button("clear").clicked() {
                        self.terminal_lines.clear();
                    }
                });
            });
        });
        let mut submit: Option<String> = None;
        egui::TopBottomPanel::bottom("term_input").resizable(false).show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(">").monospace().color(theme::ACCENT));
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.terminal_input)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("type 'help'"),
                );
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = Some(std::mem::take(&mut self.terminal_input));
                    resp.request_focus();
                }
            });
        });
        egui::CentralPanel::default().show_inside(ui, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for line in &self.terminal_lines {
                        ui.label(
                            egui::RichText::new(line)
                                .monospace()
                                .size(12.0)
                                .color(if line.starts_with('>') { theme::ACCENT } else { theme::TEXT }),
                        );
                    }
                });
        });
        if let Some(line) = submit {
            let ctx = ui.ctx().clone();
            self.run_terminal(line, &ctx);
        }
    }

    fn run_terminal(&mut self, line: String, ctx: &egui::Context) {
        let line = line.trim().to_string();
        if line.is_empty() {
            return;
        }
        self.terminal_lines.push(format!("> {line}"));
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("").to_lowercase();
        let arg = it.collect::<Vec<_>>().join(" ");
        match cmd.as_str() {
            "clear" => {
                self.terminal_lines.clear();
                return;
            }
            "help" => {
                self.terminal_lines.push(
                    "store:   help · clear · posture · findings [n] · estate · assets · certs · threats · paths · open <page> · refresh · version".to_string(),
                );
                self.terminal_lines.push(
                    "scan:    scan <dir>   (in-process code scan)".to_string(),
                );
                self.terminal_lines.push(
                    "network: wireshark (detect tshark) · ifaces · capture <host> [count]   (needs probes ON + Wireshark)".to_string(),
                );
            }
            "posture" => {
                let msg = match &self.data.posture {
                    Some(p) => format!("posture {:.0}/100 · {} findings · {} assets scored", p.overall_score, self.data.findings.len(), p.total_assets),
                    None => "no posture snapshot".to_string(),
                };
                self.terminal_lines.push(msg);
            }
            "findings" => {
                let n: usize = arg.parse().unwrap_or(10);
                let c = self.data.severity_counts();
                self.terminal_lines.push(format!(
                    "{} findings - {} critical · {} high · {} medium · {} low · {} info",
                    self.data.findings.len(), c[4], c[3], c[2], c[1], c[0]
                ));
                let rows: Vec<String> = self.data.findings.iter().take(n)
                    .map(|f| format!("  [{}] {} - {}", sev_label(f.severity), f.title, f.location)).collect();
                self.terminal_lines.extend(rows);
            }
            "estate" => {
                let rows: Vec<String> = self.data.targets.iter()
                    .map(|t| format!("{} · {} · {} · {}", t.name, t.host, t.kind, pretty_status(&t.pqc_status))).collect();
                self.terminal_lines.extend(if rows.is_empty() { vec!["(no hosts)".to_string()] } else { rows });
            }
            "assets" => {
                let rows: Vec<String> = self.data.assets.iter()
                    .map(|a| format!("{} · {} · {}", a.id, a.address, pretty_status(&a.pqc_status))).collect();
                self.terminal_lines.extend(if rows.is_empty() { vec!["(no assets)".to_string()] } else { rows });
            }
            "certs" => self.terminal_lines.push(format!("{} certificates", self.data.certs.len())),
            "threats" => {
                let n = self.data.audit.iter().filter(|e| event_to_threat(&e.event).is_some()).count();
                self.terminal_lines.push(format!("{n} threat events in the audit stream"));
            }
            "paths" => {
                self.graph.sync(&self.data.flows, &self.data.targets, &self.data.findings, &self.data.assets);
                let rows: Vec<String> = self.graph.paths().iter().take(10)
                    .map(|p| format!("[{:.0}] {} - {}", p.score, p.severity.to_uppercase(), p.title)).collect();
                self.terminal_lines.extend(if rows.is_empty() { vec!["(no attack paths)".to_string()] } else { rows });
            }
            "scan" => {
                if arg.is_empty() {
                    self.terminal_lines.push("usage: scan <dir>".to_string());
                } else {
                    self.scan_path = arg.clone();
                    self.terminal_lines.push(format!("scanning {arg} ..."));
                    self.start_scan(ctx);
                }
            }
            "open" => match page_by_name(&arg) {
                Some(p) => {
                    self.page = p;
                    self.terminal_lines.push(format!("opened {}", page_title(p)));
                }
                None => self.terminal_lines.push(format!("unknown page: {arg}")),
            },
            "refresh" => {
                self.refresh();
                self.terminal_lines.push("refreshed from store".to_string());
            }
            "wireshark" => match tshark_version() {
                Some(v) => {
                    self.tshark_ver = Some(v.clone());
                    self.terminal_lines.push(format!("detected: {v}"));
                }
                None => self.terminal_lines.push("tshark not found on PATH - install Wireshark".to_string()),
            },
            "ifaces" => match tshark_interfaces() {
                Ok(list) => self.terminal_lines.extend(list),
                Err(e) => self.terminal_lines.push(format!("tshark -D: {e}")),
            },
            "capture" => {
                if !self.net_probes_enabled {
                    self.terminal_lines.push("network probes are off - enable them in Settings first".to_string());
                } else if arg.is_empty() {
                    self.terminal_lines.push("usage: capture <host> [count]   (needs Wireshark/tshark + capture perms)".to_string());
                } else {
                    let mut a = arg.split_whitespace();
                    let host = a.next().unwrap_or("").to_string();
                    let count: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(20);
                    self.terminal_lines.push(format!("capturing up to {count} packets to/from {host} via tshark (≤8s)..."));
                    let tx = self.term_tx.clone();
                    let ctx2 = ctx.clone();
                    std::thread::spawn(move || {
                        match tshark_capture(&host, count) {
                            Ok(lines) => {
                                for l in lines {
                                    let _ = tx.send(l);
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(format!("tshark: {e}"));
                            }
                        }
                        ctx2.request_repaint();
                    });
                }
            }
            "version" => self.terminal_lines.push(format!("qw-desktop {}", build_stamp())),
            other => self.terminal_lines.push(format!("unknown command: {other} (try 'help')")),
        }
        let len = self.terminal_lines.len();
        if len > 500 {
            self.terminal_lines.drain(0..len - 500);
        }
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Posture overview");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button("Board report")
                    .on_hover_text("Generate a print-ready executive Quantum-Risk board report (HTML) - fully offline")
                    .clicked()
                {
                    self.export_board_report();
                }
            });
        });
        if !self.export_status.is_empty() {
            ui.label(egui::RichText::new(&self.export_status).color(theme::MUTED).small());
        }
        ui.add_space(8.0);

        // In-process scan - reads local files only, no network.
        egui::Frame::none()
            .fill(theme::PANEL)
            .rounding(8.0)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Scan a code directory").strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.scan_path)
                            .hint_text("path to a source tree")
                            .desired_width(340.0),
                    );
                    let btn = egui::Button::new(egui::RichText::new("▶ Scan").color(theme::TEXT))
                        .fill(theme::ACCENT);
                    if ui.add_enabled(!self.scanning, btn).clicked() {
                        let ctx = ui.ctx().clone();
                        self.start_scan(&ctx);
                    }
                    if self.scanning {
                        ui.spinner();
                    }
                });
                if !self.scan_status.is_empty() {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(&self.scan_status).color(theme::MUTED).small());
                }
                ui.label(
                    egui::RichText::new("Local files only - no network. Findings are written to the store.")
                        .color(theme::MUTED)
                        .small(),
                );
            });
        ui.add_space(12.0);

        let score = self.data.posture.as_ref().map(|p| p.overall_score);
        egui::Frame::none()
            .fill(theme::CARD)
            .rounding(8.0)
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    match score {
                        Some(s) => {
                            let col = score_color(s);
                            ui.label(egui::RichText::new(format!("{s:.0}")).size(48.0).strong().color(col));
                            ui.vertical(|ui| {
                                ui.add_space(10.0);
                                ui.label(egui::RichText::new("/ 100 PQC posture").color(theme::MUTED));
                                ui.add(
                                    egui::ProgressBar::new((s / 100.0) as f32)
                                        .desired_width(360.0)
                                        .fill(col),
                                );
                            });
                        }
                        None => {
                            ui.label(
                                egui::RichText::new("No posture snapshot yet")
                                    .size(22.0)
                                    .color(theme::MUTED),
                            );
                        }
                    }
                });
            });

        ui.add_space(14.0);
        let [info, low, med, high, crit] = self.data.severity_counts();
        ui.horizontal_wrapped(|ui| {
            stat_card(ui, "Critical", crit, theme::CRIT);
            stat_card(ui, "High", high, theme::HIGH);
            stat_card(ui, "Medium", med, theme::MED);
            stat_card(ui, "Low", low, theme::LOW);
            stat_card(ui, "Info", info, theme::MUTED);
        });
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            stat_card(ui, "Findings", self.data.findings.len(), theme::TEXT);
            stat_card(ui, "Estate hosts", self.data.targets.len(), theme::TEXT);
            stat_card(ui, "Certificates", self.data.certs.len(), theme::TEXT);
            if let Some(p) = &self.data.posture {
                stat_card(ui, "Assets scored", p.total_assets as usize, theme::TEXT);
            }
        });

        if let Some(p) = &self.data.posture {
            if !p.by_status.is_empty() {
                ui.add_space(16.0);
                ui.label(egui::RichText::new("Assets by PQC status").strong());
                ui.add_space(4.0);
                egui::Grid::new("bystatus").striped(true).show(ui, |ui| {
                    for (k, v) in &p.by_status {
                        ui.label(pretty_status(k));
                        ui.label(egui::RichText::new(v.to_string()).strong());
                        ui.end_row();
                    }
                });
            }
        }

        // Posture trend sparkline (from history snapshots).
        if self.data.history.len() >= 2 {
            ui.add_space(16.0);
            ui.label(egui::RichText::new("Posture trend").strong());
            ui.add_space(4.0);
            let hist = &self.data.history;
            let (resp, painter) =
                ui.allocate_painter(egui::vec2(380.0, 84.0), egui::Sense::hover());
            let rect = resp.rect;
            painter.rect_filled(rect, 4.0, theme::CARD);
            let n = hist.len();
            let pts: Vec<egui::Pos2> = hist
                .iter()
                .enumerate()
                .map(|(i, &v)| {
                    let x = rect.left() + rect.width() * (i as f32 / (n - 1) as f32);
                    let y = rect.bottom() - rect.height() * (v as f32 / 100.0).clamp(0.0, 1.0);
                    egui::pos2(x, y)
                })
                .collect();
            for w in pts.windows(2) {
                painter.line_segment([w[0], w[1]], egui::Stroke::new(2.0, theme::ACCENT));
            }
            if let (Some(last), Some(&v)) = (pts.last(), hist.last()) {
                painter.circle_filled(*last, 3.0, score_color(v));
                painter.text(
                    *last + egui::vec2(-6.0, -4.0),
                    egui::Align2::RIGHT_BOTTOM,
                    format!("{v:.0}"),
                    egui::FontId::proportional(11.0),
                    theme::TEXT,
                );
            }
        }
    }

    fn attack_paths(&mut self, ui: &mut egui::Ui) {
        self.graph.sync(
            &self.data.flows,
            &self.data.targets,
            &self.data.findings,
            &self.data.assets,
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Attack paths");
            let (n, e) = self.graph.counts();
            ui.label(
                egui::RichText::new(format!("{n} nodes · {e} edges · {} paths", self.graph.paths().len()))
                    .color(theme::MUTED)
                    .small(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Reset view").clicked() {
                    self.graph.reset_view();
                }
            });
        });
        ui.label(
            egui::RichText::new(
                "Shared qw-graph engine, run in-process. Drag to pan · scroll to zoom · click a node.",
            )
            .color(theme::MUTED)
            .small(),
        );
        ui.add_space(4.0);
        if self.graph.counts().0 == 0 {
            empty_state(ui, "Nothing to graph yet - run a scan or register estate hosts.");
            return;
        }

        // Ranked "toxic combinations" on the right; the graph fills the rest.
        egui::SidePanel::right("toxic_combos")
            .default_width(300.0)
            .show_inside(ui, |ui| {
                ui.add_space(4.0);
                // Remediation simulation: harden provider channels to hybrid and
                // watch the risk drop (recomputes via the shared engine, offline).
                egui::CollapsingHeader::new("Remediation simulation")
                    .default_open(true)
                    .show(ui, |ui| {
                        let providers = self.graph.providers().to_vec();
                        if providers.is_empty() {
                            ui.label(egui::RichText::new("No provider channels to harden.").color(theme::MUTED).small());
                        } else {
                            ui.label(egui::RichText::new("harden to hybrid ML-KEM:").color(theme::MUTED).small());
                            for p in &providers {
                                let mut on = self.graph.is_hardened(p);
                                if ui.checkbox(&mut on, p).changed() {
                                    self.graph.set_override(p, on);
                                }
                            }
                            if self.graph.has_overrides() {
                                let base = self.graph.base_risk();
                                let sim = self.graph.sim_risk();
                                let red = if base > 0.0 { (base - sim) / base * 100.0 } else { 0.0 };
                                ui.colored_label(theme::GOOD, format!("risk {base:.0} -> {sim:.0}  (-{red:.0}%)"));
                                if ui.small_button("reset").clicked() {
                                    self.graph.clear_overrides();
                                }
                            }
                        }
                    });
                ui.separator();
                ui.label(egui::RichText::new("Toxic combinations").strong());
                ui.label(
                    egui::RichText::new("attack paths, worst first")
                        .color(theme::MUTED)
                        .small(),
                );
                ui.add_space(4.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for p in self.graph.paths() {
                        egui::Frame::none()
                            .fill(theme::CARD)
                            .rounding(6.0)
                            .inner_margin(egui::Margin::same(8.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        graphview::severity_color(&p.severity),
                                        format!("{:.0}", p.score),
                                    );
                                    ui.label(egui::RichText::new(p.severity.to_uppercase()).small());
                                    if p.hndl {
                                        ui.colored_label(theme::CRIT, egui::RichText::new("HNDL").small());
                                    }
                                    if p.observed {
                                        ui.colored_label(theme::LOW, egui::RichText::new("observed").small());
                                    }
                                });
                                ui.label(egui::RichText::new(&p.title).small());
                                if !p.kill_chain.is_empty() {
                                    egui::CollapsingHeader::new(
                                        egui::RichText::new("kill chain").color(theme::MUTED).small(),
                                    )
                                    .id_salt(("kc", &p.title))
                                    .show(ui, |ui| {
                                        for st in &p.kill_chain {
                                            ui.horizontal(|ui| {
                                                ui.colored_label(
                                                    kc_status_color(st.status),
                                                    egui::RichText::new(format!("{}. {}", st.stage, st.label)).small().strong(),
                                                );
                                                ui.label(egui::RichText::new(st.status).color(kc_status_color(st.status)).small());
                                            });
                                            ui.label(egui::RichText::new(&st.detail).color(theme::MUTED).small());
                                        }
                                    });
                                }
                            })
                            .response
                            .on_hover_cursor(egui::CursorIcon::Help)
                            .on_hover_text(format!("Fix: {}", p.recommendation));
                        ui.add_space(4.0);
                    }
                });
            });

        if let Some((id, label, detail)) = self.graph.ui(ui) {
            // If the node maps to a store record, open the full detail panel
            // (shows address, services, remediation, etc.). Otherwise a small
            // floating card for nodes with no store row (provider/data/agent).
            if let Some(sel) = node_to_selection(&id, &self.data) {
                self.selected = Some(sel);
                self.graph.deselect();
            } else {
                egui::Window::new("Node detail")
                    .id(egui::Id::new("graph_node_detail"))
                    .collapsible(false)
                    .resizable(true)
                    .default_width(320.0)
                    .default_pos(egui::pos2(250.0, 130.0))
                    .show(ui.ctx(), |ui| {
                        ui.label(egui::RichText::new(&label).strong().size(16.0));
                        ui.add_space(4.0);
                        ui.separator();
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(&detail).size(13.0));
                        ui.add_space(6.0);
                        if ui.button("Close").clicked() {
                            self.graph.deselect();
                        }
                    });
            }
        }
    }

    fn findings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Findings");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Export JSON").clicked() {
                    self.export_findings();
                }
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("filter...").desired_width(220.0));
            });
        });
        if !self.export_status.is_empty() {
            ui.label(egui::RichText::new(&self.export_status).color(theme::MUTED).small());
        }
        ui.add_space(6.0);

        let filter = self.filter.to_lowercase();
        let rows: Vec<&FindingRecord> = self
            .data
            .findings
            .iter()
            .filter(|f| {
                filter.is_empty()
                    || f.title.to_lowercase().contains(&filter)
                    || f.location.to_lowercase().contains(&filter)
                    || f.algorithm.as_deref().unwrap_or("").to_lowercase().contains(&filter)
            })
            .collect();

        if rows.is_empty() {
            empty_state(ui, "No findings match. Run a scan via the gateway or `qw scan`.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("findings")
                .striped(true)
                .num_columns(6)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Sev", "Title", "Algorithm", "PQC", "Location", "Status"] {
                        ui.label(egui::RichText::new(h).strong().color(theme::MUTED));
                    }
                    ui.end_row();
                    for f in rows {
                        ui.colored_label(sev_color(f.severity), sev_label(f.severity));
                        // Clickable title → open the detail panel. Tooltip previews it.
                        let title = egui::Label::new(egui::RichText::new(&f.title).color(theme::ACCENT))
                            .sense(egui::Sense::click());
                        let mut tip = f.description.clone();
                        if let Some(r) = &f.remediation {
                            tip.push_str(&format!("\n\nFix: {r}"));
                        }
                        tip.push_str("\n\n(click for full details)");
                        if ui
                            .add(title)
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(tip)
                            .clicked()
                        {
                            self.selected = Some(Selection::Finding(f.id.clone()));
                        }
                        ui.label(f.algorithm.as_deref().unwrap_or("-"));
                        ui.colored_label(pqc_color(f.pqc_status), pqc_label(f.pqc_status));
                        ui.label(egui::RichText::new(&f.location).color(theme::MUTED));
                        ui.label(format!("{:?}", f.status));
                        ui.end_row();
                    }
                });
        });
    }

    fn estate(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Estate");
        ui.add_space(6.0);

        let mut add = false;
        egui::CollapsingHeader::new("Register host").show(ui, |ui| {
            let cur = self.target_form.kind.clone();
            egui::ComboBox::from_label("Template")
                .selected_text(if cur.is_empty() { "- choose -".to_string() } else { cur })
                .show_ui(ui, |ui| {
                    for (name, kind, env) in HOST_TEMPLATES {
                        if ui.selectable_label(false, *name).clicked() {
                            self.target_form.kind = kind.to_string();
                            if self.target_form.environment.is_empty() {
                                self.target_form.environment = env.to_string();
                            }
                        }
                    }
                });
            egui::Grid::new("targetform").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut self.target_form.name);
                ui.end_row();
                ui.label("Host / address");
                ui.text_edit_singleline(&mut self.target_form.host);
                ui.end_row();
                ui.label("Kind");
                ui.text_edit_singleline(&mut self.target_form.kind);
                ui.end_row();
                ui.label("Environment");
                ui.text_edit_singleline(&mut self.target_form.environment);
                ui.end_row();
            });
            ui.checkbox(&mut self.target_form.air_gapped, "Air-gapped (no network path - suppresses HNDL risk)");
            ui.label(egui::RichText::new("kind defaults to server, env to default. Scan it from Overview after registering.").color(theme::MUTED).small());
            if ui.button("Register").clicked() {
                add = true;
            }
        });
        if add {
            self.add_target();
        }
        if !self.edit_status.is_empty() {
            ui.label(egui::RichText::new(&self.edit_status).color(theme::MUTED).small());
        }
        ui.add_space(6.0);

        let mut del: Option<String> = None;
        let mut toggle: Option<String> = None;
        let mut probe: Option<(String, String, bool)> = None;
        let mut open: Option<Selection> = None;
        {
            let d = &self.data;
            let probes = &self.probe_results;
            data_table(ui, "estate", &["Name", "Host", "Kind", "Env", "PQC", "Exposure", ""],
                d.targets.len(), "No registered hosts. Register one above.", |ui, i| {
                let t = &d.targets[i];
                let air = has_tag(&t.tags, "air-gapped");
                let name = ui.add(egui::Label::new(egui::RichText::new(&t.name).color(theme::ACCENT)).sense(egui::Sense::click()))
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text("click for details");
                if name.clicked() {
                    open = Some(Selection::Host(t.id.clone()));
                }
                name.context_menu(|ui| {
                    if ui.button(if air { "Mark exposed" } else { "Mark air-gapped" }).clicked() {
                        toggle = Some(t.id.clone());
                        ui.close_menu();
                    }
                    if ui.button("Verify reachability").clicked() {
                        probe = Some((t.id.clone(), t.host.clone(), air));
                        ui.close_menu();
                    }
                    if ui.button("Delete host").clicked() {
                        del = Some(t.id.clone());
                        ui.close_menu();
                    }
                });
                ui.label(egui::RichText::new(&t.host).color(theme::MUTED));
                ui.label(&t.kind);
                ui.label(&t.environment);
                ui.colored_label(status_str_color(&t.pqc_status), pretty_status(&t.pqc_status));
                ui.horizontal(|ui| {
                    let (col, txt) = if air { (theme::GOOD, "air-gapped") } else { (theme::MUTED, "exposed") };
                    if ui.selectable_label(air, egui::RichText::new(txt).color(col).small())
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("toggle · right-click to verify reachability").clicked()
                    {
                        toggle = Some(t.id.clone());
                    }
                    probe_badge(ui, probes.get(&t.id), air);
                });
                if ui.small_button("Del").on_hover_text("delete").clicked() {
                    del = Some(t.id.clone());
                }
            });
        }
        if let Some(s) = open {
            self.selected = Some(s);
        }
        if let Some(id) = toggle {
            self.toggle_target_airgap(&id);
        }
        if let Some((id, addr, air)) = probe {
            let ctx = ui.ctx().clone();
            self.start_probe(id, addr, air, &ctx);
        }
        if let Some(id) = del {
            self.store.delete_target(TENANT, &id);
            self.edit_status = format!("Deleted host {id}");
            self.refresh();
        }
    }

    /// Lazily create (or load) the desktop's own local CA under `<data>/pki`.
    /// This is where the operational ML-DSA identity + Ed25519 root live; it is
    /// created only when the user first issues a cert, never at startup.
    fn ensure_ca(&mut self) -> Result<Arc<CertAuthority>, String> {
        if let Some(ca) = &self.ca {
            return Ok(ca.clone());
        }
        let pki_dir = std::path::Path::new(&self.source)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("pki");
        let id = qw_crypto::GatewayIdentity::load_or_generate(&pki_dir)
            .map_err(|e| format!("CA identity: {e}"))?;
        let ca = CertAuthority::load_or_create("QuantaWatch Desktop CA", &pki_dir, Arc::new(id))
            .map_err(|e| format!("CA init: {e}"))?;
        let ca = Arc::new(ca);
        self.ca = Some(ca.clone());
        Ok(ca)
    }

    fn issue_cert(&mut self) {
        let subject = self.cert_form.subject.trim().to_string();
        if subject.is_empty() {
            self.cert_status = "A certificate needs a subject (CN).".to_string();
            return;
        }
        let sans: Vec<String> = self
            .cert_form
            .sans
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let days = self.cert_form.validity_days.trim().parse::<u32>().unwrap_or(90);
        let hybrid = self.cert_form.hybrid;
        let ca = match self.ensure_ca() {
            Ok(c) => c,
            Err(e) => {
                self.cert_status = e;
                return;
            }
        };
        match ca.issue(&subject, &sans, days, hybrid) {
            Ok((row, key_pem)) => {
                self.store.record_certificate(TENANT, &row);
                self.cert_status = format!(
                    "Issued {} certificate for {} · serial {} · CA {}",
                    row.key_type, subject, row.serial, ca.fingerprint()
                );
                self.issued_key = Some((subject, key_pem));
                self.cert_form = CertForm { validity_days: days.to_string(), hybrid, ..Default::default() };
                self.refresh();
            }
            Err(e) => self.cert_status = format!("Issue failed: {e}"),
        }
    }

    fn renew_cert(&mut self, id: &str) {
        let Some(prev) = self.store.get_certificate(TENANT, id) else {
            self.cert_status = "certificate not found".to_string();
            return;
        };
        let hybrid = prev.key_type == "hybrid";
        let sans: Vec<String> = prev.sans.iter().filter(|s| **s != prev.subject).cloned().collect();
        let ca = match self.ensure_ca() {
            Ok(c) => c,
            Err(e) => {
                self.cert_status = e;
                return;
            }
        };
        // Renew = reissue the same subject/SANs with a fresh validity window.
        match ca.issue(&prev.subject, &sans, 90, hybrid) {
            Ok((row, key_pem)) => {
                self.store.record_certificate(TENANT, &row);
                self.cert_status = format!("Renewed {} · new serial {}", prev.subject, row.serial);
                self.issued_key = Some((format!("{} (renewed)", prev.subject), key_pem));
                self.refresh();
            }
            Err(e) => self.cert_status = format!("Renew failed: {e}"),
        }
    }

    fn revoke_cert(&mut self, id: &str) {
        let Some(mut cert) = self.store.get_certificate(TENANT, id) else {
            self.cert_status = "certificate not found".to_string();
            return;
        };
        cert.status = "revoked".to_string();
        cert.revoked_at = Some(Utc::now());
        self.store.record_certificate(TENANT, &cert);
        self.cert_status = format!("Revoked {} (serial {})", cert.subject, cert.serial);
        self.refresh();
    }

    fn certificates(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Certificates");
        ui.label(egui::RichText::new("Issued by this desktop's own local PQC CA (offline). Hybrid = classical Ed25519 X.509 leaf + an ML-DSA-65 binding over it.").color(theme::MUTED).small());
        ui.add_space(6.0);

        // Issue form.
        egui::CollapsingHeader::new("Issue a certificate")
            .default_open(self.data.certs.is_empty())
            .show(ui, |ui| {
                egui::Grid::new("certform").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    ui.label("Subject (CN)");
                    ui.add(egui::TextEdit::singleline(&mut self.cert_form.subject).hint_text("svc.internal").desired_width(260.0));
                    ui.end_row();
                    ui.label("SANs (comma-sep)");
                    ui.add(egui::TextEdit::singleline(&mut self.cert_form.sans).hint_text("svc.internal, svc.corp").desired_width(260.0));
                    ui.end_row();
                    ui.label("Validity (days)");
                    ui.add(egui::TextEdit::singleline(&mut self.cert_form.validity_days).desired_width(80.0));
                    ui.end_row();
                    ui.label("Post-quantum");
                    ui.checkbox(&mut self.cert_form.hybrid, "hybrid (adds ML-DSA-65 binding)");
                    ui.end_row();
                });
                if ui.button("Issue certificate").clicked() {
                    self.issue_cert();
                }
            });

        // One-time private-key reveal after an issue/renew.
        if let Some((subject, pem)) = self.issued_key.clone() {
            egui::Frame::none().fill(theme::CARD).rounding(6.0).inner_margin(egui::Margin::same(8.0)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(theme::HIGH, "Private key (shown once)");
                    ui.label(egui::RichText::new(&subject).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Dismiss").clicked() {
                            self.issued_key = None;
                        }
                        if ui.button("Copy key").clicked() {
                            ui.output_mut(|o| o.copied_text = pem.clone());
                        }
                    });
                });
                ui.label(egui::RichText::new("This leaf private key is never stored - copy it now.").color(theme::MUTED).small());
                egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                    ui.label(egui::RichText::new(&pem).monospace().small());
                });
            });
            ui.add_space(4.0);
        }
        if !self.cert_status.is_empty() {
            ui.label(egui::RichText::new(&self.cert_status).color(theme::MUTED).small());
        }
        ui.add_space(6.0);

        if self.data.certs.is_empty() {
            empty_state(ui, "No certificates yet. Issue one above with the local PQC CA.");
            return;
        }
        let now = Utc::now();
        let mut open: Option<Selection> = None;
        let mut action: Option<CertAction> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("certs")
                .striped(true)
                .num_columns(6)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Subject", "Type", "PQC", "Expires", "State", "Actions"] {
                        ui.label(egui::RichText::new(h).strong().color(theme::MUTED));
                    }
                    ui.end_row();
                    for c in &self.data.certs {
                        let tip = format!(
                            "serial: {}\nkey type: {}\nSANs: {}\nCA fingerprint: {}\nvalid: {} → {}",
                            c.serial,
                            c.key_type,
                            if c.sans.is_empty() { "-".to_string() } else { c.sans.join(", ") },
                            c.ca_fingerprint,
                            fmt_dt(c.not_before),
                            fmt_dt(c.not_after),
                        );
                        if ui.add(egui::Label::new(egui::RichText::new(&c.subject).color(theme::ACCENT)).sense(egui::Sense::click()))
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(tip)
                            .clicked()
                        {
                            open = Some(Selection::Cert(c.id.clone()));
                        }
                        // hybrid = classical X.509 + ML-DSA binding.
                        let type_col = if c.key_type.contains("hybrid") { theme::GOOD } else { theme::MED };
                        ui.colored_label(type_col, &c.key_type);
                        ui.colored_label(status_str_color(&c.pqc_status), pretty_status(&c.pqc_status));
                        // Expiry, colored by urgency.
                        let days = (c.not_after - now).num_days();
                        let (col, txt) = if c.status == "revoked" {
                            (theme::MUTED, "-".to_string())
                        } else if days < 0 {
                            (theme::CRIT, "expired".to_string())
                        } else if days < 30 {
                            (theme::HIGH, format!("{days}d"))
                        } else {
                            (theme::MUTED, format!("{days}d"))
                        };
                        ui.colored_label(col, txt);
                        let state_col = if c.status == "active" { theme::GOOD } else { theme::CRIT };
                        ui.colored_label(state_col, &c.status);
                        // Per-row actions: renew (reissue) and revoke.
                        ui.horizontal(|ui| {
                            if ui.small_button("Renew").on_hover_text("reissue same subject/SANs with a fresh window").clicked() {
                                action = Some(CertAction::Renew(c.id.clone()));
                            }
                            if c.status == "active"
                                && ui.small_button("Revoke").on_hover_text("mark revoked (irreversible)").clicked()
                            {
                                action = Some(CertAction::Revoke(c.id.clone()));
                            }
                        });
                        ui.end_row();
                    }
                });
        });
        if let Some(s) = open {
            self.selected = Some(s);
        }
        match action {
            Some(CertAction::Renew(id)) => self.renew_cert(&id),
            Some(CertAction::Revoke(id)) => self.revoke_cert(&id),
            None => {}
        }
    }

    fn scans(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Scans");
        ui.add_space(6.0);
        let mut open: Option<Selection> = None;
        {
            let d = &self.data;
            data_table(ui, "scans", &["Scanner", "Target", "Status", "Findings", "Completed"],
                d.scans.len(), "No scans recorded yet. Run one from the Overview page.", |ui, i| {
                let s = &d.scans[i];
                let name = ui.add(egui::Label::new(egui::RichText::new(&s.scanner_id).color(theme::ACCENT)).sense(egui::Sense::click()))
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text("click for details");
                if name.clicked() {
                    open = Some(Selection::Scan(s.id.clone()));
                }
                ui.label(egui::RichText::new(&s.target_address).color(theme::MUTED));
                ui.label(format!("{:?}", s.status));
                ui.label(s.finding_count.to_string());
                ui.label(egui::RichText::new(fmt_dt(s.completed_at)).color(theme::MUTED));
            });
        }
        if let Some(s) = open {
            self.selected = Some(s);
        }
    }

    /// Right-hand detail panel for the selected finding.
    fn detail_panel(&mut self, ctx: &egui::Context) {
        let Some(sel) = self.selected.clone() else {
            return;
        };
        let title = match &sel {
            Selection::Finding(_) => "Finding",
            Selection::Asset(_) => "Asset",
            Selection::Host(_) => "Host",
            Selection::Scan(_) => "Scan",
            Selection::Endpoint(_) => "Endpoint",
            Selection::Session(_) => "Session",
            Selection::Connection(_) => "Connection",
            Selection::Remediation(_) => "Remediation",
            Selection::Cert(_) => "Certificate",
            Selection::Alert(_) => "Alert",
        };
        egui::SidePanel::right("detail")
            .default_width(380.0)
            .min_width(300.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.heading(title);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Close").clicked() {
                            self.selected = None;
                        }
                    });
                });
                ui.separator();
                ui.add_space(4.0);
                match &sel {
                    Selection::Finding(id) => self.finding_body(ui, id),
                    Selection::Asset(id) => self.asset_body(ui, id),
                    Selection::Host(id) => self.host_body(ui, id),
                    Selection::Scan(id) => self.scan_body(ui, id),
                    Selection::Endpoint(id) => self.endpoint_body(ui, id),
                    Selection::Session(id) => self.session_body(ui, id),
                    Selection::Connection(id) => self.connection_body(ui, id),
                    Selection::Remediation(id) => self.remediation_body(ui, id),
                    Selection::Cert(id) => self.cert_body(ui, id),
                    Selection::Alert(id) => self.alert_body(ui, id),
                }
            });
    }

    fn finding_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(f) = self.data.findings.iter().find(|f| f.id == id).cloned() else {
            self.selected = None;
            return;
        };
        // The scan this finding came from carries the root that its (relative)
        // location is anchored to — i.e. which repo/folder was scanned.
        let scan = self.store.get_scan(TENANT, &f.scan_id);
        ui.horizontal(|ui| {
            ui.colored_label(sev_color(f.severity), sev_label(f.severity));
            ui.colored_label(pqc_color(f.pqc_status), pqc_label(f.pqc_status));
            ui.label(egui::RichText::new(format!("{:?}", f.status)).color(theme::MUTED));
        });
        ui.add_space(6.0);
        ui.label(egui::RichText::new(&f.title).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("fdetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            kv(ui, "Category", &f.category.to_string());
            if let Some(a) = &f.algorithm {
                kv(ui, "Algorithm", a);
            }
            kv(ui, "Confidence", &format!("{:?}", f.confidence));
            if let Some(s) = &scan {
                ui.label(egui::RichText::new("Scanned root").color(theme::MUTED));
                ui.label(egui::RichText::new(&s.target_address).monospace().small())
                    .on_hover_text("the repo/folder this scan ran against");
                ui.end_row();
                ui.label(egui::RichText::new("Full path").color(theme::MUTED));
                let full = resolve_path(&s.target_address, &f.location);
                copy_value(ui, &full);
                ui.end_row();
                ui.label(egui::RichText::new("Scanner").color(theme::MUTED));
                ui.label(egui::RichText::new(&s.scanner_id).small());
                ui.end_row();
            }
            ui.label(egui::RichText::new("Location").color(theme::MUTED));
            ui.label(egui::RichText::new(&f.location).monospace().small())
                .on_hover_text("relative to the scanned root above");
            ui.end_row();
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Set status:").small().color(theme::MUTED));
            for (lbl, st) in [
                ("Open", FindingStatus::Open),
                ("Acknowledge", FindingStatus::Acknowledged),
                ("Suppress", FindingStatus::Suppressed),
            ] {
                let active = f.status == st;
                if ui.selectable_label(active, lbl).clicked() && !active {
                    self.store.set_finding_status(TENANT, &f.id, st, None);
                    self.refresh();
                }
            }
        });

        // File a remediation ticket/PR via a connected tracker (Online mode).
        // The ticket carries this finding's concrete PQC migration plan.
        let trackers: Vec<(String, String)> = self
            .data
            .connections
            .iter()
            .filter(|c| matches!(c.integration_type.as_str(), "jira" | "linear" | "github" | "gitlab"))
            .map(|c| (c.id.clone(), c.display_name.clone()))
            .collect();
        let mut op: Option<NetOp> = None;
        if !trackers.is_empty() {
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Open ticket:").small().color(theme::MUTED));
                let online = self.net_probes_enabled && !self.net_busy;
                for (cid, name) in &trackers {
                    if ui.add_enabled(online, egui::Button::new(name).small()).clicked() {
                        op = Some(NetOp::OpenTicket { finding_id: f.id.clone(), conn_id: cid.clone() });
                    }
                }
            });
            if !self.net_probes_enabled {
                ui.label(egui::RichText::new("enable Online mode (Settings) to file tickets").color(theme::MUTED).small());
            }
            if !self.net_status.is_empty() {
                ui.label(egui::RichText::new(&self.net_status).color(theme::LOW).small());
            }
        }
        if let Some(op) = op {
            let ctx = ui.ctx().clone();
            self.spawn_net_op(&ctx, op, "Opening ticket");
        }

        ui.add_space(8.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.label(egui::RichText::new("Description").strong());
            ui.label(&f.description);
            if let Some(rem) = &f.remediation {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Remediation").strong().color(theme::GOOD));
                ui.label(rem);
            }
            if !f.evidence.is_empty() {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Evidence").strong());
                for e in &f.evidence {
                    ui.label(egui::RichText::new(format!("* {e}")).monospace().small());
                }
            }
        });
    }

    fn asset_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(a) = self.data.assets.iter().find(|a| a.id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&a.id).strong().size(15.0));
        ui.add_space(8.0);
        let air = has_tag(&a.tags, "air-gapped");
        egui::Grid::new("adetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            kv(ui, "Kind", &a.kind);
            ui.label(egui::RichText::new("Address").color(theme::MUTED));
            ui.label(egui::RichText::new(&a.address).monospace().small());
            ui.end_row();
            kv(ui, "Environment", &a.environment);
            ui.label(egui::RichText::new("PQC").color(theme::MUTED));
            ui.colored_label(status_str_color(&a.pqc_status), pretty_status(&a.pqc_status));
            ui.end_row();
            if let Some(v) = &a.tls_version {
                kv(ui, "TLS", v);
            }
            kv(ui, "Source", &a.source);
            ui.label(egui::RichText::new("Exposure").color(theme::MUTED));
            ui.colored_label(if air { theme::GOOD } else { theme::MUTED }, if air { "air-gapped" } else { "exposed" });
            ui.end_row();
            kv(ui, "Last scanned", &fmt_opt_dt(a.last_scanned));
            if !a.tags.is_empty() {
                kv(ui, "Tags", &a.tags.join(", "));
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button(if air { "Mark exposed" } else { "Mark air-gapped" }).clicked() {
                self.toggle_asset_airgap(&a.id);
            }
            if ui.button("Delete").clicked() {
                self.store.delete_asset(TENANT, &a.id);
                self.selected = None;
                self.refresh();
            }
        });
    }

    fn host_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(t) = self.data.targets.iter().find(|t| t.id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&t.name).strong().size(15.0));
        ui.add_space(8.0);
        let air = has_tag(&t.tags, "air-gapped");
        egui::Grid::new("hdetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            ui.label(egui::RichText::new("Host").color(theme::MUTED));
            ui.label(egui::RichText::new(&t.host).monospace().small());
            ui.end_row();
            kv(ui, "Kind", &t.kind);
            kv(ui, "Environment", &t.environment);
            ui.label(egui::RichText::new("PQC").color(theme::MUTED));
            ui.colored_label(status_str_color(&t.pqc_status), pretty_status(&t.pqc_status));
            ui.end_row();
            kv(ui, "Reachability", &t.reachability.join(", "));
            kv(ui, "Deep scanned", if t.deep_scanned { "yes" } else { "no" });
            ui.label(egui::RichText::new("Exposure").color(theme::MUTED));
            ui.colored_label(if air { theme::GOOD } else { theme::MUTED }, if air { "air-gapped" } else { "exposed" });
            ui.end_row();
            kv(ui, "Last scanned", &fmt_opt_dt(t.last_scanned));
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button(if air { "Mark exposed" } else { "Mark air-gapped" }).clicked() {
                self.toggle_target_airgap(&t.id);
            }
            if ui.button("Delete").clicked() {
                self.store.delete_target(TENANT, &t.id);
                self.selected = None;
                self.refresh();
            }
        });
        ui.add_space(8.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            if t.exposed_services.is_empty() {
                ui.label(egui::RichText::new("No exposed services scanned.").color(theme::MUTED).small());
            } else {
                ui.label(egui::RichText::new(format!("Exposed services ({})", t.exposed_services.len())).strong());
                for s in &t.exposed_services {
                    ui.horizontal(|ui| {
                        ui.colored_label(status_str_color(&s.pqc_status), format!(":{} {}", s.port, s.service));
                        ui.label(egui::RichText::new(&s.detail).color(theme::MUTED).small());
                    });
                }
            }
            if !t.containers.is_empty() {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(format!("Containers ({})", t.containers.len())).strong());
            }
        });
    }

    fn scan_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(s) = self.data.scans.iter().find(|s| s.id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&s.scanner_id).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("sdetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            ui.label(egui::RichText::new("Target").color(theme::MUTED));
            ui.label(egui::RichText::new(&s.target_address).monospace().small());
            ui.end_row();
            kv(ui, "Status", &format!("{:?}", s.status));
            kv(ui, "Findings", &s.finding_count.to_string());
            kv(ui, "Started", &fmt_dt(s.started_at));
            kv(ui, "Completed", &fmt_dt(s.completed_at));
            ui.label(egui::RichText::new("Content hash").color(theme::MUTED));
            ui.label(egui::RichText::new(truncate_str(&s.content_hash, 24)).monospace().small())
                .on_hover_text(&s.content_hash);
            ui.end_row();
        });
    }

    fn endpoint_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(e) = self.data.endpoints.iter().find(|e| e.id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&e.hostname).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("edetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            kv(ui, "OS", &e.os);
            kv(ui, "OS kind", &e.os_kind);
            kv(ui, "Agent", e.agent_version.as_deref().unwrap_or("-"));
            ui.label(egui::RichText::new("PQC").color(theme::MUTED));
            ui.colored_label(status_str_color(&e.pqc_status), pretty_status(&e.pqc_status));
            ui.end_row();
            kv(ui, "Findings", &e.findings_count.to_string());
            kv(ui, "Enrolled", &fmt_dt(e.enrolled_at));
            kv(ui, "Last report", &fmt_dt(e.last_report));
        });
    }

    fn session_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(s) = self.data.sessions.iter().find(|s| s.session_id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&s.agent_name).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("sesdetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            ui.label(egui::RichText::new("Session").color(theme::MUTED));
            ui.label(egui::RichText::new(&s.session_id).monospace().small());
            ui.end_row();
            kv(ui, "Provider", &s.provider);
            kv(ui, "Model", &s.model);
            kv(ui, "Requests", &s.request_count.to_string());
            kv(ui, "Tokens", &s.total_tokens.to_string());
            kv(ui, "Client IP", &s.client_ip);
            kv(ui, "Created", &fmt_dt(s.created_at));
        });
    }

    fn connection_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(c) = self.data.connections.iter().find(|c| c.id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&c.display_name).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("conndetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            kv(ui, "Type", &c.integration_type);
            kv(ui, "Base URL", c.base_url.as_deref().unwrap_or("-"));
            kv(ui, "Org", c.org.as_deref().unwrap_or("-"));
            kv(ui, "Project", c.project.as_deref().unwrap_or("-"));
            kv(ui, "Status", c.last_status.as_deref().unwrap_or("untested"));
            kv(ui, "Secret", "****** (encrypted at rest)");
            kv(ui, "Created", &fmt_dt(c.created_at));
            if let Some(n) = c.findings_count {
                kv(ui, "Findings", &n.to_string());
            }
        });
    }

    fn remediation_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(r) = self.data.remediations.iter().find(|r| r.id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&r.external_id).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("remdetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            kv(ui, "Integration", &r.integration_id);
            kv(ui, "Status", &format!("{:?}", r.status));
            ui.label(egui::RichText::new("Finding").color(theme::MUTED));
            ui.label(egui::RichText::new(&r.finding_id).monospace().small());
            ui.end_row();
            kv(ui, "Created", &fmt_dt(r.created_at));
            kv(ui, "Updated", &fmt_dt(r.updated_at));
            ui.label(egui::RichText::new("URL").color(theme::MUTED));
            ui.label(egui::RichText::new(&r.external_url).small());
            ui.end_row();
        });
    }

    fn cert_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(c) = self.data.certs.iter().find(|c| c.id == id).cloned() else {
            self.selected = None;
            return;
        };
        ui.label(egui::RichText::new(&c.subject).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("certdetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            kv(ui, "Key type", &c.key_type);
            ui.label(egui::RichText::new("PQC").color(theme::MUTED));
            ui.colored_label(status_str_color(&c.pqc_status), pretty_status(&c.pqc_status));
            ui.end_row();
            kv(ui, "State", &c.status);
            ui.label(egui::RichText::new("Serial").color(theme::MUTED));
            ui.label(egui::RichText::new(&c.serial).monospace().small());
            ui.end_row();
            kv(ui, "Not before", &fmt_dt(c.not_before));
            kv(ui, "Not after", &fmt_dt(c.not_after));
            ui.label(egui::RichText::new("CA fingerprint").color(theme::MUTED));
            ui.label(egui::RichText::new(truncate_str(&c.ca_fingerprint, 24)).monospace().small())
                .on_hover_text(&c.ca_fingerprint);
            ui.end_row();
            kv(ui, "Hybrid binding", if c.mldsa_signature.is_some() { "ML-DSA-65 present" } else { "none" });
        });
        if !c.sans.is_empty() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("SANs").strong());
            for s in &c.sans {
                ui.label(egui::RichText::new(s).monospace().small());
            }
        }
    }

    fn endpoints(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Endpoints");
        ui.add_space(6.0);
        let mut open: Option<Selection> = None;
        {
            let d = &self.data;
            data_table(ui, "endpoints", &["Hostname", "OS", "Agent", "PQC", "Findings", "Last report"],
                d.endpoints.len(), "No host agents enrolled.", |ui, i| {
                let e = &d.endpoints[i];
                if link_cell(ui, &e.hostname) {
                    open = Some(Selection::Endpoint(e.id.clone()));
                }
                ui.label(egui::RichText::new(&e.os).color(theme::MUTED));
                ui.label(e.agent_version.as_deref().unwrap_or("-"));
                ui.colored_label(status_str_color(&e.pqc_status), pretty_status(&e.pqc_status));
                ui.label(e.findings_count.to_string());
                ui.label(egui::RichText::new(fmt_dt(e.last_report)).color(theme::MUTED));
            });
        }
        if let Some(s) = open {
            self.selected = Some(s);
        }
    }

    fn assets(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Assets");
        ui.add_space(6.0);

        let mut add = false;
        egui::CollapsingHeader::new("Add asset").show(ui, |ui| {
            let cur = self.asset_form.kind.clone();
            egui::ComboBox::from_label("Template")
                .selected_text(if cur.is_empty() { "- choose -".to_string() } else { cur })
                .show_ui(ui, |ui| {
                    for (name, kind, env) in ASSET_TEMPLATES {
                        if ui.selectable_label(false, *name).clicked() {
                            self.asset_form.kind = kind.to_string();
                            if self.asset_form.environment.is_empty() {
                                self.asset_form.environment = env.to_string();
                            }
                        }
                    }
                });
            egui::Grid::new("assetform").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                ui.label("ID");
                ui.text_edit_singleline(&mut self.asset_form.id);
                ui.end_row();
                ui.label("Address");
                ui.text_edit_singleline(&mut self.asset_form.address);
                ui.end_row();
                ui.label("Kind");
                ui.text_edit_singleline(&mut self.asset_form.kind);
                ui.end_row();
                ui.label("Environment");
                ui.text_edit_singleline(&mut self.asset_form.environment);
                ui.end_row();
            });
            ui.checkbox(&mut self.asset_form.air_gapped, "Air-gapped (no network path - suppresses HNDL risk)");
            ui.label(egui::RichText::new("kind defaults to tls_endpoint, env to default.").color(theme::MUTED).small());
            if ui.button("Add asset").clicked() {
                add = true;
            }
        });
        if add {
            self.add_asset();
        }
        if !self.edit_status.is_empty() {
            ui.label(egui::RichText::new(&self.edit_status).color(theme::MUTED).small());
        }
        ui.add_space(6.0);

        let mut del: Option<String> = None;
        let mut toggle: Option<String> = None;
        let mut probe: Option<(String, String, bool)> = None;
        let mut open: Option<Selection> = None;
        {
            let d = &self.data;
            let probes = &self.probe_results;
            data_table(ui, "assets", &["Asset", "Kind", "Address", "Env", "PQC", "Exposure", ""],
                d.assets.len(), "No declared assets. Add one above.", |ui, i| {
                let a = &d.assets[i];
                let air = has_tag(&a.tags, "air-gapped");
                let name = ui.add(egui::Label::new(egui::RichText::new(&a.id).color(theme::ACCENT)).sense(egui::Sense::click()))
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text("click for details");
                if name.clicked() {
                    open = Some(Selection::Asset(a.id.clone()));
                }
                name.context_menu(|ui| {
                    if ui.button(if air { "Mark exposed" } else { "Mark air-gapped" }).clicked() {
                        toggle = Some(a.id.clone());
                        ui.close_menu();
                    }
                    if ui.button("Verify reachability").clicked() {
                        probe = Some((a.id.clone(), a.address.clone(), air));
                        ui.close_menu();
                    }
                    if ui.button("Delete asset").clicked() {
                        del = Some(a.id.clone());
                        ui.close_menu();
                    }
                });
                ui.label(&a.kind);
                ui.label(egui::RichText::new(&a.address).color(theme::MUTED));
                ui.label(&a.environment);
                ui.colored_label(status_str_color(&a.pqc_status), pretty_status(&a.pqc_status));
                ui.horizontal(|ui| {
                    let (col, txt) = if air { (theme::GOOD, "air-gapped") } else { (theme::MUTED, "exposed") };
                    if ui.selectable_label(air, egui::RichText::new(txt).color(col).small())
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("toggle · right-click to verify reachability").clicked()
                    {
                        toggle = Some(a.id.clone());
                    }
                    probe_badge(ui, probes.get(&a.id), air);
                });
                if ui.small_button("Del").on_hover_text("delete").clicked() {
                    del = Some(a.id.clone());
                }
            });
        }
        if let Some(s) = open {
            self.selected = Some(s);
        }
        if let Some(id) = toggle {
            self.toggle_asset_airgap(&id);
        }
        if let Some((id, addr, air)) = probe {
            let ctx = ui.ctx().clone();
            self.start_probe(id, addr, air, &ctx);
        }
        if let Some(id) = del {
            self.store.delete_asset(TENANT, &id);
            self.edit_status = format!("Deleted asset {id}");
            self.refresh();
        }
    }

    fn remediations(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Remediations");
        ui.add_space(6.0);
        let mut open: Option<Selection> = None;
        {
        let d = &self.data;
        data_table(ui, "remediations", &["Ticket", "Integration", "Status", "Finding", "Updated"],
            d.remediations.len(), "No remediation tickets opened.", |ui, i| {
            let r = &d.remediations[i];
            if link_cell(ui, &r.external_id) { open = Some(Selection::Remediation(r.id.clone())); }
            ui.label(egui::RichText::new(&r.integration_id).color(theme::MUTED));
            ui.label(format!("{:?}", r.status));
            ui.label(egui::RichText::new(truncate_str(&r.finding_id, 14)).monospace().small());
            ui.label(egui::RichText::new(fmt_dt(r.updated_at)).color(theme::MUTED));
        });
        }
        if let Some(s) = open {
            self.selected = Some(s);
        }
    }

    fn overlay(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("PQC Overlay");
        ui.label(egui::RichText::new("Hybrid-PQC TLS listeners fronting legacy upstreams.").color(theme::MUTED).small());
        ui.add_space(6.0);
        let d = &self.data;
        data_table(ui, "overlay", &["Route", "Listen", "Upstream", "Upstream TLS", "Mode"],
            d.overlay_routes.len(), "No overlay routes configured.", |ui, i| {
            let r = &d.overlay_routes[i];
            ui.label(&r.id);
            ui.label(egui::RichText::new(&r.listen).monospace().small());
            ui.label(egui::RichText::new(&r.upstream).monospace().small());
            ui.colored_label(if r.upstream_tls { theme::GOOD } else { theme::MUTED },
                if r.upstream_tls { "re-encrypt" } else { "plaintext" });
            ui.colored_label(if r.mode == "pqc-only" { theme::GOOD } else { theme::LOW }, &r.mode);
        });
    }

    fn connections(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Connections");
        ui.label(egui::RichText::new("UI-managed integrations. Secrets are encrypted at rest and masked here.").color(theme::MUTED).small());
        if self.net_probes_enabled {
            ui.label(egui::RichText::new("Online mode ON - Test and Scan make live API calls.").color(theme::MUTED).small());
        } else {
            ui.label(egui::RichText::new("Offline - enable Online mode in Settings to test or scan connections.").color(theme::MUTED).small());
        }
        if !self.net_status.is_empty() {
            ui.label(egui::RichText::new(&self.net_status).color(theme::LOW).small());
        }
        ui.add_space(6.0);
        let mut open: Option<Selection> = None;
        let mut op: Option<NetOp> = None;
        let online = self.net_probes_enabled && !self.net_busy;
        {
        let d = &self.data;
        data_table(ui, "connections", &["Name", "Type", "Status", "Last scan", "Actions"],
            d.connections.len(), "No connections. Add one from the gateway dashboard.", |ui, i| {
            let c = &d.connections[i];
            if link_cell(ui, &c.display_name) { open = Some(Selection::Connection(c.id.clone())); }
            ui.label(&c.integration_type);
            let (col, s) = match c.last_status.as_deref() {
                Some("connected") => (theme::GOOD, "connected"),
                Some("failed") => (theme::CRIT, "failed"),
                _ => (theme::MUTED, "untested"),
            };
            ui.colored_label(col, s);
            ui.label(egui::RichText::new(c.last_scanned.map(|t| fmt_dt(t)).unwrap_or_else(|| "-".to_string())).color(theme::MUTED).small());
            ui.horizontal(|ui| {
                if ui.add_enabled(online, egui::Button::new("Test").small()).clicked() {
                    op = Some(NetOp::TestConnection { conn_id: c.id.clone() });
                }
                let scannable = matches!(c.integration_type.as_str(), "github" | "gitlab");
                if scannable && ui.add_enabled(online, egui::Button::new("Scan repos").small()).clicked() {
                    op = Some(NetOp::ScanConnection { conn_id: c.id.clone() });
                }
            });
        });
        }
        if let Some(s) = open {
            self.selected = Some(s);
        }
        if let Some(op) = op {
            let ctx = ui.ctx().clone();
            let label = match &op {
                NetOp::TestConnection { .. } => "Testing connection",
                NetOp::ScanConnection { .. } => "Scanning repos",
                NetOp::OpenTicket { .. } => "Opening ticket",
            };
            self.spawn_net_op(&ctx, op, label);
        }
    }

    fn agents(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Agents");
        ui.label(egui::RichText::new("Observed agent → provider flows from the in-path proxy.").color(theme::MUTED).small());
        ui.add_space(6.0);
        let d = &self.data;
        data_table(ui, "agents", &["Agent", "Provider", "Requests", "Sensitive", "Threats", "Last seen"],
            d.flows.len(), "No observed flows yet.", |ui, i| {
            let f = &d.flows[i];
            ui.label(&f.agent);
            ui.label(&f.provider);
            ui.label(f.requests.to_string());
            ui.colored_label(if f.sensitive > 0 { theme::HIGH } else { theme::MUTED }, f.sensitive.to_string());
            ui.colored_label(if f.threats > 0 { theme::CRIT } else { theme::MUTED }, f.threats.to_string());
            ui.label(egui::RichText::new(fmt_dt(f.last_seen)).color(theme::MUTED));
        });
    }

    fn sessions(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Sessions");
        ui.add_space(6.0);
        let mut open: Option<Selection> = None;
        {
        let d = &self.data;
        data_table(ui, "sessions", &["Agent", "Provider", "Model", "Requests", "Client IP", "Started"],
            d.sessions.len(), "No sessions recorded.", |ui, i| {
            let s = &d.sessions[i];
            if link_cell(ui, &s.agent_name) { open = Some(Selection::Session(s.session_id.clone())); }
            ui.label(&s.provider);
            ui.label(egui::RichText::new(&s.model).color(theme::MUTED));
            ui.label(s.request_count.to_string());
            ui.label(egui::RichText::new(&s.client_ip).monospace().small());
            ui.label(egui::RichText::new(fmt_dt(s.created_at)).color(theme::MUTED));
        });
        }
        if let Some(s) = open {
            self.selected = Some(s);
        }
    }

    fn access(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Access (RBAC)");
        ui.label(egui::RichText::new("Runtime user accounts from the store. Config-file users are managed by the gateway.").color(theme::MUTED).small());
        ui.add_space(6.0);
        let d = &self.data;
        data_table(ui, "users", &["User", "Role", "Org", "Created"],
            d.users.len(), "No runtime users. Add users via the gateway admin center.", |ui, i| {
            let u = &d.users[i];
            ui.label(&u.username);
            let rc = match u.role.as_str() {
                "admin" => theme::CRIT, "operator" => theme::HIGH, "auditor" => theme::LOW, _ => theme::MUTED,
            };
            ui.colored_label(rc, &u.role);
            ui.label(&u.org);
            ui.label(egui::RichText::new(fmt_dt(u.created_at)).color(theme::MUTED));
        });
    }

    fn crypto_policies(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Crypto policies");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Export JSON").clicked() {
                    self.export_crypto_policies();
                }
            });
        });
        ui.label(egui::RichText::new(
            "Declarative crypto-agility rules (\"clicks, not code\") evaluated in-process against your local \
             inventory by the shared qw-cbom engine - the same default policy set the gateway enforces.",
        ).color(theme::MUTED).small());
        if !self.export_status.is_empty() {
            ui.label(egui::RichText::new(&self.export_status).color(theme::MUTED).small());
        }
        ui.add_space(8.0);

        let results = self.evaluate_crypto_policies();
        let violated = results.iter().filter(|r| r.status == "violated").count();
        let breached = results.iter().filter(|r| r.deadline_passed).count();
        ui.horizontal(|ui| {
            stat_card(ui, "policies", results.len(), theme::ACCENT);
            stat_card(ui, "violated", violated, if violated > 0 { theme::CRIT } else { theme::GOOD });
            stat_card(ui, "compliant", results.len() - violated, theme::GOOD);
            stat_card(ui, "deadline passed", breached, if breached > 0 { theme::CRIT } else { theme::MUTED });
        });
        ui.add_space(8.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            for r in &results {
                egui::Frame::none().fill(theme::CARD).rounding(6.0).inner_margin(egui::Margin::same(8.0)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (col, txt) = if r.status == "violated" {
                            (theme::CRIT, "VIOLATED")
                        } else {
                            (theme::GOOD, "COMPLIANT")
                        };
                        ui.colored_label(col, txt);
                        ui.label(egui::RichText::new(&r.name).strong());
                        ui.label(egui::RichText::new(format!("[{}]", r.severity)).color(sev_str_color(&r.severity)).small());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // Enforcement + action tell you what the gateway would do.
                            ui.label(egui::RichText::new(format!("{} · {}", r.enforcement, r.action)).color(theme::MUTED).small());
                        });
                    });
                    if !r.description.is_empty() {
                        ui.label(egui::RichText::new(&r.description).color(theme::MUTED).small());
                    }
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(format!("{} violation(s)", r.violation_count)).small());
                        if let Some(d) = r.deadline {
                            let (col, txt) = match r.days_to_deadline {
                                _ if r.deadline_passed => (theme::CRIT, format!("deadline passed ({})", fmt_dt(d))),
                                Some(days) if days < 180 => (theme::MED, format!("{days}d to deadline ({})", fmt_dt(d))),
                                Some(days) => (theme::MUTED, format!("{days}d to deadline")),
                                None => (theme::MUTED, format!("due {}", fmt_dt(d))),
                            };
                            ui.label(egui::RichText::new("·").color(theme::MUTED).small());
                            ui.colored_label(col, egui::RichText::new(txt).small());
                        }
                    });
                    // Drill-down into the specific violating assets.
                    if !r.violations.is_empty() {
                        let head = format!("{} violating asset(s)", r.violations.len());
                        egui::CollapsingHeader::new(head).id_salt(&r.id).show(ui, |ui| {
                            egui::Grid::new(format!("viol-{}", r.id)).striped(true).num_columns(4).spacing([14.0, 4.0]).show(ui, |ui| {
                                for h in ["Location", "Algorithm", "PQC", "Severity"] {
                                    ui.label(egui::RichText::new(h).strong().color(theme::MUTED).small());
                                }
                                ui.end_row();
                                for v in &r.violations {
                                    ui.label(egui::RichText::new(&v.location).monospace().small());
                                    ui.label(egui::RichText::new(v.algorithm.as_deref().unwrap_or("-")).small());
                                    ui.colored_label(status_str_color(&v.pqc_status), egui::RichText::new(pretty_status(&v.pqc_status)).small());
                                    ui.label(egui::RichText::new(&v.severity).small());
                                    ui.end_row();
                                }
                            });
                        });
                    }
                });
                ui.add_space(4.0);
            }
        });
    }

    /// Evaluate the shared default crypto-agility policy set against the local
    /// inventory. Fully offline - no gateway, no network.
    fn evaluate_crypto_policies(&self) -> Vec<qw_cbom::PolicyResult> {
        let policies = qw_cbom::default_policies();
        let assets: Vec<qw_cbom::AssetContext> = self
            .data
            .assets
            .iter()
            .map(|a| qw_cbom::AssetContext {
                address: a.address.clone(),
                kind: a.kind.clone(),
                environment: a.environment.clone(),
                tags: a.tags.clone(),
            })
            .collect();
        qw_cbom::evaluate_policies(&policies, &self.data.findings, &assets, Utc::now())
    }

    fn export_crypto_policies(&mut self) {
        let dir = std::path::Path::new(&self.source)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join("quantawatch-crypto-policies.json");
        let results = self.evaluate_crypto_policies();
        self.export_status = match serde_json::to_string_pretty(&results) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(_) => format!("Exported {} policy results to {}", results.len(), path.display()),
                Err(e) => format!("Export failed: {e}"),
            },
            Err(e) => format!("Serialize failed: {e}"),
        };
    }

    /// Write a print-ready executive Quantum-Risk board report to disk. Assembled
    /// entirely from the local store (posture + attack paths + compliance +
    /// migration roadmap) - the offline counterpart of the gateway's
    /// `/api/report/board`. Output is a self-contained HTML file.
    fn export_board_report(&mut self) {
        // Make sure the attack-path graph reflects current data even if the user
        // hasn't opened the Attack Paths page this session (it builds lazily).
        self.graph.sync(
            &self.data.flows,
            &self.data.targets,
            &self.data.findings,
            &self.data.assets,
        );
        let dir = std::path::Path::new(&self.source)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join("quantawatch-board-report.html");
        let html = self.board_report_html();
        self.export_status = match std::fs::write(&path, html) {
            Ok(_) => format!("Wrote board report to {} (open in a browser, Print to PDF)", path.display()),
            Err(e) => format!("Board report failed: {e}"),
        };
    }

    fn board_report_html(&self) -> String {
        let posture = self.data.posture.as_ref().map(|p| p.overall_score).unwrap_or(0.0);
        let paths = self.graph.paths();
        let critical_paths = paths.iter().filter(|p| p.severity == "critical").count();
        let hndl = paths.iter().filter(|p| p.hndl).count();
        let compliance = ComplianceEngine::assess(&self.data.findings);

        // Composite Quantum Risk Score — identical weighting to the gateway report.
        let exposure_penalty = (critical_paths as f64 * 8.0).min(40.0);
        let quantum_risk =
            ((posture * 0.5 + compliance.overall_compliance_pct * 0.5) - exposure_penalty).clamp(0.0, 100.0);
        let grade = if quantum_risk >= 80.0 {
            ("A", "#1a7f52")
        } else if quantum_risk >= 60.0 {
            ("B", "#b9770a")
        } else if quantum_risk >= 40.0 {
            ("C", "#c2671a")
        } else {
            ("D", "#c0353a")
        };

        let path_rows: String = paths.iter().take(8).map(|p| {
            format!("<tr><td><span class='pill' style='background:{}'>{}</span></td><td><strong>{}</strong>{}</td><td class='num'>{:.0}</td><td>{}</td></tr>",
                report_sev_color(&p.severity), html_esc(&p.severity), html_esc(&p.title),
                if p.observed { "<div class='sub'>observed in traffic</div>" } else { "" },
                p.score, if p.hndl { "HNDL" } else { "—" })
        }).collect();

        let fw_rows: String = compliance.frameworks.iter().map(|f| {
            format!("<tr><td><strong>{}</strong> <span class='sub'>{}</span></td><td class='num'>{:.0}%</td><td class='num'>{}</td></tr>",
                html_esc(&f.name), html_esc(&f.authority), f.compliance_pct,
                f.nearest_deadline.map(|y| y.to_string()).unwrap_or_else(|| "—".into()))
        }).collect();

        let mig_rows: String = compliance.migration_items.iter().take(6).map(|m| {
            format!("<tr><td><span class='pill' style='background:{}'>{}</span></td><td><strong>{}</strong><div class='sub'>&rarr; {}</div></td><td class='num'>{}</td><td class='num'>{}</td></tr>",
                if m.priority == "P0" { "#c0353a" } else if m.priority == "P1" { "#c2671a" } else { "#5b5fc7" },
                html_esc(&m.priority), html_esc(&m.title), html_esc(&m.target_state), m.affected_count, m.deadline_year)
        }).collect();

        let date = Utc::now().format("%Y-%m-%d %H:%M UTC");
        let build = build_stamp();

        format!(
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
    <div class="muted">QuantaWatch Desktop · Post-Quantum Posture Management · {date}</div></div></div>

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

  <div class="foot">Generated offline from the local QuantaWatch store by {build}. {total} cryptographic findings assessed against CNSA 2.0, NIST IR 8547 and FIPS 203/204. For a cryptographically-attested inventory, export the signed CBOM.</div>
</body></html>"#,
            date = date,
            grade = grade.0,
            grade_color = grade.1,
            quantum_risk = quantum_risk,
            posture = posture,
            compliance = compliance.overall_compliance_pct,
            critical_paths = critical_paths,
            hndl = hndl,
            build = html_esc(&build),
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
            total = compliance.total_findings,
        )
    }

    fn compliance(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Compliance");
        ui.label(egui::RichText::new("Computed in-process by the shared qw-cbom engine from your findings.").color(theme::MUTED).small());
        ui.add_space(8.0);
        let report = ComplianceEngine::assess(&self.data.findings);
        ui.horizontal(|ui| {
            let col = score_color(report.overall_compliance_pct);
            ui.label(egui::RichText::new(format!("{:.0}%", report.overall_compliance_pct)).size(30.0).strong().color(col));
            ui.vertical(|ui| {
                ui.add_space(6.0);
                ui.label(egui::RichText::new("overall compliant").color(theme::MUTED).small());
                ui.label(egui::RichText::new(format!(
                    "{} compliant · {} at risk · {} non-compliant",
                    report.compliant, report.at_risk, report.non_compliant
                )).small());
            });
        });
        ui.add_space(10.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("frameworks").striped(true).num_columns(4).spacing([16.0, 6.0]).show(ui, |ui| {
                for h in ["Framework", "Authority", "Compliance", "Deadline"] {
                    ui.label(egui::RichText::new(h).strong().color(theme::MUTED));
                }
                ui.end_row();
                for fw in &report.frameworks {
                    ui.label(&fw.name);
                    ui.label(egui::RichText::new(&fw.authority).color(theme::MUTED));
                    ui.colored_label(score_color(fw.compliance_pct), format!("{:.0}%", fw.compliance_pct));
                    ui.label(fw.nearest_deadline.map(|y| y.to_string()).unwrap_or_else(|| "-".to_string()));
                    ui.end_row();
                }
            });
            if !report.migration_items.is_empty() {
                ui.add_space(12.0);
                ui.label(egui::RichText::new("Migration items").strong());
                ui.add_space(4.0);
                for m in &report.migration_items {
                    egui::Frame::none().fill(theme::CARD).rounding(6.0).inner_margin(egui::Margin::same(8.0)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let pc = match m.priority.as_str() {
                                "p0" | "critical" => theme::CRIT,
                                "p1" | "high" => theme::HIGH,
                                _ => theme::MED,
                            };
                            ui.colored_label(pc, m.priority.to_uppercase());
                            ui.label(egui::RichText::new(&m.title).small());
                        });
                        ui.label(egui::RichText::new(format!(
                            "{} → {} · by {} · {} affected",
                            m.current_state, m.target_state, m.deadline_year, m.affected_count
                        )).color(theme::MUTED).small());
                    });
                    ui.add_space(4.0);
                }
            }
        });
    }

    fn frameworks(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Frameworks");
        ui.label(egui::RichText::new("Shared qw-cbom control set (CNSA 2.0, NIST 800-53, PCI-DSS, FedRAMP). Evaluated from local signals - the gateway's live config is authoritative.").color(theme::MUTED).small());
        ui.add_space(8.0);

        // Best-effort signals from what the local store reveals.
        let at_rest = self
            .data
            .findings
            .iter()
            .any(|f| f.category.to_string().contains("at_rest") || f.category.to_string().contains("unencrypted"));
        let signals = frameworks::Signals {
            auth_on: !self.data.users.is_empty() || !self.data.sessions.is_empty(),
            lockout: true,
            idle_timeout: true,
            enforce_on: false,
            enforce_block: false,
            at_rest_on: at_rest,
            key_rotation: false,
            tls_scan: true,
            target_pqc: false,
            forbidden_set: false,
            alerts_on: false,
        };
        let fws = frameworks::all(&signals);

        egui::ScrollArea::vertical().show(ui, |ui| {
            for f in &fws {
                let pass = f
                    .controls
                    .iter()
                    .all(|c| !c.required || matches!(c.status, frameworks::Status::Enforced));
                egui::CollapsingHeader::new(egui::RichText::new(f.name).strong())
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(if pass { theme::GOOD } else { theme::HIGH },
                                if pass { "PASS" } else { "GAPS" });
                            ui.label(egui::RichText::new(f.description).color(theme::MUTED).small());
                        });
                        ui.add_space(4.0);
                        egui::Grid::new(f.id).striped(true).num_columns(3).spacing([14.0, 4.0]).show(ui, |ui| {
                            for ctl in &f.controls {
                                let (col, txt) = fw_status(&ctl.status);
                                ui.colored_label(col, txt);
                                ui.label(egui::RichText::new(ctl.title).small());
                                ui.label(egui::RichText::new(&ctl.evidence).color(theme::MUTED).small());
                                ui.end_row();
                            }
                        });
                    });
                ui.add_space(6.0);
            }
        });
    }

    fn soc2(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("SOC 2");
        ui.label(egui::RichText::new("Shared qw-cbom control set. Evaluated from local store signals - the gateway's live config is authoritative.").color(theme::MUTED).small());
        ui.add_space(8.0);
        // Best-effort inputs from what the local store reveals.
        let auth_on = !self.data.users.is_empty() || !self.data.sessions.is_empty();
        let inputs = soc2::Soc2Inputs {
            auth_enabled: auth_on,
            max_failed_logins: 5,
            lockout_secs: 900,
            session_ttl_secs: 28800,
            idle_timeout_secs: 3600,
            sso_enabled: false,
            custom_roles: false,
            tls_scanner_enabled: true,
            alerts_enabled: false,
            shared_identity: false,
        };
        let report = soc2::assess(&inputs);
        ui.label(egui::RichText::new(format!(
            "{} enforced · {} partial · {} configurable · {} manual",
            report.enforced, report.partial, report.configurable, report.manual
        )).small());
        ui.add_space(8.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            for c in &report.controls {
                egui::Frame::none().fill(theme::CARD).rounding(6.0).inner_margin(egui::Margin::same(8.0)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (col, txt) = soc2_status(&c.status);
                        ui.colored_label(col, txt);
                        ui.label(egui::RichText::new(c.criteria).monospace().small());
                        ui.label(egui::RichText::new(c.title).strong());
                    });
                    ui.label(egui::RichText::new(&c.evidence).color(theme::MUTED).small());
                });
                ui.add_space(4.0);
            }
        });
    }

    fn threats(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Threats");
        ui.label(egui::RichText::new("Security events surfaced from the audit stream - blocked threats, policy & access violations.").color(theme::MUTED).small());
        ui.add_space(6.0);
        let d = &self.data;
        let threats: Vec<(&AuditEntry, (String, &'static str, String, bool))> = d
            .audit
            .iter()
            .filter_map(|e| event_to_threat(&e.event).map(|t| (e, t)))
            .collect();
        data_table(ui, "threats", &["Time", "Category", "Severity", "Action", "Detail"],
            threats.len(), "No threats detected in the audit stream.", |ui, i| {
            let (e, (cat, sev, msg, blocked)) = &threats[i];
            ui.label(egui::RichText::new(fmt_dt(e.timestamp)).color(theme::MUTED));
            ui.label(cat);
            ui.colored_label(graphview::severity_color(sev), sev.to_uppercase());
            ui.colored_label(if *blocked { theme::CRIT } else { theme::MED },
                if *blocked { "blocked" } else { "flagged" });
            ui.label(egui::RichText::new(msg).small());
        });
    }

    fn alerts(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Alerts");
        ui.label(egui::RichText::new("Notifications the gateway raised - posture breaches, detected threats, SLO-gate failures. Read from the local store; click one for detail.").color(theme::MUTED).small());
        ui.add_space(6.0);
        let d = &self.data;
        let mut open = None;
        data_table(ui, "alerts", &["Time", "Severity", "Kind", "Title", "Delivered"],
            d.alerts.len(), "No alerts recorded.", |ui, i| {
            let a = &d.alerts[i];
            ui.label(egui::RichText::new(fmt_dt(a.timestamp)).color(theme::MUTED));
            let (col, txt) = alert_sev(a.severity);
            ui.colored_label(col, txt);
            ui.label(egui::RichText::new(&a.kind).small());
            if link_cell(ui, &a.title) {
                open = Some(Selection::Alert(a.id.clone()));
            }
            ui.label(egui::RichText::new(a.delivered.to_string()).color(theme::MUTED).small());
        });
        if let Some(s) = open {
            self.selected = Some(s);
        }
    }

    fn alert_body(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(a) = self.data.alerts.iter().find(|a| a.id == id).cloned() else {
            self.selected = None;
            return;
        };
        let (col, txt) = alert_sev(a.severity);
        ui.horizontal(|ui| {
            ui.colored_label(col, txt);
            ui.label(egui::RichText::new(&a.kind).color(theme::MUTED));
        });
        ui.add_space(6.0);
        ui.label(egui::RichText::new(&a.title).strong().size(15.0));
        ui.add_space(8.0);
        egui::Grid::new("adetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            kv(ui, "Raised", &fmt_dt(a.timestamp));
            kv(ui, "Delivered", &a.delivered.to_string());
            ui.label(egui::RichText::new("Alert id").color(theme::MUTED));
            ui.label(egui::RichText::new(&a.id).monospace().small());
            ui.end_row();
        });
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Message").strong());
        ui.label(&a.message);
        if !a.metadata.is_empty() {
            ui.add_space(8.0);
            ui.label(egui::RichText::new("Metadata").strong());
            let mut keys: Vec<&String> = a.metadata.keys().collect();
            keys.sort();
            egui::Grid::new("ameta").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                for k in keys {
                    kv(ui, k, &a.metadata[k]);
                }
            });
        }
    }

    fn governance(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Governance / SLO");
        ui.label(egui::RichText::new("Crypto-agility governance verdicts and PQC-migration SLO gates, tracked over time. Read from the local store.").color(theme::MUTED).small());
        ui.add_space(8.0);
        let d = &self.data;
        if let Some(g) = d.gov_hist.last() {
            ui.horizontal(|ui| {
                stat_card(ui, "agility score", g.agility_score.round() as usize, score_color(g.agility_score));
                stat_card(ui, "compliant", g.compliant as usize, theme::GOOD);
                stat_card(ui, "deprecated", g.deprecated as usize, theme::MED);
                stat_card(ui, "forbidden", g.forbidden as usize, theme::CRIT);
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new(format!("Latest verdict: {}   ({})", g.verdict, fmt_dt(g.timestamp))).small());
        } else {
            ui.label(egui::RichText::new("No governance snapshots recorded yet.").color(theme::MUTED));
        }
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);
        ui.label(egui::RichText::new("PQC migration SLO").strong());
        if let Some(s) = d.slo_hist.last() {
            let pct = if s.total > 0 { (s.passing as f64 / s.total as f64) * 100.0 } else { 0.0 };
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("{pct:.0}% passing"))
                    .size(20.0).strong()
                    .color(if s.gate_breach { theme::CRIT } else { theme::GOOD }));
                ui.label(egui::RichText::new(format!("{}/{} objectives · {} failing", s.passing, s.total, s.failing)).color(theme::MUTED).small());
                if s.gate_breach {
                    ui.colored_label(theme::CRIT, "GATE BREACHED");
                }
            });
        } else {
            ui.label(egui::RichText::new("No SLO snapshots recorded yet.").color(theme::MUTED));
        }
        ui.add_space(12.0);
        let gh: Vec<&GovernanceSnapshot> = d.gov_hist.iter().rev().collect();
        let sh: Vec<&SloSnapshot> = d.slo_hist.iter().rev().collect();
        ui.columns(2, |cols| {
            cols[0].label(egui::RichText::new("Governance history").strong());
            cols[0].add_space(4.0);
            data_table(&mut cols[0], "govhist", &["Time", "Score", "Verdict"], gh.len(), "No history yet.", |ui, i| {
                let g = gh[i];
                ui.label(egui::RichText::new(fmt_dt(g.timestamp)).color(theme::MUTED).small());
                ui.label(format!("{:.0}", g.agility_score));
                ui.label(egui::RichText::new(&g.verdict).small());
            });
            cols[1].label(egui::RichText::new("SLO history").strong());
            cols[1].add_space(4.0);
            data_table(&mut cols[1], "slohist", &["Time", "Pass/Total", "Gate"], sh.len(), "No history yet.", |ui, i| {
                let s = sh[i];
                ui.label(egui::RichText::new(fmt_dt(s.timestamp)).color(theme::MUTED).small());
                ui.label(format!("{}/{}", s.passing, s.total));
                ui.colored_label(if s.gate_breach { theme::CRIT } else { theme::GOOD },
                    if s.gate_breach { "breach" } else { "ok" });
            });
        });
    }

    fn cbom(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Cryptographic Bill of Materials");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Export JSON").clicked() {
                    self.export_cbom();
                }
            });
        });
        ui.label(egui::RichText::new("Every distinct cryptographic algorithm discovered across the estate, with its quantum-readiness. Built in-process from local scan findings - no network.").color(theme::MUTED).small());
        if !self.export_status.is_empty() {
            ui.label(egui::RichText::new(&self.export_status).color(theme::MUTED).small());
        }
        ui.add_space(6.0);
        let entries = cbom_entries(&self.data.findings);
        if entries.is_empty() {
            empty_state(ui, "No cryptographic assets found. Run a scan first (Scans → Scan directory, or `qw scan`).");
            return;
        }
        let vuln = entries.iter().filter(|e| e.quantum_vulnerable).count();
        ui.horizontal(|ui| {
            stat_card(ui, "algorithms", entries.len(), theme::ACCENT);
            stat_card(ui, "quantum-vulnerable", vuln, if vuln > 0 { theme::CRIT } else { theme::GOOD });
            stat_card(ui, "quantum-safe", entries.len() - vuln, theme::GOOD);
        });
        ui.add_space(8.0);
        data_table(ui, "cbom", &["Algorithm", "Used as", "Uses", "PQC", "Quantum-vulnerable"],
            entries.len(), "-", |ui, i| {
            let e = &entries[i];
            ui.label(egui::RichText::new(&e.algorithm).monospace());
            ui.label(egui::RichText::new(&e.kinds).color(theme::MUTED).small());
            ui.label(e.count.to_string());
            ui.colored_label(pqc_color(e.worst_pqc), pqc_label(e.worst_pqc));
            ui.colored_label(if e.quantum_vulnerable { theme::CRIT } else { theme::GOOD },
                if e.quantum_vulnerable { "yes" } else { "no" });
        });
    }

    fn export_cbom(&mut self) {
        let dir = std::path::Path::new(&self.source)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join("quantawatch-cbom.json");
        let entries = cbom_entries(&self.data.findings);
        self.export_status = match serde_json::to_string_pretty(&entries) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(_) => format!("Exported {} crypto assets to {}", entries.len(), path.display()),
                Err(e) => format!("Export failed: {e}"),
            },
            Err(e) => format!("Serialize failed: {e}"),
        };
    }

    fn audit(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Audit log");
        ui.label(egui::RichText::new("Tamper-evident, ML-DSA-65-signed hash chain - read from the local store.").color(theme::MUTED).small());
        ui.add_space(6.0);
        let d = &self.data;
        data_table(ui, "audit", &["Time", "Writer", "Seq", "Session", "Event"],
            d.audit.len(), "No audit entries yet.", |ui, i| {
            let e = &d.audit[i];
            ui.label(egui::RichText::new(fmt_dt(e.timestamp)).color(theme::MUTED));
            ui.label(egui::RichText::new(&e.writer_id).small());
            ui.label(e.sequence.to_string());
            ui.label(egui::RichText::new(truncate_str(&e.session_id, 10)).monospace().small());
            let full = format!("{:?}", e.event);
            ui.label(egui::RichText::new(truncate_str(&full, 72)).small())
                .on_hover_text(&full);
        });
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Settings");
        ui.label(egui::RichText::new("App-local settings for this desktop client. Gateway policy (auth, enforcement, alerts, RBAC) is managed by the gateway config, not here.").color(theme::MUTED).small());
        ui.add_space(10.0);
        egui::Grid::new("settings").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
            ui.label("Store");
            ui.label(egui::RichText::new(&self.source).monospace().small().color(theme::MUTED));
            ui.end_row();
            ui.label("Default scan directory");
            ui.text_edit_singleline(&mut self.scan_path);
            ui.end_row();
            ui.label("Terminal");
            ui.checkbox(&mut self.terminal_open, "open");
            ui.end_row();
            ui.label("Terminal mode");
            ui.checkbox(&mut self.terminal_float, "floating window (else docked)");
            ui.end_row();
        });
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);
        ui.label(egui::RichText::new("Mode").strong());
        ui.checkbox(&mut self.net_probes_enabled, "Online mode - allow network  (default: OFFLINE / air-gapped)");
        ui.label(egui::RichText::new(
            "Off by default the app is fully air-gapped: it makes no network calls and reads only the local \
             store. Turn this on to allow network features - reachability probes, live packet capture (tshark), \
             and, as they land, connection tests / ticket sync / certificate operations. The top-bar badge \
             always shows the current mode.",
        ).color(theme::MUTED).small());
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Wireshark (tshark):");
            match &self.tshark_ver {
                Some(v) if v.is_empty() => { ui.colored_label(theme::MUTED, "not detected on PATH"); }
                Some(v) => { ui.colored_label(theme::GOOD, v); }
                None => { ui.colored_label(theme::MUTED, "unknown"); }
            }
            if ui.small_button("Detect").clicked() {
                self.tshark_ver = Some(tshark_version().unwrap_or_default());
            }
        });
        ui.label(egui::RichText::new(
            "Optional deeper check: with probes on and Wireshark installed, run `capture <host>` in the \
             terminal to sniff live packets to/from a host (tshark). Confirms real traffic beyond a TCP connect. \
             Requires capture privileges.",
        ).color(theme::MUTED).small());
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);
        ui.label(egui::RichText::new("Data").strong());
        if ui.button("Refresh from store").clicked() {
            self.refresh();
        }
        ui.label(egui::RichText::new(format!(
            "{} findings · {} hosts · {} assets · {} certs loaded",
            self.data.findings.len(), self.data.targets.len(), self.data.assets.len(), self.data.certs.len()
        )).color(theme::MUTED).small());
    }

    fn activity_bar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("activity")
            .exact_width(42.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    let go = |ui: &mut egui::Ui, icon: &str, tip: &str, p: Page, page: &mut Page| {
                        if ui.selectable_label(*page == p, egui::RichText::new(icon).size(16.0)).on_hover_text(tip).clicked() {
                            *page = p;
                        }
                        ui.add_space(2.0);
                    };
                    go(ui, "📊", "Overview", Page::Overview, &mut self.page);
                    go(ui, "🎯", "Attack paths", Page::AttackPaths, &mut self.page);
                    go(ui, "⚠", "Findings", Page::Findings, &mut self.page);
                    go(ui, "🌐", "Estate", Page::Estate, &mut self.page);
                    go(ui, "📜", "Audit log", Page::Audit, &mut self.page);
                    ui.add_space(6.0);
                    if ui.selectable_label(self.terminal_open, egui::RichText::new("💻").size(16.0)).on_hover_text("Terminal (Ctrl+`)").clicked() {
                        self.terminal_open = !self.terminal_open;
                    }
                });
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    if ui.selectable_label(self.page == Page::Settings, egui::RichText::new("⚙").size(16.0)).on_hover_text("Settings").clicked() {
                        self.page = Page::Settings;
                    }
                });
            });
    }

    fn about(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("About");
        ui.add_space(8.0);
        ui.label("QuantaWatch Desktop - a native, offline view of your post-quantum posture.");
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Air-gap posture").strong());
        ui.label("* No embedded browser or webview - this is a native egui window.");
        ui.label("* No network listener and no outbound calls - it reads the local store in-process.");
        ui.label("* Links the same qw-store / qw-scanner / qw-cbom crates the gateway uses.");
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Store path").strong());
        ui.label(egui::RichText::new(&self.source).monospace().color(theme::MUTED));
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Build").strong());
        ui.label(egui::RichText::new(build_stamp()).monospace().color(theme::MUTED));
        ui.label(egui::RichText::new("If this build time is older than your last change, you're running a stale exe - rebuild.").color(theme::MUTED).small());
    }
}

// ----------------------------------------------------------------------------- widgets

fn nav_item(ui: &mut egui::Ui, page: &mut Page, target: Page, label: &str, badge: Option<usize>) {
    let selected = *page == target;
    let text = match badge {
        Some(n) if n > 0 => format!("{label}   ({n})"),
        _ => label.to_string(),
    };
    let resp = ui.selectable_label(selected, egui::RichText::new(text).size(14.0));
    if resp.clicked() {
        *page = target;
    }
}

fn page_title(p: Page) -> &'static str {
    match p {
        Page::Overview => "Overview",
        Page::AttackPaths => "Attack Paths",
        Page::Estate => "Estate",
        Page::Endpoints => "Endpoints",
        Page::Assets => "Assets",
        Page::Findings => "Findings",
        Page::Certificates => "Certificates",
        Page::Cbom => "Crypto (CBOM)",
        Page::Compliance => "Compliance",
        Page::CryptoPolicies => "Crypto Policies",
        Page::Frameworks => "Frameworks",
        Page::Soc2 => "SOC 2",
        Page::Governance => "Governance/SLO",
        Page::Scans => "Scans",
        Page::Remediations => "Remediations",
        Page::Overlay => "PQC Overlay",
        Page::Connections => "Connections",
        Page::Agents => "Agents",
        Page::Sessions => "Sessions",
        Page::Threats => "Threats",
        Page::Alerts => "Alerts",
        Page::Audit => "Audit Log",
        Page::Access => "Access (RBAC)",
        Page::Settings => "Settings",
        Page::About => "About",
    }
}

fn page_by_name(name: &str) -> Option<Page> {
    let n = name.trim().to_lowercase().replace([' ', '-', '_'], "");
    let pages = [
        Page::Overview, Page::AttackPaths, Page::Estate, Page::Endpoints, Page::Assets,
        Page::Findings, Page::Certificates, Page::Cbom, Page::Compliance, Page::CryptoPolicies,
        Page::Frameworks, Page::Soc2, Page::Governance, Page::Scans, Page::Remediations, Page::Overlay,
        Page::Connections, Page::Agents, Page::Sessions, Page::Threats, Page::Alerts,
        Page::Audit, Page::Access, Page::Settings, Page::About,
    ];
    pages
        .into_iter()
        .find(|p| page_title(*p).to_lowercase().replace([' ', '-', '_', '(', ')'], "").starts_with(&n))
}

fn nav_group(ui: &mut egui::Ui, label: &str) {
    ui.add_space(8.0);
    ui.label(egui::RichText::new(label).color(theme::MUTED).small().strong());
    ui.add_space(2.0);
}

/// A striped table: headers + `rows` invocations of `cell`, which fills one row.
fn data_table(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: usize,
    empty: &str,
    mut cell: impl FnMut(&mut egui::Ui, usize),
) {
    if rows == 0 {
        empty_state(ui, empty);
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new(id)
            .striped(true)
            .num_columns(headers.len())
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                for h in headers {
                    ui.label(egui::RichText::new(*h).strong().color(theme::MUTED));
                }
                ui.end_row();
                for r in 0..rows {
                    cell(ui, r);
                    ui.end_row();
                }
            });
    });
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: usize, color: egui::Color32) {
    egui::Frame::none()
        .fill(theme::CARD)
        .rounding(8.0)
        .inner_margin(egui::Margin::symmetric(18.0, 12.0))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(value.to_string()).size(26.0).strong().color(color));
                ui.label(egui::RichText::new(label).color(theme::MUTED).small());
            });
        });
}

fn empty_state(ui: &mut egui::Ui, msg: &str) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new(msg).color(theme::MUTED));
    });
}

// ----------------------------------------------------------------------------- mappings

fn sev_rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Info => 0,
        FindingSeverity::Low => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::High => 3,
        FindingSeverity::Critical => 4,
    }
}
fn sev_label(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Info => "INFO",
        FindingSeverity::Low => "LOW",
        FindingSeverity::Medium => "MED",
        FindingSeverity::High => "HIGH",
        FindingSeverity::Critical => "CRIT",
    }
}
fn sev_color(s: FindingSeverity) -> egui::Color32 {
    match s {
        FindingSeverity::Critical => theme::CRIT,
        FindingSeverity::High => theme::HIGH,
        FindingSeverity::Medium => theme::MED,
        FindingSeverity::Low => theme::LOW,
        FindingSeverity::Info => theme::MUTED,
    }
}
fn pqc_label(p: PqcStatus) -> &'static str {
    match p {
        PqcStatus::PqcReady => "PQC",
        PqcStatus::Hybrid => "Hybrid",
        PqcStatus::ClassicalSecure => "Classical",
        PqcStatus::ClassicalWeak => "Weak",
        PqcStatus::Unknown => "Unknown",
    }
}
fn pqc_color(p: PqcStatus) -> egui::Color32 {
    match p {
        PqcStatus::PqcReady => theme::GOOD,
        PqcStatus::Hybrid => theme::LOW,
        PqcStatus::ClassicalSecure => theme::MED,
        PqcStatus::ClassicalWeak => theme::CRIT,
        PqcStatus::Unknown => theme::MUTED,
    }
}
fn score_color(s: f64) -> egui::Color32 {
    if s >= 80.0 {
        theme::GOOD
    } else if s >= 50.0 {
        theme::MED
    } else {
        theme::CRIT
    }
}

/// Kill-chain stage status → color. `blocked`/`na` are good for the defender
/// (the attacker can't advance); `active`/`feasible` are bad.
fn kc_status_color(status: &str) -> egui::Color32 {
    match status {
        "active" => theme::CRIT,
        "feasible" => theme::MED,
        "pending" => theme::LOW,
        "blocked" => theme::GOOD,
        _ => theme::MUTED, // na
    }
}

/// Alert severity → (color, label) for the Alerts page/panel.
fn alert_sev(s: AlertSeverity) -> (egui::Color32, &'static str) {
    match s {
        AlertSeverity::Critical => (theme::CRIT, "CRITICAL"),
        AlertSeverity::Warning => (theme::MED, "WARNING"),
        AlertSeverity::Info => (theme::MUTED, "INFO"),
    }
}

/// "Worst-first" rank for a PQC status - higher = more quantum-exposed. Used to
/// pick the worst posture across all uses of one algorithm in the CBOM.
fn pqc_rank(p: PqcStatus) -> u8 {
    match p {
        PqcStatus::PqcReady => 0,
        PqcStatus::Hybrid => 1,
        PqcStatus::Unknown => 2,
        PqcStatus::ClassicalSecure => 3,
        PqcStatus::ClassicalWeak => 4,
    }
}

/// One row of the Cryptographic Bill of Materials: a distinct algorithm and the
/// aggregate posture of every place it was found.
#[derive(serde::Serialize)]
struct CbomEntry {
    algorithm: String,
    /// Comma-joined asset kinds this algorithm is used as (e.g. "TlsConnection, Certificate").
    kinds: String,
    /// How many findings reference this algorithm.
    count: usize,
    /// Worst PQC posture observed across those uses.
    #[serde(skip)]
    worst_pqc: PqcStatus,
    pqc_status: String,
    quantum_vulnerable: bool,
    example_location: String,
}

/// Collapse the finding list into a deduplicated crypto inventory keyed by
/// algorithm. Findings with no named algorithm are skipped.
fn cbom_entries(findings: &[FindingRecord]) -> Vec<CbomEntry> {
    use std::collections::{BTreeMap, BTreeSet};
    struct Acc {
        worst: PqcStatus,
        kinds: BTreeSet<String>,
        count: usize,
        example: String,
    }
    let mut map: BTreeMap<String, Acc> = BTreeMap::new();
    for f in findings {
        let Some(alg) = f.algorithm.as_ref().map(|a| a.trim()).filter(|a| !a.is_empty()) else {
            continue;
        };
        let e = map.entry(alg.to_string()).or_insert_with(|| Acc {
            worst: PqcStatus::PqcReady,
            kinds: BTreeSet::new(),
            count: 0,
            example: f.location.clone(),
        });
        e.count += 1;
        e.kinds.insert(format!("{:?}", f.asset_type));
        if pqc_rank(f.pqc_status) > pqc_rank(e.worst) {
            e.worst = f.pqc_status;
            e.example = f.location.clone();
        }
    }
    let mut out: Vec<CbomEntry> = map
        .into_iter()
        .map(|(algorithm, a)| CbomEntry {
            algorithm,
            kinds: a.kinds.into_iter().collect::<Vec<_>>().join(", "),
            count: a.count,
            worst_pqc: a.worst,
            pqc_status: pqc_label(a.worst).to_string(),
            quantum_vulnerable: matches!(
                a.worst,
                PqcStatus::ClassicalSecure | PqcStatus::ClassicalWeak
            ),
            example_location: a.example,
        })
        .collect();
    // Most-exposed first, then most-used.
    out.sort_by(|x, y| {
        pqc_rank(y.worst_pqc)
            .cmp(&pqc_rank(x.worst_pqc))
            .then(y.count.cmp(&x.count))
    });
    out
}
fn status_str_color(s: &str) -> egui::Color32 {
    match s.to_lowercase().replace(['_', '-'], "").as_str() {
        x if x.contains("weak") || x.contains("vulnerable") => theme::CRIT,
        x if x.contains("hybrid") => theme::LOW,
        x if x.contains("ready") || x.contains("pqc") => theme::GOOD,
        _ => theme::MUTED,
    }
}

/// Color for a severity given as a string ("low" | "medium" | "high" | "critical").
fn sev_str_color(s: &str) -> egui::Color32 {
    match s.to_lowercase().as_str() {
        "critical" => theme::CRIT,
        "high" => theme::HIGH,
        "medium" => theme::MED,
        "low" => theme::LOW,
        _ => theme::MUTED,
    }
}

/// Minimal HTML escaping for the board report (untrusted store strings).
fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Severity → print-friendly hex color for the board report.
fn report_sev_color(s: &str) -> &'static str {
    match s {
        "critical" => "#c0353a",
        "high" => "#c2671a",
        "medium" => "#b9770a",
        _ => "#5b5fc7",
    }
}
/// Map an audit event to a threat row (category, severity, message, blocked),
/// mirroring the gateway's /api/threats derivation. Non-security events → None.
fn event_to_threat(ev: &AuditEvent) -> Option<(String, &'static str, String, bool)> {
    match ev {
        AuditEvent::ThreatBlocked {
            category,
            severity,
            pattern,
        } => Some((
            category.clone(),
            norm_sev(severity),
            format!("In-path monitor blocked {category} (pattern: {pattern})"),
            true,
        )),
        AuditEvent::PolicyViolation {
            rule,
            reason,
            agent_name,
        } => Some((
            "policy_violation".to_string(),
            "medium",
            format!("Agent '{agent_name}' violated policy '{rule}': {reason}"),
            true,
        )),
        AuditEvent::CryptoPolicyEnforced {
            provider,
            agent,
            action,
            channel_status,
            required,
        } => {
            let blocked = action == "blocked";
            Some((
                "quantum_unsafe_channel".to_string(),
                if blocked { "high" } else { "medium" },
                format!("Agent '{agent}' → {provider}: channel {channel_status} below required {required} ({action})"),
                blocked,
            ))
        }
        AuditEvent::AccessDenied {
            principal,
            method,
            path,
            required_permission,
        } => Some((
            "unauthorized_access".to_string(),
            "medium",
            format!("{principal} was denied {method} {path} (needs {required_permission})"),
            true,
        )),
        AuditEvent::LoginFailed {
            username,
            client_ip,
        } => Some((
            "failed_login".to_string(),
            "low",
            format!("Failed login for '{username}' from {client_ip}"),
            false,
        )),
        _ => None,
    }
}

fn norm_sev(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "warning" => "medium",
        "low" => "low",
        _ => "info",
    }
}

// ---- Wireshark / tshark integration (Wireshark's CLI). Optional, opt-in. ----

/// Detect tshark on PATH; returns its version line (empty string if not found).
fn tshark_version() -> Option<String> {
    let out = std::process::Command::new("tshark").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string(),
    )
}

/// `tshark -D` - the capture interfaces Wireshark can see.
fn tshark_interfaces() -> Result<Vec<String>, String> {
    let out = std::process::Command::new("tshark")
        .arg("-D")
        .output()
        .map_err(|e| format!("could not run tshark ({e}); is Wireshark installed?"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr)
            .lines()
            .next()
            .unwrap_or("tshark -D failed")
            .to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect())
}

/// Live packet capture to/from a host via tshark. Bounded by count and an 8s
/// stop timer. Needs Wireshark installed and capture privileges.
fn tshark_capture(host: &str, count: usize) -> Result<Vec<String>, String> {
    let out = std::process::Command::new("tshark")
        .args([
            "-a",
            "duration:8",
            "-c",
            &count.to_string(),
            "-f",
            &format!("host {host}"),
        ])
        .output()
        .map_err(|e| format!("could not run tshark ({e}); is Wireshark installed and on PATH?"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err.lines().next().unwrap_or("capture failed").to_string());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut result = vec![format!("captured {} packet(s) to/from {host}", lines.len())];
    result.extend(lines.into_iter().take(15));
    if result.len() == 1 {
        result.push("(no packets - host may be air-gapped, idle, or unreachable)".to_string());
    }
    Ok(result)
}

/// Ensure `host:port` form: strip any scheme, default the port to 443.
fn normalize_probe_addr(addr: &str) -> String {
    let a = addr.trim().rsplit("://").next().unwrap_or(addr).trim();
    let a = a.split('/').next().unwrap_or(a); // drop any path
    // If it already ends in `:<digits>`, keep it; else append :443.
    match a.rsplit_once(':') {
        Some((_, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => a.to_string(),
        _ => format!("{a}:443"),
    }
}

/// Blocking TCP-connect reachability probe with a short timeout. A successful
/// connect proves a network path exists; failure/timeout means unreachable
/// (which is what a truly air-gapped target should show).
fn probe_addr(addr: &str) -> ProbeState {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let target = normalize_probe_addr(addr);
    let resolved = match target.to_socket_addrs() {
        Ok(mut it) => it.next(),
        Err(e) => {
            return ProbeState {
                reachable: Some(false),
                detail: format!("unreachable (resolve failed: {e})"),
            }
        }
    };
    let Some(sa) = resolved else {
        return ProbeState { reachable: Some(false), detail: "unreachable (no address)".to_string() };
    };
    match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
        Ok(_) => ProbeState { reachable: Some(true), detail: format!("reachable - TCP connect to {sa}") },
        Err(e) => ProbeState { reachable: Some(false), detail: format!("unreachable ({e})") },
    }
}

/// Render a reachability-probe result chip. Reachable + air-gapped is a
/// contradiction and shown in red.
fn probe_badge(ui: &mut egui::Ui, state: Option<&ProbeState>, air_gapped: bool) {
    let Some(ps) = state else { return };
    let (col, txt) = match ps.reachable {
        None => (theme::MUTED, "probing..."),
        Some(true) if air_gapped => (theme::CRIT, "(!) reachable"),
        Some(true) => (theme::LOW, "reachable"),
        Some(false) => (theme::GOOD, "unreachable"),
    };
    ui.colored_label(col, egui::RichText::new(txt).small())
        .on_hover_text(&ps.detail);
}

/// Map an attack-graph node id (e.g. `asset:prod-api-edge`, `host:h1`,
/// `service:h1:5432`, `dependency:sha3`) to the store record it represents, so
/// clicking it opens the full detail panel. Returns None for nodes with no
/// backing row (provider / data / agent / identity).
fn node_to_selection(id: &str, data: &Snapshot) -> Option<Selection> {
    if let Some(aid) = id.strip_prefix("asset:") {
        if data.assets.iter().any(|a| a.id == aid) {
            return Some(Selection::Asset(aid.to_string()));
        }
    }
    if let Some(hid) = id.strip_prefix("host:") {
        if data.targets.iter().any(|t| t.id == hid) {
            return Some(Selection::Host(hid.to_string()));
        }
    }
    if let Some(rest) = id.strip_prefix("service:") {
        // service:{target_id}:{port} -> its host
        if let Some((tid, _port)) = rest.rsplit_once(':') {
            if data.targets.iter().any(|t| t.id == tid) {
                return Some(Selection::Host(tid.to_string()));
            }
        }
    }
    if let Some(lib) = id.strip_prefix("dependency:") {
        if let Some(f) = data.findings.iter().find(|f| f.title.contains(lib)) {
            return Some(Selection::Finding(f.id.clone()));
        }
    }
    None
}

/// A clickable "link" table cell (accent color + hand cursor). Returns clicked.
fn link_cell(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add(egui::Label::new(egui::RichText::new(text).color(theme::ACCENT)).sense(egui::Sense::click()))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("click for details")
        .clicked()
}

/// Resolve a finding's (usually relative) location against the scanned root, so
/// ".\Cargo.toml" scanned from "H:\repo" reads as "H:\repo\Cargo.toml".
fn resolve_path(root: &str, location: &str) -> String {
    let loc = location.trim_start_matches("./").trim_start_matches(".\\");
    let root = root.trim();
    if root.is_empty() || root == "." || root == "./" || root == ".\\" {
        location.to_string()
    } else if loc.contains(':') || loc.starts_with('/') || loc.starts_with('\\') {
        // Already absolute — leave it.
        location.to_string()
    } else {
        // Normalize the relative part's separators so the joined path the user
        // copies is consistent (no `C:\repo\src/file.rs` mixed-slash output).
        let loc = loc.replace('/', "\\");
        format!("{}\\{}", root.trim_end_matches(['/', '\\']), loc)
    }
}

/// One "Key   value" row in a detail grid.
fn kv(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.label(egui::RichText::new(key).color(theme::MUTED));
    ui.label(value);
    ui.end_row();
}

/// A monospace value that copies itself to the clipboard when clicked — for
/// paths, hashes and fingerprints the user will want to paste elsewhere.
fn copy_value(ui: &mut egui::Ui, value: &str) {
    let resp = ui
        .add(
            egui::Label::new(
                egui::RichText::new(value).monospace().small().color(theme::ACCENT),
            )
            .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("click to copy");
    if resp.clicked() {
        ui.output_mut(|o| o.copied_text = value.to_string());
    }
}

fn has_tag(tags: &[String], tag: &str) -> bool {
    tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
}

/// Add `tag` if absent, remove it if present. Returns the new state (true = on).
fn toggle_tag(tags: &mut Vec<String>, tag: &str) -> bool {
    if let Some(pos) = tags.iter().position(|t| t.eq_ignore_ascii_case(tag)) {
        tags.remove(pos);
        false
    } else {
        tags.push(tag.to_string());
        true
    }
}

fn non_empty(s: &str, default: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        default.to_string()
    } else {
        t.to_string()
    }
}

fn fw_status(s: &frameworks::Status) -> (egui::Color32, &'static str) {
    match s {
        frameworks::Status::Enforced => (theme::GOOD, "ENFORCED"),
        frameworks::Status::Partial => (theme::MED, "PARTIAL"),
        frameworks::Status::Configurable => (theme::LOW, "CONFIG"),
        frameworks::Status::Manual => (theme::MUTED, "MANUAL"),
    }
}

fn soc2_status(s: &soc2::ControlStatus) -> (egui::Color32, &'static str) {
    match s {
        soc2::ControlStatus::Enforced => (theme::GOOD, "ENFORCED"),
        soc2::ControlStatus::Partial => (theme::MED, "PARTIAL"),
        soc2::ControlStatus::Configurable => (theme::LOW, "CONFIGURABLE"),
        soc2::ControlStatus::Manual => (theme::MUTED, "MANUAL"),
    }
}

fn fmt_dt(dt: DateTime<Utc>) -> String {
    dt.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string()
}
fn fmt_opt_dt(dt: Option<DateTime<Utc>>) -> String {
    dt.map(fmt_dt).unwrap_or_else(|| "-".to_string())
}
fn truncate_str(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(n.saturating_sub(1)).collect::<String>())
    }
}

fn pretty_status(s: &str) -> String {
    s.replace(['_', '-'], " ")
        .split_whitespace()
        .map(|w| match w.to_lowercase().as_str() {
            // Keep security acronyms upper-cased.
            "pqc" | "tls" | "ssh" | "rsa" | "ecc" | "kem" => w.to_uppercase(),
            _ => {
                let mut c = w.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use qw_scanner::types::{Confidence, CryptoAssetType, FindingCategory, FindingStatus};

    #[test]
    fn resolve_path_joins_relative_under_scanned_root() {
        assert_eq!(
            resolve_path("C:\\repos\\app", ".\\src\\tls.rs"),
            "C:\\repos\\app\\src\\tls.rs"
        );
        assert_eq!(
            resolve_path("C:\\repos\\app\\", "src/tls.rs"),
            "C:\\repos\\app\\src\\tls.rs"
        );
    }

    #[test]
    fn resolve_path_leaves_absolute_and_empty_root_alone() {
        // An already-absolute finding location is returned unchanged.
        assert_eq!(resolve_path("C:\\repos\\app", "D:\\other\\x.rs"), "D:\\other\\x.rs");
        assert_eq!(resolve_path("C:\\repos\\app", "/etc/ssl/openssl.cnf"), "/etc/ssl/openssl.cnf");
        // No meaningful root -> hand back the location as-is.
        assert_eq!(resolve_path(".", "src/tls.rs"), "src/tls.rs");
        assert_eq!(resolve_path("", "src/tls.rs"), "src/tls.rs");
    }

    fn finding(alg: &str, kind: CryptoAssetType, pqc: PqcStatus, loc: &str) -> FindingRecord {
        FindingRecord {
            id: format!("{alg}-{loc}"),
            scan_id: "s".into(),
            category: FindingCategory::WeakAlgorithm,
            severity: FindingSeverity::Medium,
            title: alg.into(),
            description: String::new(),
            asset_type: kind,
            algorithm: Some(alg.into()),
            pqc_status: pqc,
            location: loc.into(),
            remediation: None,
            created_at: Utc::now(),
            confidence: Confidence::default(),
            evidence: Vec::new(),
            status: FindingStatus::default(),
            note: None,
        }
    }

    #[test]
    fn cbom_dedups_by_algorithm_and_keeps_worst_pqc() {
        let findings = vec![
            finding("RSA-2048", CryptoAssetType::Certificate, PqcStatus::ClassicalSecure, "a.crt"),
            finding("RSA-2048", CryptoAssetType::TlsConnection, PqcStatus::ClassicalWeak, "b.pem"),
            finding("ML-KEM-768", CryptoAssetType::CryptoLibrary, PqcStatus::PqcReady, "kem.rs"),
        ];
        let entries = cbom_entries(&findings);
        assert_eq!(entries.len(), 2, "two distinct algorithms");

        let rsa = entries.iter().find(|e| e.algorithm == "RSA-2048").unwrap();
        assert_eq!(rsa.count, 2, "both RSA findings collapse into one entry");
        // Worst posture across the two uses wins, and it is quantum-vulnerable.
        assert_eq!(rsa.worst_pqc, PqcStatus::ClassicalWeak);
        assert!(rsa.quantum_vulnerable);
        assert!(rsa.kinds.contains("Certificate") && rsa.kinds.contains("TlsConnection"));

        let kem = entries.iter().find(|e| e.algorithm == "ML-KEM-768").unwrap();
        assert!(!kem.quantum_vulnerable, "PQC-ready algorithm is not quantum-vulnerable");
    }

    #[test]
    fn cbom_skips_findings_without_an_algorithm() {
        let mut f = finding("", CryptoAssetType::DataStore, PqcStatus::ClassicalWeak, "x");
        f.algorithm = None;
        assert!(cbom_entries(&[f]).is_empty());
    }
}
