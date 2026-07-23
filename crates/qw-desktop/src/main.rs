//! QuantaWatch Desktop — a native (egui) view onto the local QuantaWatch store.
//!
//! Air-gap posture: this binary links `qw-store`/`qw-scanner`/`qw-cbom` directly
//! and reads the on-disk SQLite store **in-process**. There is no embedded
//! browser, no webview, and no network listener of any kind — nothing is served
//! and nothing is fetched. Point it at a data directory (arg 1, default
//! `./data`) that a gateway or the CLI has populated, or at a fresh one.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use chrono::{DateTime, Local, Utc};
use eframe::egui;

mod graphview;

use std::sync::mpsc::Receiver;

use graphview::GraphView;
use qw_audit::{AuditBackend, AuditEntry, AuditEvent};
use qw_cbom::{frameworks, soc2};
use qw_cbom::{ComplianceEngine, PostureEngine, PostureSnapshot};
use qw_scanner::types::{FindingRecord, FindingSeverity, FindingStatus, PqcStatus, ScanRecord};
use qw_scanner::{build_scanner_registry, ScanTarget, ScannerConfig};
use qw_integrations::RemediationTicket;
use qw_store::{
    AssetRow, CertificateRow, ConnectionRow, DbUser, EndpointRow, FlowRow, OverlayRouteRow,
    SessionRow, Store, TargetRow, DEFAULT_TENANT,
};

const TENANT: &str = DEFAULT_TENANT;

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
    let data_dir = std::env::args().nth(1).unwrap_or_else(|| "./data".to_string());
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
            format!("(no store at {} — {e}; empty view)", db_path.display()),
        ),
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 820.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("QuantaWatch Desktop"),
        ..Default::default()
    };

    eframe::run_native(
        "QuantaWatch Desktop",
        options,
        Box::new(move |cc| {
            install_theme(&cc.egui_ctx);
            Ok(Box::new(App::new(store, source)))
        }),
    )
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
/// tokio runtime to drive the async scanners); reads local files only — no
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
    Compliance,
    Frameworks,
    Soc2,
    Scans,
    Remediations,
    Overlay,
    Connections,
    Agents,
    Sessions,
    Threats,
    Audit,
    Access,
    Settings,
    About,
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
    selected_finding: Option<String>,
    graph: GraphView,
    export_status: String,
    // IDE shell: editor tabs + bottom terminal.
    open_tabs: Vec<Page>,
    terminal_open: bool,
    terminal_float: bool,
    terminal_input: String,
    terminal_lines: Vec<String>,
    asset_form: AssetForm,
    target_form: TargetForm,
    edit_status: String,
    // In-process scanning.
    scan_path: String,
    scanning: bool,
    scan_rx: Option<Receiver<ScanOutcome>>,
    scan_status: String,
}

impl App {
    fn new(store: Store, source: String) -> Self {
        let data = Snapshot::load(&store);
        Self {
            store,
            source,
            page: Page::Overview,
            data,
            filter: String::new(),
            selected_finding: None,
            graph: GraphView::default(),
            export_status: String::new(),
            open_tabs: vec![Page::Overview],
            terminal_open: false,
            terminal_float: false,
            terminal_input: String::new(),
            terminal_lines: vec!["QuantaWatch console — type 'help' for commands.".to_string()],
            asset_form: AssetForm::default(),
            target_form: TargetForm::default(),
            edit_status: String::new(),
            scan_path: ".".to_string(),
            scanning: false,
            scan_rx: None,
            scan_status: String::new(),
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
        self.scan_status = format!("Scanning {path} …");
        let store = self.store.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let outcome = run_scan_blocking(&store, &path);
            let _ = tx.send(outcome);
            ctx.request_repaint(); // wake the UI when the scan finishes
        });
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

    /// Drain a finished scan (if any) and refresh from the store.
    fn poll_scan(&mut self) {
        if let Some(rx) = &self.scan_rx {
            if let Ok(o) = rx.try_recv() {
                self.scanning = false;
                self.scan_rx = None;
                self.scan_status = match o.error {
                    Some(e) => format!("Scan failed: {e}"),
                    None => format!("Scan complete — {} findings, posture {:.0}", o.findings, o.score),
                };
                self.refresh();
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
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
        self.finding_detail_panel(ctx); // right panel; must precede CentralPanel
        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Overview => self.overview(ui),
            Page::AttackPaths => self.attack_paths(ui),
            Page::Estate => self.estate(ui),
            Page::Endpoints => self.endpoints(ui),
            Page::Assets => self.assets(ui),
            Page::Findings => self.findings(ui),
            Page::Certificates => self.certificates(ui),
            Page::Compliance => self.compliance(ui),
            Page::Frameworks => self.frameworks(ui),
            Page::Soc2 => self.soc2(ui),
            Page::Scans => self.scans(ui),
            Page::Remediations => self.remediations(ui),
            Page::Overlay => self.overlay(ui),
            Page::Connections => self.connections(ui),
            Page::Agents => self.agents(ui),
            Page::Sessions => self.sessions(ui),
            Page::Threats => self.threats(ui),
            Page::Audit => self.audit(ui),
            Page::Access => self.access(ui),
            Page::Settings => self.settings(ui),
            Page::About => self.about(ui),
        });
        // While a scan runs, keep the frame loop alive so poll_scan sees the result.
        if self.scanning {
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
                ui.separator();
                // Air-gap badge — this build never opens a socket.
                ui.label(egui::RichText::new("● OFFLINE").color(theme::GOOD).small());
                ui.label(egui::RichText::new("no network · no browser").color(theme::MUTED).small());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⟳ Refresh").clicked() {
                        self.refresh();
                    }
                    if ui.selectable_label(self.terminal_open, "▾ Terminal").on_hover_text("Ctrl+`").clicked() {
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
                    nav_item(ui, &mut self.page, Page::AttackPaths, "🕸  Attack paths", None);
                    nav_item(ui, &mut self.page, Page::Estate, "🖧  Estate", Some(d.targets.len()));
                    nav_item(ui, &mut self.page, Page::Endpoints, "🖥  Endpoints", Some(d.endpoints.len()));
                    nav_item(ui, &mut self.page, Page::Assets, "🧱  Assets", Some(d.assets.len()));
                    nav_item(ui, &mut self.page, Page::Findings, "⚠  Findings", Some(d.findings.len()));
                    nav_item(ui, &mut self.page, Page::Certificates, "🔏  Certificates", Some(d.certs.len()));

                    nav_group(ui, "GOVERNANCE");
                    nav_item(ui, &mut self.page, Page::Compliance, "📋  Compliance", None);
                    nav_item(ui, &mut self.page, Page::Frameworks, "🏛  Frameworks", None);
                    nav_item(ui, &mut self.page, Page::Soc2, "✅  SOC 2", None);

                    nav_group(ui, "OPERATE");
                    nav_item(ui, &mut self.page, Page::Scans, "🔎  Scans", Some(d.scans.len()));
                    nav_item(ui, &mut self.page, Page::Remediations, "🛠  Remediations", Some(d.remediations.len()));
                    nav_item(ui, &mut self.page, Page::Overlay, "🛡  PQC Overlay", Some(d.overlay_routes.len()));
                    nav_item(ui, &mut self.page, Page::Connections, "🔌  Connections", Some(d.connections.len()));

                    nav_group(ui, "MONITOR");
                    nav_item(ui, &mut self.page, Page::Agents, "🤖  Agents", Some(d.flows.len()));
                    nav_item(ui, &mut self.page, Page::Sessions, "🧾  Sessions", Some(d.sessions.len()));
                    nav_item(ui, &mut self.page, Page::Threats, "🚨  Threats", None);
                    nav_item(ui, &mut self.page, Page::Audit, "📜  Audit log", Some(d.audit.len()));

                    nav_group(ui, "ADMIN");
                    nav_item(ui, &mut self.page, Page::Access, "🔑  Access (RBAC)", Some(d.users.len()));
                    nav_item(ui, &mut self.page, Page::Settings, "⚙  Settings", None);
                    nav_item(ui, &mut self.page, Page::About, "ⓘ  About", None);
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
        let mut act: Option<TabAction> = None;
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_space(2.0);
            egui::ScrollArea::horizontal().show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (idx, tab) in tabs.iter().enumerate() {
                        let tab = *tab;
                        let is_active = tab == active;
                        egui::Frame::none()
                            .fill(if is_active { theme::BG } else { theme::PANEL })
                            .inner_margin(egui::Margin::symmetric(9.0, 4.0))
                            .rounding(4.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let col = if is_active { theme::TEXT } else { theme::MUTED };
                                    let resp = ui.add(
                                        egui::Label::new(egui::RichText::new(page_title(tab)).color(col))
                                            .sense(egui::Sense::click()),
                                    );
                                    if resp.clicked() {
                                        act = Some(TabAction::Select(tab));
                                    }
                                    if resp.middle_clicked() {
                                        act = Some(TabAction::Close(tab));
                                    }
                                    resp.context_menu(|ui| {
                                        if ui.button("Close").clicked() {
                                            act = Some(TabAction::Close(tab));
                                            ui.close_menu();
                                        }
                                        if ui.button("Close to the right").clicked() {
                                            act = Some(TabAction::CloseRight(idx));
                                            ui.close_menu();
                                        }
                                        if ui.button("Close others").clicked() {
                                            act = Some(TabAction::CloseOthers(tab));
                                            ui.close_menu();
                                        }
                                        if ui.button("Close all").clicked() {
                                            act = Some(TabAction::CloseAll);
                                            ui.close_menu();
                                        }
                                    });
                                    // A readable close affandance (× renders where ✕ didn't).
                                    if ui
                                        .add(egui::Label::new(egui::RichText::new(" ×").color(theme::MUTED)).sense(egui::Sense::click()))
                                        .on_hover_text("close (or middle-click the tab)")
                                        .clicked()
                                    {
                                        act = Some(TabAction::Close(tab));
                                    }
                                });
                            });
                    }
                });
            });
            ui.add_space(2.0);
        });
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
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("TERMINAL").small().strong().color(theme::MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("✕").on_hover_text("close").clicked() {
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
        ui.separator();
        let mut submit: Option<String> = None;
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .max_height((ui.available_height() - 28.0).max(60.0))
            .show(ui, |ui| {
                for line in &self.terminal_lines {
                    ui.label(
                        egui::RichText::new(line)
                            .monospace()
                            .size(12.0)
                            .color(if line.starts_with('›') { theme::ACCENT } else { theme::TEXT }),
                    );
                }
            });
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("›").monospace().color(theme::ACCENT));
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
        self.terminal_lines.push(format!("› {line}"));
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("").to_lowercase();
        let arg = it.collect::<Vec<_>>().join(" ");
        match cmd.as_str() {
            "clear" => {
                self.terminal_lines.clear();
                return;
            }
            "help" => self.terminal_lines.push(
                "commands: help · clear · posture · findings [n] · estate · assets · certs · threats · paths · scan <dir> · open <page> · refresh · version".to_string(),
            ),
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
                    "{} findings — {} critical · {} high · {} medium · {} low · {} info",
                    self.data.findings.len(), c[4], c[3], c[2], c[1], c[0]
                ));
                let rows: Vec<String> = self.data.findings.iter().take(n)
                    .map(|f| format!("  [{}] {} — {}", sev_label(f.severity), f.title, f.location)).collect();
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
                    .map(|p| format!("[{:.0}] {} — {}", p.score, p.severity.to_uppercase(), p.title)).collect();
                self.terminal_lines.extend(if rows.is_empty() { vec!["(no attack paths)".to_string()] } else { rows });
            }
            "scan" => {
                if arg.is_empty() {
                    self.terminal_lines.push("usage: scan <dir>".to_string());
                } else {
                    self.scan_path = arg.clone();
                    self.terminal_lines.push(format!("scanning {arg} …"));
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
            "version" => self.terminal_lines.push(format!("qw-desktop v{}", env!("CARGO_PKG_VERSION"))),
            other => self.terminal_lines.push(format!("unknown command: {other} (try 'help')")),
        }
        let len = self.terminal_lines.len();
        if len > 500 {
            self.terminal_lines.drain(0..len - 500);
        }
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Posture overview");
        ui.add_space(8.0);

        // In-process scan — reads local files only, no network.
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
                    egui::RichText::new("Local files only — no network. Findings are written to the store.")
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
            empty_state(ui, "Nothing to graph yet — run a scan or register estate hosts.");
            return;
        }

        // Ranked "toxic combinations" on the right; the graph fills the rest.
        egui::SidePanel::right("toxic_combos")
            .default_width(300.0)
            .show_inside(ui, |ui| {
                ui.add_space(4.0);
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
                            });
                        ui.add_space(4.0);
                    }
                });
            });

        let sel = self.graph.ui(ui);
        if let Some((label, detail)) = sel {
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

    fn findings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Findings");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⭳ Export JSON").clicked() {
                    self.export_findings();
                }
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("filter…").desired_width(220.0));
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
                        // Clickable title → open the detail panel.
                        let title = egui::Label::new(egui::RichText::new(&f.title).color(theme::ACCENT))
                            .sense(egui::Sense::click());
                        if ui.add(title).on_hover_text("view details").clicked() {
                            self.selected_finding = Some(f.id.clone());
                        }
                        ui.label(f.algorithm.as_deref().unwrap_or("—"));
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
        egui::CollapsingHeader::new("➕ Register host").show(ui, |ui| {
            let cur = self.target_form.kind.clone();
            egui::ComboBox::from_label("Template")
                .selected_text(if cur.is_empty() { "— choose —".to_string() } else { cur })
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
            ui.checkbox(&mut self.target_form.air_gapped, "Air-gapped (no network path — suppresses HNDL risk)");
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
        {
            let d = &self.data;
            data_table(ui, "estate", &["Name", "Host", "Kind", "Env", "PQC", "Exposure", ""],
                d.targets.len(), "No registered hosts. Register one above.", |ui, i| {
                let t = &d.targets[i];
                ui.label(&t.name).context_menu(|ui| {
                    let air = has_tag(&t.tags, "air-gapped");
                    if ui.button(if air { "Mark exposed" } else { "Mark air-gapped" }).clicked() {
                        toggle = Some(t.id.clone());
                        ui.close_menu();
                    }
                    if ui.button("Scan from Overview").clicked() {
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
                let air = has_tag(&t.tags, "air-gapped");
                let (col, txt) = if air { (theme::GOOD, "🔒 air-gapped") } else { (theme::MUTED, "exposed") };
                if ui.selectable_label(air, egui::RichText::new(txt).color(col).small())
                    .on_hover_text("toggle air-gapped").clicked()
                {
                    toggle = Some(t.id.clone());
                }
                if ui.small_button("✕").on_hover_text("delete").clicked() {
                    del = Some(t.id.clone());
                }
            });
        }
        if let Some(id) = toggle {
            self.toggle_target_airgap(&id);
        }
        if let Some(id) = del {
            self.store.delete_target(TENANT, &id);
            self.edit_status = format!("Deleted host {id}");
            self.refresh();
        }
    }

    fn certificates(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Certificates");
        ui.add_space(6.0);
        if self.data.certs.is_empty() {
            empty_state(ui, "No certificates issued. Use the gateway's internal PQC CA to issue hybrid certs.");
            return;
        }
        let now = Utc::now();
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("certs")
                .striped(true)
                .num_columns(5)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Subject", "Type", "PQC", "Expires", "State"] {
                        ui.label(egui::RichText::new(h).strong().color(theme::MUTED));
                    }
                    ui.end_row();
                    for c in &self.data.certs {
                        ui.label(&c.subject);
                        // hybrid = classical X.509 + ML-DSA binding.
                        let type_col = if c.key_type.contains("hybrid") { theme::GOOD } else { theme::MED };
                        ui.colored_label(type_col, &c.key_type);
                        ui.colored_label(status_str_color(&c.pqc_status), pretty_status(&c.pqc_status));
                        // Expiry, colored by urgency.
                        let days = (c.not_after - now).num_days();
                        let (col, txt) = if c.status == "revoked" {
                            (theme::MUTED, "—".to_string())
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
                        ui.end_row();
                    }
                });
        });
    }

    fn scans(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Scans");
        ui.add_space(6.0);
        if self.data.scans.is_empty() {
            empty_state(ui, "No scans recorded yet. Run one from the Overview page.");
            return;
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("scans")
                .striped(true)
                .num_columns(5)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Scanner", "Target", "Status", "Findings", "Completed"] {
                        ui.label(egui::RichText::new(h).strong().color(theme::MUTED));
                    }
                    ui.end_row();
                    for s in &self.data.scans {
                        ui.label(&s.scanner_id);
                        ui.label(egui::RichText::new(&s.target_address).color(theme::MUTED));
                        ui.label(format!("{:?}", s.status));
                        ui.label(s.finding_count.to_string());
                        ui.label(
                            egui::RichText::new(
                                s.completed_at.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string(),
                            )
                            .color(theme::MUTED),
                        );
                        ui.end_row();
                    }
                });
        });
    }

    /// Right-hand detail panel for the selected finding.
    fn finding_detail_panel(&mut self, ctx: &egui::Context) {
        let Some(id) = self.selected_finding.clone() else {
            return;
        };
        let Some(f) = self.data.findings.iter().find(|f| f.id == id).cloned() else {
            self.selected_finding = None;
            return;
        };
        egui::SidePanel::right("finding_detail")
            .default_width(380.0)
            .min_width(300.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.heading("Finding");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("✕").clicked() {
                            self.selected_finding = None;
                        }
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.colored_label(sev_color(f.severity), sev_label(f.severity));
                    ui.colored_label(pqc_color(f.pqc_status), pqc_label(f.pqc_status));
                    ui.label(egui::RichText::new(format!("{:?}", f.status)).color(theme::MUTED));
                });
                ui.add_space(6.0);
                ui.label(egui::RichText::new(&f.title).strong().size(15.0));
                ui.add_space(8.0);

                egui::Grid::new("fdetail").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("Category").color(theme::MUTED));
                    ui.label(f.category.to_string());
                    ui.end_row();
                    if let Some(a) = &f.algorithm {
                        ui.label(egui::RichText::new("Algorithm").color(theme::MUTED));
                        ui.label(a);
                        ui.end_row();
                    }
                    ui.label(egui::RichText::new("Confidence").color(theme::MUTED));
                    ui.label(format!("{:?}", f.confidence));
                    ui.end_row();
                    ui.label(egui::RichText::new("Location").color(theme::MUTED));
                    ui.label(egui::RichText::new(&f.location).monospace().small());
                    ui.end_row();
                });

                // Triage actions — persisted to the store in-process.
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
                            ui.label(egui::RichText::new(format!("• {e}")).monospace().small());
                        }
                    }
                });
            });
    }

    fn endpoints(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Endpoints");
        ui.add_space(6.0);
        let d = &self.data;
        data_table(ui, "endpoints", &["Hostname", "OS", "Agent", "PQC", "Findings", "Last report"],
            d.endpoints.len(), "No host agents enrolled.", |ui, i| {
            let e = &d.endpoints[i];
            ui.label(&e.hostname);
            ui.label(egui::RichText::new(&e.os).color(theme::MUTED));
            ui.label(e.agent_version.as_deref().unwrap_or("—"));
            ui.colored_label(status_str_color(&e.pqc_status), pretty_status(&e.pqc_status));
            ui.label(e.findings_count.to_string());
            ui.label(egui::RichText::new(fmt_dt(e.last_report)).color(theme::MUTED));
        });
    }

    fn assets(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Assets");
        ui.add_space(6.0);

        let mut add = false;
        egui::CollapsingHeader::new("➕ Add asset").show(ui, |ui| {
            let cur = self.asset_form.kind.clone();
            egui::ComboBox::from_label("Template")
                .selected_text(if cur.is_empty() { "— choose —".to_string() } else { cur })
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
            ui.checkbox(&mut self.asset_form.air_gapped, "Air-gapped (no network path — suppresses HNDL risk)");
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
        {
            let d = &self.data;
            data_table(ui, "assets", &["Asset", "Kind", "Address", "Env", "PQC", "Exposure", ""],
                d.assets.len(), "No declared assets. Add one above.", |ui, i| {
                let a = &d.assets[i];
                ui.label(&a.id).context_menu(|ui| {
                    let air = has_tag(&a.tags, "air-gapped");
                    if ui.button(if air { "Mark exposed" } else { "Mark air-gapped" }).clicked() {
                        toggle = Some(a.id.clone());
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
                // Exposure toggle: air-gapped vs internet-facing.
                let air = has_tag(&a.tags, "air-gapped");
                let (col, txt) = if air { (theme::GOOD, "🔒 air-gapped") } else { (theme::MUTED, "exposed") };
                if ui.selectable_label(air, egui::RichText::new(txt).color(col).small())
                    .on_hover_text("toggle air-gapped").clicked()
                {
                    toggle = Some(a.id.clone());
                }
                if ui.small_button("✕").on_hover_text("delete").clicked() {
                    del = Some(a.id.clone());
                }
            });
        }
        if let Some(id) = toggle {
            self.toggle_asset_airgap(&id);
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
        let d = &self.data;
        data_table(ui, "remediations", &["Ticket", "Integration", "Status", "Finding", "Updated"],
            d.remediations.len(), "No remediation tickets opened.", |ui, i| {
            let r = &d.remediations[i];
            ui.label(&r.external_id);
            ui.label(egui::RichText::new(&r.integration_id).color(theme::MUTED));
            ui.label(format!("{:?}", r.status));
            ui.label(egui::RichText::new(truncate_str(&r.finding_id, 14)).monospace().small());
            ui.label(egui::RichText::new(fmt_dt(r.updated_at)).color(theme::MUTED));
        });
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
        ui.add_space(6.0);
        let d = &self.data;
        data_table(ui, "connections", &["Name", "Type", "Base URL", "Status"],
            d.connections.len(), "No connections. Add one from the gateway dashboard.", |ui, i| {
            let c = &d.connections[i];
            ui.label(&c.display_name);
            ui.label(&c.integration_type);
            ui.label(egui::RichText::new(c.base_url.as_deref().unwrap_or("—")).color(theme::MUTED));
            let (col, s) = match c.last_status.as_deref() {
                Some("connected") => (theme::GOOD, "connected"),
                Some("failed") => (theme::CRIT, "failed"),
                _ => (theme::MUTED, "untested"),
            };
            ui.colored_label(col, s);
        });
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
        let d = &self.data;
        data_table(ui, "sessions", &["Agent", "Provider", "Model", "Requests", "Client IP", "Started"],
            d.sessions.len(), "No sessions recorded.", |ui, i| {
            let s = &d.sessions[i];
            ui.label(&s.agent_name);
            ui.label(&s.provider);
            ui.label(egui::RichText::new(&s.model).color(theme::MUTED));
            ui.label(s.request_count.to_string());
            ui.label(egui::RichText::new(&s.client_ip).monospace().small());
            ui.label(egui::RichText::new(fmt_dt(s.created_at)).color(theme::MUTED));
        });
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
                    ui.label(fw.nearest_deadline.map(|y| y.to_string()).unwrap_or_else(|| "—".to_string()));
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
        ui.label(egui::RichText::new("Shared qw-cbom control set (CNSA 2.0, NIST 800-53, PCI-DSS, FedRAMP). Evaluated from local signals — the gateway's live config is authoritative.").color(theme::MUTED).small());
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
        ui.label(egui::RichText::new("Shared qw-cbom control set. Evaluated from local store signals — the gateway's live config is authoritative.").color(theme::MUTED).small());
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
        ui.label(egui::RichText::new("Security events surfaced from the audit stream — blocked threats, policy & access violations.").color(theme::MUTED).small());
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

    fn audit(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Audit log");
        ui.label(egui::RichText::new("Tamper-evident, ML-DSA-65-signed hash chain — read from the local store.").color(theme::MUTED).small());
        ui.add_space(6.0);
        let d = &self.data;
        data_table(ui, "audit", &["Time", "Writer", "Seq", "Session", "Event"],
            d.audit.len(), "No audit entries yet.", |ui, i| {
            let e = &d.audit[i];
            ui.label(egui::RichText::new(fmt_dt(e.timestamp)).color(theme::MUTED));
            ui.label(egui::RichText::new(&e.writer_id).small());
            ui.label(e.sequence.to_string());
            ui.label(egui::RichText::new(truncate_str(&e.session_id, 10)).monospace().small());
            ui.label(egui::RichText::new(truncate_str(&format!("{:?}", e.event), 72)).small());
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
        ui.label(egui::RichText::new("Data").strong());
        if ui.button("⟳ Refresh from store").clicked() {
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
                    let mut go = |ui: &mut egui::Ui, icon: &str, tip: &str, p: Page, page: &mut Page| {
                        if ui.selectable_label(*page == p, egui::RichText::new(icon).size(18.0)).on_hover_text(tip).clicked() {
                            *page = p;
                        }
                        ui.add_space(2.0);
                    };
                    go(ui, "🏠", "Overview", Page::Overview, &mut self.page);
                    go(ui, "🕸", "Attack paths", Page::AttackPaths, &mut self.page);
                    go(ui, "⚠", "Findings", Page::Findings, &mut self.page);
                    go(ui, "🖧", "Estate", Page::Estate, &mut self.page);
                    go(ui, "📜", "Audit log", Page::Audit, &mut self.page);
                    ui.add_space(6.0);
                    if ui.selectable_label(self.terminal_open, egui::RichText::new("▾").size(18.0)).on_hover_text("Terminal (Ctrl+`)").clicked() {
                        self.terminal_open = !self.terminal_open;
                    }
                });
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    if ui.selectable_label(self.page == Page::Settings, egui::RichText::new("⚙").size(18.0)).on_hover_text("Settings").clicked() {
                        self.page = Page::Settings;
                    }
                });
            });
    }

    fn about(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("About");
        ui.add_space(8.0);
        ui.label("QuantaWatch Desktop — a native, offline view of your post-quantum posture.");
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Air-gap posture").strong());
        ui.label("• No embedded browser or webview — this is a native egui window.");
        ui.label("• No network listener and no outbound calls — it reads the local store in-process.");
        ui.label("• Links the same qw-store / qw-scanner / qw-cbom crates the gateway uses.");
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Store path").strong());
        ui.label(egui::RichText::new(&self.source).monospace().color(theme::MUTED));
        ui.add_space(8.0);
        ui.label(egui::RichText::new(format!("qw-desktop v{}", env!("CARGO_PKG_VERSION"))).color(theme::MUTED));
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
        Page::Compliance => "Compliance",
        Page::Frameworks => "Frameworks",
        Page::Soc2 => "SOC 2",
        Page::Scans => "Scans",
        Page::Remediations => "Remediations",
        Page::Overlay => "PQC Overlay",
        Page::Connections => "Connections",
        Page::Agents => "Agents",
        Page::Sessions => "Sessions",
        Page::Threats => "Threats",
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
        Page::Findings, Page::Certificates, Page::Compliance, Page::Frameworks, Page::Soc2,
        Page::Scans, Page::Remediations, Page::Overlay, Page::Connections, Page::Agents,
        Page::Sessions, Page::Threats, Page::Audit, Page::Access, Page::Settings, Page::About,
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
fn status_str_color(s: &str) -> egui::Color32 {
    match s.to_lowercase().replace(['_', '-'], "").as_str() {
        x if x.contains("weak") || x.contains("vulnerable") => theme::CRIT,
        x if x.contains("hybrid") => theme::LOW,
        x if x.contains("ready") || x.contains("pqc") => theme::GOOD,
        _ => theme::MUTED,
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
    dt.map(fmt_dt).unwrap_or_else(|| "—".to_string())
}
fn truncate_str(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
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
