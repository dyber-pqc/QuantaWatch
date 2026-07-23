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
use qw_cbom::{PostureEngine, PostureSnapshot};
use qw_scanner::types::{FindingRecord, FindingSeverity, FindingStatus, PqcStatus, ScanRecord};
use qw_scanner::{build_scanner_registry, ScanTarget, ScannerConfig};
use qw_store::{CertificateRow, FlowRow, Store, TargetRow, DEFAULT_TENANT};

const TENANT: &str = DEFAULT_TENANT;

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
    Findings,
    Estate,
    Certificates,
    Scans,
    About,
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
        self.top_bar(ctx);
        self.side_nav(ctx);
        self.finding_detail_panel(ctx); // right panel; must precede CentralPanel
        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Overview => self.overview(ui),
            Page::AttackPaths => self.attack_paths(ui),
            Page::Findings => self.findings(ui),
            Page::Estate => self.estate(ui),
            Page::Certificates => self.certificates(ui),
            Page::Scans => self.scans(ui),
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
            .exact_width(190.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                let n = self.data.findings.len();
                let t = self.data.targets.len();
                let c = self.data.certs.len();
                nav_item(ui, &mut self.page, Page::Overview, "📊  Overview", None);
                nav_item(ui, &mut self.page, Page::AttackPaths, "🕸  Attack paths", None);
                nav_item(ui, &mut self.page, Page::Findings, "⚠  Findings", Some(n));
                nav_item(ui, &mut self.page, Page::Estate, "🖧  Estate", Some(t));
                nav_item(ui, &mut self.page, Page::Certificates, "🔏  Certificates", Some(c));
                nav_item(ui, &mut self.page, Page::Scans, "🔎  Scans", Some(self.data.scans.len()));
                ui.add_space(8.0);
                ui.separator();
                nav_item(ui, &mut self.page, Page::About, "ⓘ  About", None);

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(&self.source).color(theme::MUTED).small());
                    ui.label(egui::RichText::new("store").color(theme::MUTED).small());
                });
            });
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
        self.graph
            .sync(&self.data.flows, &self.data.targets, &self.data.findings);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Attack paths");
            let (n, e) = self.graph.counts();
            ui.label(
                egui::RichText::new(format!("{n} nodes · {e} edges"))
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
                "Drag to pan · scroll to zoom · click a node. Built in-process from flows, estate & findings.",
            )
            .color(theme::MUTED)
            .small(),
        );
        ui.add_space(4.0);
        if self.graph.counts().0 == 0 {
            empty_state(ui, "Nothing to graph yet — run a scan or register estate hosts.");
            return;
        }
        let sel = self.graph.ui(ui);
        if let Some((label, detail)) = sel {
            egui::Area::new(egui::Id::new("graph_sel"))
                .anchor(egui::Align2::LEFT_BOTTOM, egui::vec2(16.0, -16.0))
                .show(ui.ctx(), |ui| {
                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                        ui.set_max_width(320.0);
                        ui.label(egui::RichText::new(label).strong());
                        ui.label(egui::RichText::new(detail).small().color(theme::MUTED));
                    });
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
        if self.data.targets.is_empty() {
            empty_state(ui, "No registered hosts. Register targets via the gateway's Estate page.");
            return;
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("estate")
                .striped(true)
                .num_columns(6)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Name", "Host", "Kind", "Env", "PQC", "Services"] {
                        ui.label(egui::RichText::new(h).strong().color(theme::MUTED));
                    }
                    ui.end_row();
                    for t in &self.data.targets {
                        ui.label(&t.name);
                        ui.label(egui::RichText::new(&t.host).color(theme::MUTED));
                        ui.label(&t.kind);
                        ui.label(&t.environment);
                        ui.colored_label(status_str_color(&t.pqc_status), pretty_status(&t.pqc_status));
                        ui.label(t.exposed_services.len().to_string());
                        ui.end_row();
                    }
                });
        });
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
