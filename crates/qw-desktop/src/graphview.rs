//! Layered renderer for the **shared** attack-path engine (`qw-graph`). The
//! desktop assembles a `GraphInputs` snapshot from the local store and runs the
//! exact same engine the gateway uses, then lays the resulting nodes out in
//! left→right tiers (Identities · Data · Agents · Providers · Assets & Hosts)
//! and lists the exploitability-ranked attack paths. No gateway, no network.

use std::collections::HashMap;

use eframe::egui::{self, Color32, Pos2, Sense, Stroke, Vec2};

use qw_graph::{build_graph, AgentInput, GraphInputs};
use qw_scanner::types::FindingRecord;
use qw_store::{AssetRow, FlowRow, TargetRow};

use crate::theme;

const COL_HEADERS: [&str; 5] = ["Identities", "Data", "Agents", "Providers", "Assets & Hosts"];
const COL_GAP: f32 = 230.0;
const ROW_GAP: f32 = 34.0;

fn col_x(col: i32) -> f32 {
    (col as f32 - 2.0) * COL_GAP
}

fn col_for(kind: &str) -> i32 {
    match kind {
        "identity" => 0,
        "data" => 1,
        "agent" => 2,
        "provider" => 3,
        _ => 4, // certificate | dependency | asset | host | service | container
    }
}

fn node_color(kind: &str, pqc: &str, risk: f64) -> Color32 {
    match pqc {
        "pqc_ready" => theme::GOOD,
        "hybrid" => theme::LOW,
        "classical_secure" => theme::MED,
        "classical_weak" => theme::CRIT,
        "unknown" => theme::MUTED,
        _ => match kind {
            "identity" => theme::LOW,
            "data" => theme::MED,
            "agent" => theme::ACCENT,
            "container" => theme::MUTED,
            _ if risk >= 60.0 => theme::HIGH,
            _ => theme::ACCENT,
        },
    }
}

fn sev_color(sev: &str) -> Color32 {
    match sev {
        "critical" => theme::CRIT,
        "high" => theme::HIGH,
        "medium" => theme::MED,
        "low" => theme::LOW,
        _ => theme::MUTED,
    }
}

struct LNode {
    label: String,
    detail: String,
    color: Color32,
    col: i32,
    radius: f32,
    pos: Pos2,
    vy: f32,
}

/// A row in the "toxic combinations" list.
pub struct PathRow {
    pub title: String,
    pub severity: String,
    pub score: f64,
    pub hndl: bool,
    pub observed: bool,
    pub recommendation: String,
}

pub struct GraphView {
    nodes: Vec<LNode>,
    edges: Vec<(usize, usize)>,
    paths: Vec<PathRow>,
    pan: Vec2,
    zoom: f32,
    selected: Option<usize>,
    signature: u64,
}

impl Default for GraphView {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            paths: Vec::new(),
            pan: Vec2::ZERO,
            zoom: 1.0,
            selected: None,
            signature: u64::MAX,
        }
    }
}

impl GraphView {
    pub fn sync(
        &mut self,
        flows: &[FlowRow],
        targets: &[TargetRow],
        findings: &[FindingRecord],
        assets: &[AssetRow],
    ) {
        let sig = (flows.len() as u64).wrapping_mul(1000003)
            ^ (targets.len() as u64).wrapping_mul(31)
            ^ (findings.len() as u64).wrapping_mul(7)
            ^ (assets.len() as u64);
        if sig == self.signature && !self.nodes.is_empty() {
            return;
        }
        self.signature = sig;
        self.selected = None;
        self.build(flows, targets, findings, assets);
    }

    fn build(
        &mut self,
        flows: &[FlowRow],
        targets: &[TargetRow],
        findings: &[FindingRecord],
        assets: &[AssetRow],
    ) {
        // The desktop has no live config, so synthesize agents from observed
        // flows; providers/identities come through the flows and store data.
        let mut seen_agents = std::collections::BTreeSet::new();
        let agents: Vec<AgentInput> = flows
            .iter()
            .filter(|f| seen_agents.insert(f.agent.clone()))
            .map(|f| AgentInput {
                name: f.agent.clone(),
                offline: false,
                allowed_tools: Vec::new(),
                allowed_models: Vec::new(),
            })
            .collect();

        let inputs = GraphInputs {
            providers: Vec::new(),
            identities: Vec::new(),
            agents,
            flows,
            findings,
            assets,
            targets,
        };
        let g = build_graph(&inputs, &HashMap::new());

        // Convert engine nodes → laid-out nodes.
        let mut idx: HashMap<String, usize> = HashMap::new();
        let mut nodes: Vec<LNode> = Vec::new();
        for n in &g.nodes {
            idx.insert(n.id.clone(), nodes.len());
            let radius = 6.0 + (n.risk as f32 / 20.0).min(6.0) + (n.blast_radius as f32).sqrt().min(4.0);
            // Multi-line, readable detail for the node panel.
            let mut detail = format!("Type:  {}\n{}", n.kind, n.sublabel);
            if n.pqc_status != "n/a" {
                detail.push_str(&format!("\nPQC status:  {}", n.pqc_status));
            }
            if n.risk > 0.0 {
                detail.push_str(&format!("\nRisk:  {:.0} / 100", n.risk));
            }
            if n.blast_radius > 0.0 {
                detail.push_str(&format!("\nBlast radius:  {:.0}", n.blast_radius));
            }
            if n.observed {
                detail.push_str("\nObserved in live traffic");
            }
            nodes.push(LNode {
                label: n.label.clone(),
                detail,
                color: node_color(&n.kind, &n.pqc_status, n.risk),
                col: col_for(&n.kind),
                radius,
                pos: Pos2::new(col_x(col_for(&n.kind)), 0.0),
                vy: 0.0,
            });
        }
        let edges: Vec<(usize, usize)> = g
            .edges
            .iter()
            .filter_map(|e| Some((*idx.get(&e.source)?, *idx.get(&e.target)?)))
            .collect();

        // Attack paths (already score-ranked by the engine).
        self.paths = g
            .paths
            .iter()
            .map(|p| PathRow {
                title: p.title.clone(),
                severity: p.severity.clone(),
                score: p.score,
                hndl: p.hndl,
                observed: p.observed,
                recommendation: p.recommendation.clone(),
            })
            .collect();

        // Initial vertical spread per column.
        let mut per_col: std::collections::BTreeMap<i32, Vec<usize>> = Default::default();
        for (i, n) in nodes.iter().enumerate() {
            per_col.entry(n.col).or_default().push(i);
        }
        for ids in per_col.values() {
            let m = ids.len();
            for (k, &i) in ids.iter().enumerate() {
                nodes[i].pos.y = (k as f32 - (m as f32 - 1.0) / 2.0) * ROW_GAP;
            }
        }

        self.nodes = nodes;
        self.edges = edges;
    }

    fn step(&mut self) {
        let n = self.nodes.len();
        if n == 0 {
            return;
        }
        let mut fy = vec![0.0f32; n];
        for i in 0..n {
            for j in (i + 1)..n {
                if self.nodes[i].col == self.nodes[j].col {
                    let dy = self.nodes[i].pos.y - self.nodes[j].pos.y;
                    if dy.abs() < ROW_GAP {
                        let push = (ROW_GAP - dy.abs()) * 0.5;
                        let s = if dy >= 0.0 { push } else { -push };
                        fy[i] += s;
                        fy[j] -= s;
                    }
                }
            }
        }
        for &(a, b) in &self.edges {
            let dy = self.nodes[b].pos.y - self.nodes[a].pos.y;
            fy[a] += dy * 0.01;
            fy[b] -= dy * 0.01;
        }
        for i in 0..n {
            fy[i] -= self.nodes[i].pos.y * 0.001;
            self.nodes[i].vy = (self.nodes[i].vy + fy[i]) * 0.80;
            self.nodes[i].pos.y += self.nodes[i].vy * 0.1;
            self.nodes[i].pos.x = col_x(self.nodes[i].col);
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<(String, String)> {
        self.step();
        ui.ctx().request_repaint();

        let size = ui.available_size();
        let (resp, painter) = ui.allocate_painter(size, Sense::click_and_drag());
        let center = resp.rect.center();

        if resp.dragged() {
            self.pan += resp.drag_delta();
        }
        let scroll = ui.input(|i| i.raw_scroll_delta.y);
        if scroll != 0.0 && resp.hovered() {
            self.zoom = (self.zoom * (1.0 + scroll * 0.001)).clamp(0.3, 3.0);
        }

        let to_screen = |p: Pos2| center + self.pan + p.to_vec2() * self.zoom;

        for (c, name) in COL_HEADERS.iter().enumerate() {
            let sx = to_screen(Pos2::new(col_x(c as i32), 0.0)).x;
            painter.text(
                egui::pos2(sx, resp.rect.top() + 4.0),
                egui::Align2::CENTER_TOP,
                *name,
                egui::FontId::proportional(12.0),
                theme::MUTED,
            );
        }

        for &(a, b) in &self.edges {
            painter.line_segment(
                [to_screen(self.nodes[a].pos), to_screen(self.nodes[b].pos)],
                Stroke::new(1.0, Color32::from_gray(70)),
            );
        }

        // Hand cursor when hovering a node (signals it's clickable).
        if let Some(hp) = resp.hover_pos() {
            if self.nodes.iter().any(|n| (to_screen(n.pos) - hp).length() < 16.0) {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
        }
        if resp.clicked() {
            if let Some(p) = resp.interact_pointer_pos() {
                let mut best: Option<(usize, f32)> = None;
                for (i, node) in self.nodes.iter().enumerate() {
                    let d = (to_screen(node.pos) - p).length();
                    if d < 18.0 && best.map(|(_, bd)| d < bd).unwrap_or(true) {
                        best = Some((i, d));
                    }
                }
                self.selected = best.map(|(i, _)| i);
            }
        }

        for (i, node) in self.nodes.iter().enumerate() {
            let c = to_screen(node.pos);
            let r = node.radius * self.zoom.clamp(0.6, 1.6);
            painter.circle_filled(c, r, node.color);
            if Some(i) == self.selected {
                painter.circle_stroke(c, r + 3.0, Stroke::new(2.0, theme::TEXT));
            }
            painter.text(
                c + Vec2::new(r + 6.0, 0.0),
                egui::Align2::LEFT_CENTER,
                truncate(&node.label, 24),
                egui::FontId::proportional(11.0),
                theme::TEXT,
            );
        }

        self.selected
            .map(|i| (self.nodes[i].label.clone(), self.nodes[i].detail.clone()))
    }

    pub fn paths(&self) -> &[PathRow] {
        &self.paths
    }
    pub fn reset_view(&mut self) {
        self.pan = Vec2::ZERO;
        self.zoom = 1.0;
    }
    pub fn deselect(&mut self) {
        self.selected = None;
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.nodes.len(), self.edges.len())
    }
}

/// Color for a path-row severity chip (used by the page's toxic-combos list).
pub fn severity_color(sev: &str) -> Color32 {
    sev_color(sev)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}
