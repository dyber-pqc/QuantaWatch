//! A self-contained **layered** attack-path graph, built from local store data
//! (agent→provider flows, estate hosts + services, and findings aggregated by
//! category) and rendered with an egui `Painter`. Nodes are pinned to columns
//! (left→right tiers) like the web dashboard's crypto security graph; only their
//! vertical position relaxes, so the layout reads as tiers, not an explosion.
//! No gateway, no network — computed and laid out in-process.

use std::collections::BTreeMap;

use eframe::egui::{self, Color32, Pos2, Sense, Stroke, Vec2};

use qw_scanner::types::{FindingRecord, FindingSeverity};
use qw_store::{FlowRow, TargetRow};

use crate::theme;

/// Column tiers, left → right.
const COL_AGENT: i32 = 0;
const COL_PROVIDER: i32 = 1;
const COL_HOST: i32 = 2;
const COL_SERVICE: i32 = 3;
const COL_EXPOSURE: i32 = 4;
const COL_HEADERS: [&str; 5] = ["Agents", "Providers", "Hosts", "Services", "Exposures"];
const COL_GAP: f32 = 220.0;
const ROW_GAP: f32 = 34.0;

fn col_x(col: i32) -> f32 {
    (col as f32 - 2.0) * COL_GAP // center the middle column at x = 0
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Agent,
    Provider,
    Host,
    Service,
    Exposure,
}

struct GNode {
    label: String,
    detail: String,
    color: Color32,
    kind: Kind,
    col: i32,
    radius: f32,
    pos: Pos2,
    vy: f32,
}

pub struct GraphView {
    nodes: Vec<GNode>,
    edges: Vec<(usize, usize)>,
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
            pan: Vec2::ZERO,
            zoom: 1.0,
            selected: None,
            signature: u64::MAX,
        }
    }
}

fn sev_rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Info => 0,
        FindingSeverity::Low => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::High => 3,
        FindingSeverity::Critical => 4,
    }
}
fn sev_color(s: FindingSeverity) -> Color32 {
    match s {
        FindingSeverity::Critical => theme::CRIT,
        FindingSeverity::High => theme::HIGH,
        FindingSeverity::Medium => theme::MED,
        FindingSeverity::Low => theme::LOW,
        FindingSeverity::Info => theme::MUTED,
    }
}
fn status_color(s: &str) -> Color32 {
    match s.to_lowercase().replace(['_', '-'], "").as_str() {
        x if x.contains("weak") || x.contains("vulnerable") => theme::CRIT,
        x if x.contains("hybrid") => theme::LOW,
        x if x.contains("ready") || x.contains("pqc") => theme::GOOD,
        _ => theme::MUTED,
    }
}

impl GraphView {
    pub fn sync(&mut self, flows: &[FlowRow], targets: &[TargetRow], findings: &[FindingRecord]) {
        let sig = (flows.len() as u64).wrapping_mul(1000003)
            ^ (targets.len() as u64).wrapping_mul(31)
            ^ (findings.len() as u64);
        if sig == self.signature && !self.nodes.is_empty() {
            return;
        }
        self.signature = sig;
        self.selected = None;
        self.build(flows, targets, findings);
    }

    fn build(&mut self, flows: &[FlowRow], targets: &[TargetRow], findings: &[FindingRecord]) {
        let mut nodes: Vec<GNode> = Vec::new();
        let mut edges: Vec<(usize, usize)> = Vec::new();
        let mut index: BTreeMap<String, usize> = BTreeMap::new();

        let mut add = |nodes: &mut Vec<GNode>,
                       index: &mut BTreeMap<String, usize>,
                       key: String,
                       label: String,
                       detail: String,
                       color: Color32,
                       kind: Kind,
                       col: i32,
                       radius: f32|
         -> usize {
            if let Some(&i) = index.get(&key) {
                return i;
            }
            let i = nodes.len();
            nodes.push(GNode {
                label,
                detail,
                color,
                kind,
                col,
                radius,
                pos: Pos2::new(col_x(col), 0.0),
                vy: 0.0,
            });
            index.insert(key, i);
            i
        };

        // Agents → providers (flows).
        for f in flows {
            let a = add(&mut nodes, &mut index, format!("agent:{}", f.agent), f.agent.clone(),
                format!("Agent · {} requests", f.requests), theme::LOW, Kind::Agent, COL_AGENT, 8.0);
            let threat = f.threats > 0 || f.sensitive > 0;
            let p = add(&mut nodes, &mut index, format!("prov:{}", f.provider), f.provider.clone(),
                format!("Provider · {} req · {} sensitive · {} threats", f.requests, f.sensitive, f.threats),
                if threat { theme::HIGH } else { theme::ACCENT }, Kind::Provider, COL_PROVIDER, 9.0);
            edges.push((a, p));
        }

        // Hosts → their non-PQC-ready services.
        let mut host_ids: Vec<usize> = Vec::new();
        for t in targets {
            let h = add(&mut nodes, &mut index, format!("host:{}", t.id), t.name.clone(),
                format!("{} · {} · {}", t.host, t.kind, t.environment),
                status_color(&t.pqc_status), Kind::Host, COL_HOST, 9.0);
            host_ids.push(h);
            for s in &t.exposed_services {
                if status_color(&s.pqc_status) == theme::GOOD {
                    continue; // surface exposure, not already-safe services
                }
                let sv = add(&mut nodes, &mut index, format!("svc:{}:{}", t.id, s.port),
                    format!("{}:{}", s.service, s.port),
                    format!("{} on port {} — {}", s.service, s.port, s.detail),
                    status_color(&s.pqc_status), Kind::Service, COL_SERVICE, 6.0);
                edges.push((h, sv));
            }
        }

        // Findings aggregated by category — one node per category (count + worst
        // severity), so hundreds of duplicates collapse into a readable column.
        let mut cats: BTreeMap<String, (usize, FindingSeverity)> = BTreeMap::new();
        for f in findings {
            let e = cats.entry(f.category.to_string()).or_insert((0, FindingSeverity::Info));
            e.0 += 1;
            if sev_rank(f.severity) > sev_rank(e.1) {
                e.1 = f.severity;
            }
        }
        for (cat, (count, worst)) in cats {
            let r = 6.0 + (count as f32).sqrt().min(8.0);
            let ex = add(&mut nodes, &mut index, format!("cat:{cat}"),
                format!("{} ×{count}", pretty(&cat)),
                format!("{count} findings · worst {:?}", worst),
                sev_color(worst), Kind::Exposure, COL_EXPOSURE, r);
            // Link the exposure to the estate it threatens (first host), else leave
            // it in its column. One edge each — no hub explosion.
            if let Some(&h) = host_ids.first() {
                edges.push((h, ex));
            }
        }

        // Initial vertical spread per column so relaxation starts untangled.
        let mut per_col: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
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

    /// Relax vertical positions only (x stays pinned to the column): same-column
    /// spacing + a barycenter pull along edges + gentle centering.
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
            fy[i] -= self.nodes[i].pos.y * 0.001; // centering
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

        // Column headers, pinned to the top of the viewport.
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

        // Edges under nodes.
        for &(a, b) in &self.edges {
            painter.line_segment(
                [to_screen(self.nodes[a].pos), to_screen(self.nodes[b].pos)],
                Stroke::new(1.0, Color32::from_gray(70)),
            );
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
                truncate(&node.label, 26),
                egui::FontId::proportional(11.0),
                theme::TEXT,
            );
        }

        self.selected
            .map(|i| (self.nodes[i].label.clone(), self.nodes[i].detail.clone()))
    }

    pub fn reset_view(&mut self) {
        self.pan = Vec2::ZERO;
        self.zoom = 1.0;
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.nodes.len(), self.edges.len())
    }
}

fn pretty(s: &str) -> String {
    s.replace(['_', '-'], " ")
        .split_whitespace()
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}
