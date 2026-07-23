//! A self-contained force-directed attack-path graph, built from local store
//! data (agent→provider flows, estate hosts + services, and top findings) and
//! rendered with an egui `Painter`. No gateway, no network — the desktop
//! computes and lays out the graph in-process.

use eframe::egui::{self, Color32, Pos2, Sense, Stroke, Vec2};

use qw_scanner::types::{FindingRecord, FindingSeverity};
use qw_store::{FlowRow, TargetRow};

use crate::theme;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Root,
    Agent,
    Provider,
    Host,
    Service,
    Finding,
}

struct GNode {
    label: String,
    detail: String,
    color: Color32,
    kind: Kind,
    pos: Pos2,
    vel: Vec2,
}

pub struct GraphView {
    nodes: Vec<GNode>,
    edges: Vec<(usize, usize)>,
    pan: Vec2,
    zoom: f32,
    selected: Option<usize>,
    /// Cheap signature of the data the graph was built from, to rebuild on change.
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

/// Golden-angle spiral seeds a spread-out initial layout deterministically
/// (no RNG needed), which the physics then relaxes.
fn seed_pos(i: usize) -> Pos2 {
    let a = i as f32 * 2.399_963_2; // golden angle
    let r = 24.0 + 10.0 * (i as f32).sqrt();
    Pos2::new(r * a.cos(), r * a.sin())
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
    /// (Re)build the graph if the underlying data changed.
    pub fn sync(&mut self, flows: &[FlowRow], targets: &[TargetRow], findings: &[FindingRecord]) {
        let sig = (flows.len() as u64)
            .wrapping_mul(1000003)
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
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        let mut add = |nodes: &mut Vec<GNode>,
                       index: &mut std::collections::HashMap<String, usize>,
                       key: String,
                       label: String,
                       detail: String,
                       color: Color32,
                       kind: Kind|
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
                pos: seed_pos(i),
                vel: Vec2::ZERO,
            });
            index.insert(key, i);
            i
        };

        let root = add(
            &mut nodes,
            &mut index,
            "__root".into(),
            "Estate".into(),
            "Root of the crypto attack surface".into(),
            theme::ACCENT,
            Kind::Root,
        );

        // Agent → provider flows.
        for f in flows {
            let a = add(
                &mut nodes,
                &mut index,
                format!("agent:{}", f.agent),
                f.agent.clone(),
                format!("Agent · {} requests", f.requests),
                theme::LOW,
                Kind::Agent,
            );
            let threat = f.threats > 0 || f.sensitive > 0;
            let p = add(
                &mut nodes,
                &mut index,
                format!("prov:{}", f.provider),
                f.provider.clone(),
                format!(
                    "Provider · {} req · {} sensitive · {} threats",
                    f.requests, f.sensitive, f.threats
                ),
                if threat { theme::HIGH } else { theme::ACCENT },
                Kind::Provider,
            );
            edges.push((a, p));
            edges.push((p, root));
        }

        // Estate hosts + their non-PQC-ready services.
        for t in targets {
            let h = add(
                &mut nodes,
                &mut index,
                format!("host:{}", t.id),
                t.name.clone(),
                format!("{} · {} · {}", t.host, t.kind, t.environment),
                status_color(&t.pqc_status),
                Kind::Host,
            );
            edges.push((h, root));
            for s in &t.exposed_services {
                let ready = status_color(&s.pqc_status) == theme::GOOD;
                if ready {
                    continue; // only surface exposure, not already-safe services
                }
                let sv = add(
                    &mut nodes,
                    &mut index,
                    format!("svc:{}:{}", t.id, s.port),
                    format!("{}:{}", s.service, s.port),
                    format!("{} on port {} — {}", s.service, s.port, s.detail),
                    status_color(&s.pqc_status),
                    Kind::Service,
                );
                edges.push((sv, h));
            }
        }

        // Top findings (worst first, capped), linked to the node their location
        // names, else to the root.
        let mut fs: Vec<&FindingRecord> = findings
            .iter()
            .filter(|f| {
                matches!(f.severity, FindingSeverity::Critical | FindingSeverity::High)
            })
            .collect();
        fs.sort_by(|a, b| sev_rank(b.severity).cmp(&sev_rank(a.severity)));
        for f in fs.into_iter().take(40) {
            let fi = add(
                &mut nodes,
                &mut index,
                format!("find:{}", f.id),
                truncate(&f.title, 28),
                format!(
                    "{:?} · {} · {}",
                    f.severity,
                    f.algorithm.as_deref().unwrap_or("—"),
                    f.location
                ),
                sev_color(f.severity),
                Kind::Finding,
            );
            // Attach to the first node whose label/detail appears in the location.
            let loc = f.location.to_lowercase();
            let parent = nodes
                .iter()
                .position(|n| {
                    n.kind != Kind::Finding
                        && n.kind != Kind::Root
                        && !n.label.is_empty()
                        && loc.contains(&n.label.to_lowercase())
                })
                .unwrap_or(root);
            edges.push((fi, parent));
        }

        self.nodes = nodes;
        self.edges = edges;
    }

    /// One physics step: edge springs + all-pairs repulsion + centering.
    fn step(&mut self) {
        let n = self.nodes.len();
        if n == 0 {
            return;
        }
        let mut force = vec![Vec2::ZERO; n];

        // Repulsion (Coulomb) — O(n^2), fine for the capped node count.
        for i in 0..n {
            for j in (i + 1)..n {
                let d = self.nodes[i].pos - self.nodes[j].pos;
                let dist2 = (d.length_sq()).max(25.0);
                let f = d / dist2.sqrt() * (9000.0 / dist2);
                force[i] += f;
                force[j] -= f;
            }
        }
        // Springs along edges toward a rest length.
        for &(a, b) in &self.edges {
            let d = self.nodes[b].pos - self.nodes[a].pos;
            let len = d.length().max(0.01);
            let f = d / len * ((len - 90.0) * 0.02);
            force[a] += f;
            force[b] -= f;
        }
        // Gentle centering so the graph doesn't drift off.
        for i in 0..n {
            force[i] -= self.nodes[i].pos.to_vec2() * 0.002;
        }
        for i in 0..n {
            let node = &mut self.nodes[i];
            node.vel = (node.vel + force[i]) * 0.82; // damping
            node.pos += node.vel * 0.1;
        }
    }

    /// Render + interact. Returns the detail text of the selected node, if any.
    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<(String, String)> {
        self.step();
        ui.ctx().request_repaint(); // keep the simulation animating

        let size = ui.available_size();
        let (resp, painter) = ui.allocate_painter(size, Sense::click_and_drag());
        let center = resp.rect.center();

        // Pan by dragging empty space; zoom with the scroll wheel.
        if resp.dragged() {
            self.pan += resp.drag_delta();
        }
        let scroll = ui.input(|i| i.raw_scroll_delta.y);
        if scroll != 0.0 && resp.hovered() {
            self.zoom = (self.zoom * (1.0 + scroll * 0.001)).clamp(0.25, 4.0);
        }

        let to_screen = |p: Pos2| center + self.pan + p.to_vec2() * self.zoom;

        // Edges first (under the nodes).
        for &(a, b) in &self.edges {
            painter.line_segment(
                [to_screen(self.nodes[a].pos), to_screen(self.nodes[b].pos)],
                Stroke::new(1.0, Color32::from_gray(70)),
            );
        }

        // Click selection: nearest node to the pointer within a radius.
        if resp.clicked() {
            if let Some(p) = resp.interact_pointer_pos() {
                let mut best: Option<(usize, f32)> = None;
                for (i, node) in self.nodes.iter().enumerate() {
                    let d = (to_screen(node.pos) - p).length();
                    if d < 16.0 && best.map(|(_, bd)| d < bd).unwrap_or(true) {
                        best = Some((i, d));
                    }
                }
                self.selected = best.map(|(i, _)| i);
            }
        }

        // Nodes.
        for (i, node) in self.nodes.iter().enumerate() {
            let c = to_screen(node.pos);
            let r = node_radius(node.kind) * self.zoom.clamp(0.6, 1.6);
            painter.circle_filled(c, r, node.color);
            if Some(i) == self.selected {
                painter.circle_stroke(c, r + 3.0, Stroke::new(2.0, theme::TEXT));
            }
            // Label only for larger nodes / the selection, to reduce clutter.
            if node.kind != Kind::Finding || Some(i) == self.selected || self.zoom > 1.3 {
                painter.text(
                    c + Vec2::new(0.0, r + 2.0),
                    egui::Align2::CENTER_TOP,
                    &node.label,
                    egui::FontId::proportional(11.0),
                    theme::TEXT,
                );
            }
        }

        self.selected.map(|i| (self.nodes[i].label.clone(), self.nodes[i].detail.clone()))
    }

    pub fn reset_view(&mut self) {
        self.pan = Vec2::ZERO;
        self.zoom = 1.0;
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.nodes.len(), self.edges.len())
    }
}

fn node_radius(k: Kind) -> f32 {
    match k {
        Kind::Root => 12.0,
        Kind::Provider | Kind::Host => 9.0,
        Kind::Agent => 8.0,
        Kind::Service => 6.0,
        Kind::Finding => 5.0,
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

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}
