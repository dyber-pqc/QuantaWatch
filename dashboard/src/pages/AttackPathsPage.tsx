import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { fetchAttackPaths, fetchAttackPathTimeline, simulateAttackPaths, fetchIntegrations, remediateAttackPath, openAuthed, BOARD_REPORT_URL } from "../api/client";
import type { AttackPath, GraphNode, GraphNodeType, SimulateResponse, RemediationTicket, KillChainStage, PqcStatus } from "../api/types";
import { Badge, Group, Box, Text, ActionIcon, ScrollArea, Stack, Divider } from "@mantine/core";
import { Card, PageHeader, Stat, Spinner, EmptyState, SeverityBadge, PqcBadge } from "../components/ui";

const COL_INDEX: Record<GraphNodeType, number> = {
  identity: 0, data: 1, agent: 2, provider: 3, certificate: 4, dependency: 4, asset: 4,
  host: 4, service: 4, container: 4,
};
const COL_X = [80, 305, 530, 745, 930];
const COL_TITLE = ["Identities", "Data", "Agents", "Providers", "Assets & Hosts"];
const NODE_ICON: Record<GraphNodeType, string> = {
  identity: "🔑", data: "🗄", agent: "🤖", provider: "☁", certificate: "🔏", dependency: "📦", asset: "🌐",
  host: "🖥", service: "🔌", container: "🐳",
};
const VBW = 1010;

function riskColor(risk: number): string {
  if (risk >= 70) return "#e76a6e";
  if (risk >= 45) return "#f7894a";
  if (risk >= 20) return "#f2c744";
  return "#5bb98c";
}
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

function nodeColor(node: GraphNode): string {
  if (node.type === "data") return "#c084fc";
  if (node.type === "agent") return "#8b8ef0";
  if (node.type === "identity") return "#f0abfc";
  if (node.type === "container") return "#7a8699";
  return riskColor(node.risk);
}

function Graph({ nodes, edges, activeIds, focus, selectedNodeId, onNodeClick, maximized = false, onToggleFull }: { nodes: GraphNode[]; edges: { source: string; target: string; observed: boolean }[]; activeIds: Set<string> | null; focus: { id: string; nodeIds: string[] } | null; selectedNodeId: string | null; onNodeClick: (n: GraphNode | null) => void; maximized?: boolean; onToggleFull?: () => void }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  // Pan/zoom is applied IMPERATIVELY (ref + setAttribute), never through React
  // state — a wheel/trackpad can fire 100+ events/sec, and re-rendering the
  // ~250-element SVG on each one saturates the main thread and freezes the tab.
  // Here, zooming touches exactly one DOM attribute and triggers zero renders.
  const gRef = useRef<SVGGElement | null>(null);
  const labelRef = useRef<HTMLSpanElement | null>(null);
  const viewRef = useRef({ k: 1, tx: 0, ty: 0 });
  const pan = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);

  const layout = useMemo(() => {
    const cols: GraphNode[][] = [[], [], [], [], []];
    nodes.forEach((n) => cols[COL_INDEX[n.type]]?.push(n));
    const rowH = 84;
    const height = Math.max(1, ...cols.map((c) => c.length)) * rowH + 60;
    const pos: Record<string, { x: number; y: number; node: GraphNode }> = {};
    cols.forEach((arr, ci) => {
      const startY = (height - arr.length * rowH) / 2 + rowH / 2 + 24;
      arr.forEach((n, i) => { pos[n.id] = { x: COL_X[ci], y: startY + i * rowH, node: n }; });
    });
    return { pos, height, cols };
  }, [nodes]);

  const applyView = useCallback(() => {
    const v = viewRef.current;
    if (gRef.current) gRef.current.setAttribute("transform", `translate(${v.tx} ${v.ty}) scale(${v.k})`);
    if (labelRef.current) labelRef.current.textContent = `${Math.round(v.k * 100)}%`;
  }, []);

  const toSvg = (clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return null;
    const ctm = svg.getScreenCTM();
    if (!ctm) return null;
    const pt = svg.createSVGPoint();
    pt.x = clientX; pt.y = clientY;
    const p = pt.matrixTransform(ctm.inverse());
    return Number.isFinite(p.x) && Number.isFinite(p.y) ? { x: p.x, y: p.y } : null;
  };

  // Native, NON-passive wheel listener so preventDefault() actually stops the
  // page from scrolling/zooming underneath (React binds onWheel as passive).
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheelNative = (e: WheelEvent) => {
      e.preventDefault();
      const p = toSvg(e.clientX, e.clientY);
      if (!p) return;
      const v = viewRef.current;
      const nk = clamp(v.k * Math.exp(-e.deltaY * 0.0015), 0.5, 4);
      const r = nk / v.k;
      viewRef.current = { k: nk, tx: p.x - (p.x - v.tx) * r, ty: p.y - (p.y - v.ty) * r };
      applyView();
    };
    svg.addEventListener("wheel", onWheelNative, { passive: false });
    applyView(); // set the initial transform once mounted
    return () => svg.removeEventListener("wheel", onWheelNative);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applyView]);

  // Zoom-to-fit the selected path's nodes when a toxic combination is clicked.
  useEffect(() => {
    if (!focus || focus.nodeIds.length === 0) return;
    const pts = focus.nodeIds.map((id) => layout.pos[id]).filter(Boolean) as { x: number; y: number }[];
    if (!pts.length) return;
    const pad = 70;
    const xs = pts.map((p) => p.x), ys = pts.map((p) => p.y);
    const x0 = Math.min(...xs) - pad, x1 = Math.max(...xs) + pad;
    const y0 = Math.min(...ys) - pad, y1 = Math.max(...ys) + pad;
    const bw = Math.max(1, x1 - x0), bh = Math.max(1, y1 - y0);
    const k = clamp(Math.min(VBW / bw, layout.height / bh), 0.6, 3.2);
    viewRef.current = { k, tx: VBW / 2 - k * ((x0 + x1) / 2), ty: layout.height / 2 - k * ((y0 + y1) / 2) };
    applyView();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus?.id]);

  const onPointerDown = (e: React.PointerEvent) => {
    const p = toSvg(e.clientX, e.clientY);
    if (!p) return;
    (e.target as Element).setPointerCapture?.(e.pointerId);
    pan.current = { x: p.x, y: p.y, tx: viewRef.current.tx, ty: viewRef.current.ty };
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!pan.current) return;
    const p = toSvg(e.clientX, e.clientY);
    if (!p) return;
    viewRef.current = { ...viewRef.current, tx: pan.current.tx + (p.x - pan.current.x), ty: pan.current.ty + (p.y - pan.current.y) };
    applyView();
  };
  const endPan = () => { pan.current = null; };
  const zoomBy = (f: number) => {
    const v = viewRef.current;
    const nk = clamp(v.k * f, 0.5, 4);
    const cx = VBW / 2, cy = layout.height / 2, r = nk / v.k;
    viewRef.current = { k: nk, tx: cx - (cx - v.tx) * r, ty: cy - (cy - v.ty) * r };
    applyView();
  };
  const reset = () => { viewRef.current = { k: 1, tx: 0, ty: 0 }; applyView(); };

  const dim = (id: string) => (activeIds && !activeIds.has(id) ? 0.14 : 1);

  return (
    <div className="relative overflow-hidden rounded-lg border border-white/[0.06] bg-gradient-to-b from-surface-950/60 to-surface-900/30" style={{ height: maximized ? "100%" : undefined }}>
      {/* Zoom controls */}
      <div className="absolute right-3 top-3 z-10 flex flex-col gap-1 rounded-lg border border-white/10 bg-surface-900/95 p-1">
        <button type="button" onClick={() => zoomBy(1.3)} className="flex h-7 w-7 items-center justify-center rounded text-gray-300 hover:bg-white/10" title="Zoom in">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" d="M12 5v14M5 12h14" /></svg>
        </button>
        <button type="button" onClick={() => zoomBy(1 / 1.3)} className="flex h-7 w-7 items-center justify-center rounded text-gray-300 hover:bg-white/10" title="Zoom out">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" d="M5 12h14" /></svg>
        </button>
        <button type="button" onClick={reset} className="flex h-7 w-7 items-center justify-center rounded text-gray-400 hover:bg-white/10" title="Reset view">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.7} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3.75v4.5m0-4.5h4.5m-4.5 0L9 9M20.25 20.25v-4.5m0 4.5h-4.5m4.5 0L15 15M3.75 20.25v-4.5m0 4.5h4.5m-4.5 0L9 15M20.25 3.75v4.5m0-4.5h-4.5m4.5 0L15 9" /></svg>
        </button>
        <button type="button" onClick={onToggleFull} className="flex h-7 w-7 items-center justify-center rounded text-gray-300 hover:bg-white/10" title={maximized ? "Close full-screen tab" : "Open in a full-screen tab"}>
          {maximized ? (
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.7} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M9 9V4.5M9 9H4.5M9 9 3.75 3.75M9 15v4.5M9 15H4.5M9 15l-5.25 5.25M15 9h4.5M15 9V4.5M15 9l5.25-5.25M15 15h4.5M15 15v4.5m0-4.5 5.25 5.25" /></svg>
          ) : (
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.7} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3.75v4.5m0-4.5h4.5m-4.5 0L9 9M20.25 20.25v-4.5m0 4.5h-4.5m4.5 0L15 15M3.75 20.25v-4.5m0 4.5h4.5m-4.5 0L9 15M20.25 3.75v4.5m0-4.5h-4.5m4.5 0L15 9" /></svg>
          )}
        </button>
      </div>
      <div className="pointer-events-none absolute left-3 top-3 z-10 rounded bg-surface-900/90 px-2 py-0.5 text-[10px] text-gray-500">
        <span ref={labelRef}>100%</span> · scroll to zoom · drag to pan
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${VBW} ${layout.height}`}
        className="w-full cursor-grab touch-none active:cursor-grabbing"
        style={{ height: maximized ? "calc(100vh - 150px)" : 480 }}
        preserveAspectRatio="xMidYMid meet"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endPan}
        onPointerLeave={endPan}
      >
        <defs>
          <marker id="ap-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,1 L9,5 L0,9" fill="none" stroke="#6b8fd0" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </marker>
          <marker id="ap-arrow-dim" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M0,1 L9,5 L0,9" fill="none" stroke="#4a4948" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </marker>
          <radialGradient id="ap-node" cx="35%" cy="30%" r="80%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.14" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
          </radialGradient>
          {/* Soft outer glow, colored per node via the group's `color`. */}
          <filter id="ap-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="3.2" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <pattern id="ap-grid" width="26" height="26" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="#ffffff" fillOpacity="0.028" />
          </pattern>
          <style>{`
            .ap-node { cursor: pointer; }
            .ap-node .ap-halo { opacity: 0; transition: opacity 140ms ease; }
            .ap-node:hover .ap-halo { opacity: 0.9; }
            .ap-node:hover .ap-core { filter: brightness(1.25); }
            .ap-flow { stroke-dasharray: 5 7; animation: apFlow 0.9s linear infinite; }
            @keyframes apFlow { to { stroke-dashoffset: -24; } }
            .ap-sel { animation: apSel 1.7s ease-in-out infinite; transform-box: fill-box; transform-origin: center; }
            @keyframes apSel { 0%,100% { opacity: .95; } 50% { opacity: .3; } }
            @media (prefers-reduced-motion: reduce) {
              .ap-flow, .ap-sel { animation: none; }
            }
          `}</style>
        </defs>
        {/* Dot-grid backdrop (fixed to the viewBox, sits under the pan/zoom group). */}
        <rect x={0} y={0} width={VBW} height={layout.height} fill="url(#ap-grid)" />
        <rect x={0} y={0} width={VBW} height={layout.height} fill="transparent" onClick={() => onNodeClick(null)} />

        <g ref={gRef}>
          {/* Column bands + headers */}
          {COL_X.map((x, i) => (
            <g key={i}>
              <rect x={x - 62} y={30} width={124} height={layout.height - 44} rx={12} fill="#ffffff" fillOpacity={0.014} />
              <text x={x} y={20} textAnchor="middle" className="fill-gray-500" style={{ fontSize: 10.5, letterSpacing: 1.5, fontWeight: 600 }}>
                {COL_TITLE[i].toUpperCase()}
              </text>
            </g>
          ))}

          {/* Edges */}
          {edges.map((e, i) => {
            const a = layout.pos[e.source]; const b = layout.pos[e.target];
            if (!a || !b) return null;
            const active = activeIds ? activeIds.has(e.source) && activeIds.has(e.target) : false;
            const touchesSel = selectedNodeId != null && (e.source === selectedNodeId || e.target === selectedNodeId);
            const faded = (activeIds && !active) || (selectedNodeId != null && !touchesSel && !active);
            const mx = (a.x + b.x) / 2;
            const ra = 15 + (a.node.risk / 100) * 9;
            const rb = 15 + (b.node.risk / 100) * 9;
            const d = `M ${a.x + ra} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - rb - 3} ${b.y}`;
            const highlight = active || touchesSel;
            const stroke = highlight ? "#a6a8f0" : e.observed ? "#5b8def" : "#3b3a39";
            return (
              <g key={i} opacity={faded ? 0.09 : 1} style={{ transition: "opacity 140ms" }}>
                <path
                  d={d}
                  fill="none"
                  stroke={stroke}
                  strokeWidth={highlight ? 2.6 : e.observed ? 1.7 : 1.1}
                  strokeDasharray={e.observed ? "0" : "4 3"}
                  markerEnd={faded ? "url(#ap-arrow-dim)" : "url(#ap-arrow)"}
                  opacity={e.observed || highlight ? 0.9 : 0.5}
                />
                {/* Live traffic (or a highlighted edge) gets a flowing pulse. */}
                {(e.observed || highlight) && !faded && (
                  <path className="ap-flow" d={d} fill="none" stroke={highlight ? "#c7c9ff" : "#9fc2ff"} strokeWidth={highlight ? 2 : 1.4} strokeLinecap="round" opacity={0.9} />
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {Object.values(layout.pos).map(({ x, y, node }) => {
            const r = 15 + (node.risk / 100) * 9;
            const color = nodeColor(node);
            const isSel = node.id === selectedNodeId;
            const label = node.label.length > 15 ? node.label.slice(0, 14) + "…" : node.label;
            const sub = node.blastRadius > 0 ? `blast ${node.blastRadius}` : node.sublabel.slice(0, 18);
            return (
              <g
                key={node.id}
                className="ap-node"
                opacity={dim(node.id)}
                style={{ transition: "opacity 120ms" }}
                onClick={(e) => { e.stopPropagation(); onNodeClick(node); }}
              >
                {/* Pulsing selection ring */}
                {isSel && <circle className="ap-sel" cx={x} cy={y} r={r + 8} fill="none" stroke={color} strokeWidth={2.2} />}
                {/* Hover halo (revealed via CSS) */}
                <circle className="ap-halo" cx={x} cy={y} r={r + 6} fill={color} fillOpacity={0.14} />
                {node.observed && (
                  <circle cx={x} cy={y} r={r + 5.5} fill="none" stroke="#5b8def" strokeWidth={1.3} strokeDasharray="2 3" opacity={0.55} />
                )}
                {/* Core disc with a colored glow */}
                <g filter="url(#ap-glow)">
                  <circle className="ap-core" cx={x} cy={y} r={r} fill={color} fillOpacity={isSel ? 0.28 : 0.16} stroke={color} strokeWidth={isSel ? 2.4 : 1.8} />
                </g>
                <circle cx={x} cy={y} r={r} fill="url(#ap-node)" />
                <text x={x} y={y + 5} textAnchor="middle" style={{ fontSize: 15, pointerEvents: "none" }}>{NODE_ICON[node.type]}</text>
                {/* risk pill */}
                <g transform={`translate(${x + r - 2} ${y - r + 1})`} style={{ pointerEvents: "none" }}>
                  <circle r={7} fill="#1f1f1f" stroke={color} strokeWidth={1.2} />
                  <text textAnchor="middle" y={2.6} style={{ fontSize: 7.5, fontWeight: 700 }} fill={color}>{Math.round(node.risk)}</text>
                </g>
                <text x={x} y={y + r + 15} textAnchor="middle" className="fill-gray-100" style={{ fontSize: 11, fontWeight: 600, pointerEvents: "none" }}>{label}</text>
                <text x={x} y={y + r + 27} textAnchor="middle" className="fill-gray-500" style={{ fontSize: 8.5, pointerEvents: "none" }}>{sub}</text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

const KIND_LABEL: Record<AttackPath["kind"], { label: string; color: string }> = {
  "data-exposure": { label: "Data Exposure", color: "red" },
  "access-risk": { label: "Access Risk", color: "yellow" },
  "external-asset": { label: "External Asset", color: "brand" },
};

function ScoreBox({ score }: { score: number }) {
  const c = riskColor(score);
  return (
    <Box style={{ width: 46, height: 46, flexShrink: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", borderRadius: 2, background: `${c}1a`, border: `1px solid ${c}66` }}>
      <Text ff="heading" fw={700} fz={16} lh={1} style={{ color: c, fontVariantNumeric: "tabular-nums" }}>{Math.round(score)}</Text>
      <Text ff="monospace" fz={7.5} fw={600} tt="uppercase" c="dimmed" mt={2} style={{ letterSpacing: "0.06em" }}>risk</Text>
    </Box>
  );
}

function Arrow() {
  return <svg width={12} height={12} style={{ flexShrink: 0, color: "var(--mantine-color-dark-3)" }} fill="none" viewBox="0 0 24 24" strokeWidth={2.2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" /></svg>;
}

// Kill-chain stage → solid bar color + light text color (bg is a tint of the bar).
const KC: Record<KillChainStage["status"], { bar: string; text: string }> = {
  active: { bar: "var(--mantine-color-red-5)", text: "var(--mantine-color-red-2)" },
  feasible: { bar: "var(--mantine-color-orange-5)", text: "var(--mantine-color-orange-2)" },
  pending: { bar: "var(--mantine-color-violet-4)", text: "var(--mantine-color-violet-2)" },
  blocked: { bar: "var(--mantine-color-teal-5)", text: "var(--mantine-color-teal-2)" },
  na: { bar: "var(--mantine-color-dark-3)", text: "var(--mantine-color-dark-2)" },
};

function KillChain({ stages }: { stages: KillChainStage[] }) {
  return (
    <Box mt="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "rgba(0,0,0,0.15)" }}>
      <Text ff="monospace" fz={9} fw={600} tt="uppercase" c="dimmed" px={8} pt={6} pb={2} style={{ letterSpacing: "0.08em" }}>Crypto kill-chain</Text>
      <div style={{ padding: "2px 6px 6px", display: "flex", flexDirection: "column", gap: 2 }}>
        {stages.map((s, i) => {
          const m = KC[s.status];
          return (
            <Box key={s.key} title={s.detail}
              style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", borderRadius: 2, borderLeft: `2px solid ${m.bar}`, background: `color-mix(in srgb, ${m.bar} 10%, transparent)` }}>
              <Text ff="monospace" fz={9} c="dimmed" style={{ width: 12, flexShrink: 0 }}>{i + 1}</Text>
              <Box w={7} h={7} style={{ borderRadius: "50%", background: m.bar, flexShrink: 0 }} />
              <Text fz={11.5} fw={600} style={{ color: m.text }}>{s.label}</Text>
              <Text ff="monospace" fz={9} tt="uppercase" style={{ marginLeft: "auto", color: m.bar, letterSpacing: "0.04em", flexShrink: 0 }}>{s.status === "na" ? "n/a" : s.status}</Text>
            </Box>
          );
        })}
      </div>
    </Box>
  );
}

function ExploitChip({ value }: { value: number }) {
  const color = value >= 60 ? "red" : value >= 30 ? "orange" : value >= 10 ? "yellow" : "teal";
  return (
    <Badge variant="light" color={color} radius={2} size="sm" tt="none" fw={600}
      title="Exploitability — how realistically this path can be executed (reachability × data value × channel weakness)">
      exploit {Math.round(value)}
    </Badge>
  );
}

function PathRow({ path, onHover, onSelect, selected, remediable }: { path: AttackPath; onHover: (id: string | null) => void; onSelect: (id: string) => void; selected: boolean; remediable: { id: string; displayName: string }[] }) {
  const kind = KIND_LABEL[path.kind];
  const [open, setOpen] = useState(false);
  const [ticket, setTicket] = useState<RemediationTicket | null>(null);
  const mut = useMutation({
    mutationFn: (integrationId: string) => remediateAttackPath(path.id, { integrationId }),
    onSuccess: (t) => { setTicket(t); setOpen(false); },
  });
  return (
    <div
      onMouseEnter={() => onHover(path.id)}
      onMouseLeave={() => onHover(null)}
      onClick={(e) => { if (!(e.target as Element).closest("button,a")) onSelect(path.id); }}
      className={`cursor-pointer border-l-2 px-4 py-3.5 transition-colors ${selected ? "bg-brand-500/[0.08]" : "hover:bg-white/[0.025]"}`}
      style={{ borderLeftColor: riskColor(path.score), borderLeftWidth: selected ? 3 : 2 }}
    >
      <div className="flex items-start gap-3">
        <ScoreBox score={path.score} />
        <div className="min-w-0 flex-1">
          <Group gap={6} align="center">
            <SeverityBadge severity={path.severity} />
            <Badge variant="light" color={kind.color} radius={2} size="sm" tt="none" fw={600}>{kind.label}</Badge>
            {path.hndl && <Badge variant="light" color="grape" radius={2} size="sm" tt="none" fw={600} title="Harvest-now, decrypt-later">HNDL</Badge>}
            {path.observed && (
              <Badge variant="light" color="cyan" radius={2} size="sm" tt="none" fw={600}
                leftSection={<Box w={6} h={6} style={{ borderRadius: "50%", background: "var(--mantine-color-cyan-4)" }} />}>
                observed · {path.requestCount}
              </Badge>
            )}
            {typeof path.exploitability === "number" && <ExploitChip value={path.exploitability} />}
          </Group>

          {/* Chain flow */}
          <Group gap={6} align="center" mt="xs">
            <Badge variant="light" color="grape" radius={2} size="sm" tt="none" fw={600}>{path.dataClass}</Badge>
            <Arrow />
            <Badge variant="light" color="brand" radius={2} size="sm" tt="none" fw={600}>{path.agent}</Badge>
            {path.provider !== "—" && (<><Arrow /><Badge variant="light" color="gray" radius={2} size="sm" tt="none" fw={600}>{path.provider}</Badge></>)}
            {path.channelPqc && path.provider !== "—" && <PqcBadge status={path.channelPqc} />}
          </Group>

          {path.killChain && path.killChain.length > 0 && <KillChain stages={path.killChain} />}

          <p className="mt-2.5 text-[12px] leading-relaxed text-gray-500">{path.recommendation}</p>

          <div className="mt-2.5">
            {ticket ? (
              <a href={ticket.externalUrl} target="_blank" rel="noreferrer" className="qw-chip bg-emerald-400/10 text-emerald-300 ring-1 ring-emerald-400/30">{ticket.externalId} ↗</a>
            ) : (
              <div className="relative inline-block">
                <button
                  onClick={() => remediable.length && setOpen((v) => !v)}
                  disabled={!remediable.length || mut.isPending}
                  title={remediable.length ? "" : "Configure Jira or Linear to auto-remediate"}
                  className={`inline-flex items-center gap-1.5 rounded-[2px] px-2.5 py-1 text-[11.5px] font-semibold transition-colors ${remediable.length ? "bg-brand-500/15 text-brand-200 ring-1 ring-brand-400/30 hover:bg-brand-500/25" : "cursor-not-allowed bg-white/[0.04] text-gray-600"}`}>
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={1.8} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="m3.75 13.5 10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z" /></svg>
                  {mut.isPending ? "Creating…" : "Auto-remediate"}
                </button>
                {open && (
                  <div className="absolute left-0 z-20 mt-1 w-44 overflow-hidden rounded-lg border border-white/10 bg-surface-900/95 shadow-2xl backdrop-blur">
                    {remediable.map((it) => (
                      <button key={it.id} onClick={() => mut.mutate(it.id)} className="block w-full px-3 py-2 text-left text-xs text-gray-300 hover:bg-white/5">{it.displayName}</button>
                    ))}
                  </div>
                )}
                {mut.isError && <span className="ml-2 text-[10px] text-rose-400">failed</span>}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

const NODE_KIND_INFO: Record<GraphNodeType, { label: string; note: string }> = {
  identity: { label: "Identity", note: "A user or API key that can drive agents. Over-privileged non-human identities are an access-risk path." },
  data: { label: "Data class", note: "A category of data an agent handles. Node risk reflects its sensitivity — the prize an attacker is after." },
  agent: { label: "AI agent", note: "Reaches the providers shown. Its data is exposed if any channel it uses is quantum-vulnerable." },
  provider: { label: "AI provider", note: "An upstream AI endpoint. Its TLS key exchange decides harvest-now-decrypt-later exposure on every call." },
  certificate: { label: "Certificate", note: "An X.509 certificate on a channel. A classical signature algorithm is quantum-forgeable." },
  dependency: { label: "Crypto dependency", note: "A cryptographic library found in your code. Replace weak/classical ones with PQC-capable equivalents." },
  asset: { label: "Infrastructure asset", note: "Discovered by a cloud / connector inventory." },
  host: { label: "Estate host", note: "A registered system in your estate. Its services and containers appear as connected nodes." },
  service: { label: "Network service", note: "A listening service on a host. Classical transport crypto here is harvestable — protect it with the PQC overlay or issue it a hybrid cert." },
  container: { label: "Container", note: "A container running on a host." },
};

const EDGE_VERB: Record<string, string> = {
  "can-access": "can access",
  handles: "handles",
  "routes-to": "routes to",
  "secured-by": "secured by",
  "depends-on": "depends on",
  exposes: "exposes",
  runs: "runs",
};

function NodeDetail({ node, nodes, edges, paths, onFocusPath, onClose }: {
  node: GraphNode;
  nodes: GraphNode[];
  edges: { source: string; target: string; observed: boolean; kind?: string }[];
  paths: AttackPath[];
  onFocusPath: (id: string) => void;
  onClose: () => void;
}) {
  const byId = useMemo(() => Object.fromEntries(nodes.map((n) => [n.id, n])), [nodes]);
  const outgoing = edges.filter((e) => e.source === node.id).map((e) => ({ n: byId[e.target], kind: e.kind, out: true, observed: e.observed })).filter((x) => x.n);
  const incoming = edges.filter((e) => e.target === node.id).map((e) => ({ n: byId[e.source], kind: e.kind, out: false, observed: e.observed })).filter((x) => x.n);
  const inPaths = paths.filter((p) => p.nodeIds.includes(node.id));
  const info = NODE_KIND_INFO[node.type];
  const hasPqc = node.pqcStatus && node.pqcStatus !== "n/a";
  const color = nodeColor(node);

  const Conn = ({ n, kind, out, observed }: { n: GraphNode; kind?: string; out: boolean; observed: boolean }) => (
    <Group gap={7} wrap="nowrap" style={{ minWidth: 0 }}>
      <Text ff="monospace" fz={10} c={out ? "brand.4" : "dark.2"} style={{ flexShrink: 0 }}>{out ? "→" : "←"}</Text>
      <Text fz={15} style={{ flexShrink: 0, lineHeight: 1 }}>{NODE_ICON[n.type]}</Text>
      <Box style={{ minWidth: 0 }}>
        <Text fz={11.5} c="gray.2" truncate>{n.label}</Text>
        <Text fz={9} c="dimmed">{kind ? (EDGE_VERB[kind] ?? kind) : n.type}{observed ? " · observed" : ""}</Text>
      </Box>
    </Group>
  );

  return (
    <Box
      style={{
        position: "absolute", top: 10, right: 10, width: 280, maxHeight: "calc(100% - 20px)", zIndex: 20,
        display: "flex", flexDirection: "column",
        background: "color-mix(in srgb, var(--mantine-color-dark-7) 92%, transparent)",
        backdropFilter: "blur(6px)",
        border: `1px solid ${color}55`, borderRadius: 4,
        boxShadow: "0 12px 40px rgba(0,0,0,0.5)",
      }}
    >
      <Group justify="space-between" wrap="nowrap" px="sm" py={8} style={{ borderBottom: "1px solid var(--mantine-color-dark-5)" }}>
        <Group gap={8} wrap="nowrap" style={{ minWidth: 0 }}>
          <Box style={{ width: 26, height: 26, flexShrink: 0, display: "grid", placeItems: "center", borderRadius: 4, background: `${color}22`, border: `1px solid ${color}66` }}>
            <Text fz={15} style={{ lineHeight: 1 }}>{NODE_ICON[node.type]}</Text>
          </Box>
          <Box style={{ minWidth: 0 }}>
            <Text fw={700} fz={13} c="gray.1" truncate>{node.label}</Text>
            <Text fz={9.5} tt="uppercase" c="dimmed" style={{ letterSpacing: "0.06em" }}>{info?.label ?? node.type}</Text>
          </Box>
        </Group>
        <ActionIcon variant="subtle" color="gray" size="sm" radius={2} onClick={onClose} aria-label="Close">
          <svg width={14} height={14} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
        </ActionIcon>
      </Group>

      <ScrollArea.Autosize mah="calc(100vh - 320px)">
        <Stack gap="xs" p="sm">
          {node.sublabel && <Text ff="monospace" fz={10.5} c="dark.1">{node.sublabel}</Text>}

          <Group gap={6}>
            {hasPqc && <PqcBadge status={node.pqcStatus as PqcStatus} />}
            <Badge variant="light" color={node.risk >= 70 ? "red" : node.risk >= 45 ? "orange" : node.risk >= 20 ? "yellow" : "teal"} radius={2} size="sm" tt="none" fw={600}
              title="Risk — channel weakness weighted by what it protects">risk {Math.round(node.risk)}</Badge>
            {node.blastRadius > 0 && <Badge variant="light" color="grape" radius={2} size="sm" tt="none" fw={600} title="Sensitivity exposed if this node's crypto broke">blast {node.blastRadius}</Badge>}
            {node.observed && <Badge variant="light" color="cyan" radius={2} size="sm" tt="none" fw={600}>observed</Badge>}
          </Group>

          {(outgoing.length > 0 || incoming.length > 0) && (
            <>
              <Divider label={`Connections (${outgoing.length + incoming.length})`} labelPosition="left" styles={{ label: { fontSize: 9.5, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--mantine-color-dark-2)" } }} />
              <Stack gap={6}>
                {outgoing.map((c, i) => <Conn key={`o${i}`} {...c} />)}
                {incoming.map((c, i) => <Conn key={`i${i}`} {...c} />)}
              </Stack>
            </>
          )}

          {inPaths.length > 0 && (
            <>
              <Divider label={`In attack paths (${inPaths.length})`} labelPosition="left" styles={{ label: { fontSize: 9.5, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--mantine-color-dark-2)" } }} />
              <Stack gap={5}>
                {inPaths.slice(0, 6).map((p) => (
                  <Box key={p.id} onClick={() => onFocusPath(p.id)}
                    style={{ cursor: "pointer", borderLeft: `2px solid ${riskColor(p.score)}`, padding: "3px 8px", borderRadius: 2, background: "rgba(255,255,255,0.02)" }}>
                    <Group gap={6} wrap="nowrap">
                      <Text ff="heading" fw={700} fz={11} style={{ color: riskColor(p.score), fontVariantNumeric: "tabular-nums", flexShrink: 0 }}>{Math.round(p.score)}</Text>
                      <Text fz={10.5} c="gray.3" truncate>{p.title}</Text>
                    </Group>
                  </Box>
                ))}
              </Stack>
            </>
          )}

          {info?.note && <Text fz={10.5} c="dimmed" style={{ lineHeight: 1.5 }} mt={2}>{info.note}</Text>}
        </Stack>
      </ScrollArea.Autosize>
    </Box>
  );
}

export default function AttackPathsPage() {
  const { data, isLoading } = useQuery({ queryKey: ["attack-paths"], queryFn: fetchAttackPaths });
  const { data: timeline } = useQuery({ queryKey: ["attack-path-timeline"], queryFn: fetchAttackPathTimeline });
  const { data: integrationsData } = useQuery({ queryKey: ["integrations"], queryFn: fetchIntegrations });
  const [hovered, setHovered] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [sim, setSim] = useState<SimulateResponse | null>(null);
  const [hardened, setHardened] = useState<Set<string>>(new Set());
  const [simBusy, setSimBusy] = useState(false);
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const maximized = pathname.endsWith("/graph");
  const toggleFull = () => navigate(maximized ? "/attack-paths" : "/attack-paths/graph");

  if (isLoading) return <Spinner className="h-64" />;

  const live = sim ?? data;
  const paths = live?.paths ?? [];
  // Dedupe by id: two Estate targets can share a host, which would otherwise
  // collide on host:/service: node ids and trip React's duplicate-key guard.
  const graphNodes = Array.from(new Map((live?.nodes ?? []).map((n) => [n.id, n])).values());
  const graphEdges = live?.edges ?? [];
  const s = live?.summary;
  // Highlight follows hover, but falls back to the pinned (clicked) path.
  const activePath = paths.find((p) => p.id === (hovered ?? selected));
  const activeIds = activePath ? new Set(activePath.nodeIds) : null;
  const selectedPath = paths.find((p) => p.id === selected);
  const focus = selectedPath ? { id: selectedPath.id, nodeIds: selectedPath.nodeIds } : null;
  const toggleSelect = (id: string) => setSelected((cur) => (cur === id ? null : id));

  // Maximized: the graph gets its own editor tab, filling the pane. Panning and
  // zooming stay inside the graph instead of scrolling the page.
  if (maximized) {
    return (
      <div className="p-3" style={{ height: "calc(100vh - 96px)" }}>
        <div style={{ position: "relative", height: "100%" }}>
          <Graph nodes={graphNodes} edges={graphEdges} activeIds={activeIds} focus={focus} selectedNodeId={selectedNode?.id ?? null} onNodeClick={setSelectedNode} maximized onToggleFull={toggleFull} />
          {selectedNode && (
            <NodeDetail
              node={selectedNode}
              nodes={graphNodes}
              edges={graphEdges}
              paths={paths}
              onFocusPath={(id) => setSelected(id)}
              onClose={() => setSelectedNode(null)}
            />
          )}
        </div>
      </div>
    );
  }

  const vulnProviders = Array.from(
    new Set((data?.nodes ?? []).filter((n) => n.type === "provider" && n.risk > 20).map((n) => n.label)),
  );
  const remediable = (integrationsData?.integrations ?? [])
    .filter((i) => i.capabilities.includes("create_remediation"))
    .map((i) => ({ id: i.id, displayName: i.displayName }));

  const runSim = async (next: Set<string>) => {
    setHardened(next);
    if (next.size === 0) { setSim(null); return; }
    setSimBusy(true);
    try {
      const res = await simulateAttackPaths(Array.from(next).map((provider) => ({ provider, pqcStatus: "hybrid" })));
      setSim(res);
    } finally { setSimBusy(false); }
  };

  const toggle = (p: string) => {
    const next = new Set(hardened);
    next.has(p) ? next.delete(p) : next.add(p);
    runSim(next);
  };

  const tlData = (timeline?.timeline ?? []).map((t) => ({ t: new Date(t.timestamp).getTime(), total: t.total, critical: t.critical }));

  return (
    <div className="space-y-5">
      <PageHeader
        title="Attack Paths"
        subtitle="Crypto security graph — ranked by exploitability (reachability × data value × channel weakness), each with its harvest-now-decrypt-later kill-chain"
        actions={
          <button onClick={() => openAuthed(BOARD_REPORT_URL)} className="qw-btn-primary">
            Board Report (PDF)
          </button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
        <Stat label="Exposure Paths" value={s?.total ?? 0} accent="brand" />
        <Stat label="Critical" value={s?.critical ?? 0} accent={(s?.critical ?? 0) > 0 ? "rose" : "emerald"} />
        <Stat label="HNDL" value={s?.hndl ?? 0} accent="violet" sub="harvest-now-decrypt-later" />
        <Stat label="Observed" value={s?.observed ?? 0} accent="brand" sub="from live traffic" />
        <Stat label="High" value={s?.high ?? 0} accent="amber" />
      </div>

      {/* Remediation simulation */}
      {vulnProviders.length > 0 && (
        <Card className="p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="qw-eyebrow">Remediation Simulation — harden to hybrid ML-KEM:</div>
            {vulnProviders.map((p) => (
              <label key={p} className="flex cursor-pointer items-center gap-1.5 text-xs text-gray-300">
                <input type="checkbox" checked={hardened.has(p)} onChange={() => toggle(p)} className="accent-brand-500" />
                {p}
              </label>
            ))}
            {simBusy && <Spinner className="!h-4" />}
            {sim && (
              <div className="ml-auto flex items-center gap-3 text-sm">
                <span className="text-gray-400">risk <span className="text-gray-200">{sim.baseRisk}</span> → <span className="text-emerald-300">{sim.simRisk}</span></span>
                <span className="rounded bg-emerald-500/15 px-2 py-0.5 font-semibold text-emerald-300">−{sim.riskReduction}% risk</span>
                <span className="text-gray-500">critical {sim.before.critical} → {sim.after.critical}</span>
              </div>
            )}
          </div>
        </Card>
      )}

      {paths.length === 0 && !sim ? (
        <Card><EmptyState title="No attack paths">Every agent's data reaches its providers over a PQC-safe channel, or no agents/providers are configured yet.</EmptyState></Card>
      ) : (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <div className="space-y-5 xl:col-span-2">
            <Card className="p-4">
              <div className="mb-3 flex items-center justify-between">
                <div className="qw-eyebrow">Cryptographic Security Graph {sim && <span className="text-quantum-300">(simulated)</span>}</div>
                {activePath && <div className="max-w-[55%] truncate text-[11px] text-gray-500">{activePath.title}</div>}
              </div>
              <div style={{ position: "relative" }}>
                <Graph nodes={graphNodes} edges={graphEdges} activeIds={activeIds} focus={focus} selectedNodeId={selectedNode?.id ?? null} onNodeClick={setSelectedNode} maximized={false} onToggleFull={toggleFull} />
                {selectedNode && (
                  <NodeDetail
                    node={selectedNode}
                    nodes={graphNodes}
                    edges={graphEdges}
                    paths={paths}
                    onFocusPath={(id) => setSelected(id)}
                    onClose={() => setSelectedNode(null)}
                  />
                )}
              </div>
              <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[10px] text-gray-500">
                <span className="flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full border border-dashed border-[#5b8def]" /> observed in live traffic</span>
                <span className="flex items-center gap-1"><span className="inline-block h-0 w-4 border-t-2 border-[#5b8def]" /> observed flow</span>
                <span className="flex items-center gap-1"><span className="inline-block h-0 w-4 border-t border-dashed border-gray-600" /> possible flow</span>
                <span>click a node for details · node size &amp; ring = risk</span>
              </div>
            </Card>

            {tlData.length > 1 && (
              <Card className="p-4">
                <div className="qw-eyebrow mb-3">Exposure Drift</div>
                <div className="h-36">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={tlData}>
                      <defs><linearGradient id="apFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#e76a6e" stopOpacity={0.3} /><stop offset="100%" stopColor="#e76a6e" stopOpacity={0} /></linearGradient></defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#3b3a39" vertical={false} />
                      <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: "short", day: "numeric" })} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={{ stroke: "#3b3a39" }} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} width={24} />
                      <Tooltip contentStyle={{ background: "#2d2c2c", border: "1px solid #3b3a39", borderRadius: 8, color: "#e2e8f0", fontSize: 12 }} labelFormatter={(v) => new Date(v).toLocaleString()} />
                      <Area type="stepAfter" dataKey="total" name="paths" stroke="#e76a6e" strokeWidth={2} fill="url(#apFill)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Card>
            )}
          </div>

          <Card>
            <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
              <div className="qw-eyebrow">Toxic Combinations <span className="ml-1 font-normal normal-case tracking-normal text-gray-600">· click to focus the graph</span></div>
              <span className="text-[11px] text-gray-500">{paths.length}</span>
            </div>
            <div className="max-h-[640px] divide-y divide-white/5 overflow-y-auto">
              {paths.map((p) => <PathRow key={p.id} path={p} onHover={setHovered} onSelect={toggleSelect} selected={p.id === selected} remediable={remediable} />)}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
