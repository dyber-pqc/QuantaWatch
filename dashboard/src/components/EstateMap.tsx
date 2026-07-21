import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Box, Button, Group, Stack, Text, ActionIcon, ScrollArea, Divider, Tooltip } from "@mantine/core";
import { protectService, issueServiceCert, scanTarget } from "../api/client";
import type { Target, ExposedService, HostContainer } from "../api/types";

const PQC_HEX: Record<string, string> = {
  classical_weak: "#e76a6e",
  classical_secure: "#f7894a",
  unknown: "#8a94a6",
  hybrid: "#4dd4e0",
  pqc_ready: "#5bb98c",
};
const pqcHex = (s?: string) => PQC_HEX[s ?? "unknown"] ?? "#8a94a6";
const ICON = { host: "🖥", service: "🔌", container: "🐳" } as const;
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));
const fixable = (s?: string) => s === "classical_weak" || s === "classical_secure" || s === "unknown";

type MapNode =
  | { kind: "host"; id: string; x: number; y: number; t: Target }
  | { kind: "service"; id: string; x: number; y: number; t: Target; s: ExposedService }
  | { kind: "container"; id: string; x: number; y: number; t: Target; c: HostContainer };

const COL = { host: 96, service: 380, container: 660 };
const ROW = 66;
const BAND_GAP = 34;
const VBW = 780;

export function EstateMap({ targets, onDeepScan }: { targets: Target[]; onDeepScan: (t: Target) => void }) {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const svgRef = useRef<SVGSVGElement | null>(null);
  const gRef = useRef<SVGGElement | null>(null);
  const labelRef = useRef<HTMLSpanElement | null>(null);
  const viewRef = useRef({ k: 1, tx: 0, ty: 0 });
  const pan = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["targets"] });
    qc.invalidateQueries({ queryKey: ["attack-paths"] });
    qc.invalidateQueries({ queryKey: ["overlay"] });
    qc.invalidateQueries({ queryKey: ["pki"] });
  };
  const sweep = useMutation({ mutationFn: (id: string) => scanTarget(id), onSuccess: invalidate });
  const protect = useMutation({ mutationFn: (v: { id: string; port: number }) => protectService(v.id, v.port), onSuccess: invalidate });
  const cert = useMutation({ mutationFn: (v: { id: string; port: number }) => issueServiceCert(v.id, v.port), onSuccess: invalidate });

  const layout = useMemo(() => {
    const nodes: MapNode[] = [];
    const edges: { a: string; b: string }[] = [];
    let y = 40;
    for (const t of targets) {
      const svcs = t.exposedServices ?? [];
      const cons = t.containers ?? [];
      const rows = Math.max(svcs.length, cons.length, 1);
      const bandH = rows * ROW;
      const hostY = y + bandH / 2;
      const hid = `host:${t.id}`;
      nodes.push({ kind: "host", id: hid, x: COL.host, y: hostY, t });
      svcs.forEach((s, i) => {
        const id = `svc:${t.id}:${s.port}`;
        nodes.push({ kind: "service", id, x: COL.service, y: y + i * ROW + ROW / 2, t, s });
        edges.push({ a: hid, b: id });
      });
      cons.forEach((c, j) => {
        const id = `con:${t.id}:${c.name}`;
        nodes.push({ kind: "container", id, x: COL.container, y: y + j * ROW + ROW / 2, t, c });
        edges.push({ a: hid, b: id });
      });
      y += bandH + BAND_GAP;
    }
    const height = Math.max(y + 10, 220);
    const posById: Record<string, MapNode> = Object.fromEntries(nodes.map((n) => [n.id, n]));
    return { nodes, edges, height, posById };
  }, [targets]);

  const selected = selectedId ? layout.posById[selectedId] : null;

  const applyView = useCallback(() => {
    const v = viewRef.current;
    if (gRef.current) gRef.current.setAttribute("transform", `translate(${v.tx} ${v.ty}) scale(${v.k})`);
    if (labelRef.current) labelRef.current.textContent = `${Math.round(v.k * 100)}%`;
  }, []);

  const toSvg = (cx: number, cy: number) => {
    const svg = svgRef.current;
    if (!svg) return null;
    const ctm = svg.getScreenCTM();
    if (!ctm) return null;
    const pt = svg.createSVGPoint();
    pt.x = cx; pt.y = cy;
    const p = pt.matrixTransform(ctm.inverse());
    return Number.isFinite(p.x) && Number.isFinite(p.y) ? { x: p.x, y: p.y } : null;
  };

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const p = toSvg(e.clientX, e.clientY);
      if (!p) return;
      const v = viewRef.current;
      const nk = clamp(v.k * Math.exp(-e.deltaY * 0.0015), 0.5, 4);
      const r = nk / v.k;
      viewRef.current = { k: nk, tx: p.x - (p.x - v.tx) * r, ty: p.y - (p.y - v.ty) * r };
      applyView();
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    applyView();
    return () => svg.removeEventListener("wheel", onWheel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applyView]);

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

  const nodeColor = (n: MapNode) =>
    n.kind === "host" ? pqcHex(n.t.pqcStatus) : n.kind === "service" ? pqcHex(n.s.pqcStatus) : "#7a8699";
  const nodeR = (n: MapNode) => (n.kind === "host" ? 22 : n.kind === "container" ? 14 : 16);

  return (
    <div className="relative overflow-hidden rounded-lg border border-white/[0.06] bg-gradient-to-b from-surface-950/60 to-surface-900/30">
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
      </div>
      <div className="pointer-events-none absolute left-3 top-3 z-10 rounded bg-surface-900/90 px-2 py-0.5 text-[10px] text-gray-500">
        <span ref={labelRef}>100%</span> · click a node for details · scroll to zoom
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${VBW} ${layout.height}`}
        className="w-full cursor-grab touch-none active:cursor-grabbing"
        style={{ height: 460 }}
        preserveAspectRatio="xMidYMid meet"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endPan}
        onPointerLeave={endPan}
      >
        <defs>
          <marker id="em-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,1 L9,5 L0,9" fill="none" stroke="#6b8fd0" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </marker>
          <radialGradient id="em-node" cx="35%" cy="30%" r="80%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.14" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
          </radialGradient>
          <filter id="em-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="3.2" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <pattern id="em-grid" width="26" height="26" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="#ffffff" fillOpacity="0.028" />
          </pattern>
          <style>{`
            .em-node { cursor: pointer; }
            .em-node .em-halo { opacity: 0; transition: opacity 140ms ease; }
            .em-node:hover .em-halo { opacity: 0.9; }
            .em-node:hover .em-core { filter: brightness(1.25); }
            .em-flow { stroke-dasharray: 5 7; animation: emFlow 0.9s linear infinite; }
            @keyframes emFlow { to { stroke-dashoffset: -24; } }
            .em-sel { animation: emSel 1.7s ease-in-out infinite; }
            @keyframes emSel { 0%,100% { opacity: .95; } 50% { opacity: .3; } }
            @media (prefers-reduced-motion: reduce) { .em-flow, .em-sel { animation: none; } }
          `}</style>
        </defs>
        <rect x={0} y={0} width={VBW} height={layout.height} fill="url(#em-grid)" />
        <rect x={0} y={0} width={VBW} height={layout.height} fill="transparent" onClick={() => setSelectedId(null)} />

        <g ref={gRef}>
          {/* Column headers */}
          {([["Hosts", COL.host], ["Services", COL.service], ["Containers", COL.container]] as const).map(([t, x]) => (
            <text key={t} x={x} y={22} textAnchor="middle" className="fill-gray-500" style={{ fontSize: 10.5, letterSpacing: 1.5, fontWeight: 600 }}>{t.toUpperCase()}</text>
          ))}

          {/* Edges */}
          {layout.edges.map((e, i) => {
            const a = layout.posById[e.a]; const b = layout.posById[e.b];
            if (!a || !b) return null;
            const touchesSel = selectedId != null && (e.a === selectedId || e.b === selectedId);
            const ra = nodeR(a), rb = nodeR(b);
            const mx = (a.x + b.x) / 2;
            const d = `M ${a.x + ra} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - rb - 3} ${b.y}`;
            return (
              <g key={i} opacity={selectedId && !touchesSel ? 0.18 : 1} style={{ transition: "opacity 140ms" }}>
                <path d={d} fill="none" stroke={touchesSel ? "#a6a8f0" : "#3b3a39"} strokeWidth={touchesSel ? 2.4 : 1.2} markerEnd="url(#em-arrow)" opacity={0.7} />
                {touchesSel && <path className="em-flow" d={d} fill="none" stroke="#c7c9ff" strokeWidth={1.8} strokeLinecap="round" opacity={0.9} />}
              </g>
            );
          })}

          {/* Nodes */}
          {layout.nodes.map((n) => {
            const r = nodeR(n);
            const color = nodeColor(n);
            const isSel = n.id === selectedId;
            const label =
              n.kind === "host" ? n.t.name : n.kind === "service" ? `:${n.s.port} ${n.s.service}` : n.c.name;
            const short = label.length > 16 ? label.slice(0, 15) + "…" : label;
            const dim = selectedId && !isSel && !layout.edges.some((e) => (e.a === selectedId && e.b === n.id) || (e.b === selectedId && e.a === n.id)) ? 0.28 : 1;
            const protectedFlag = n.kind === "service" && !!n.s.protectedListen;
            return (
              <g key={n.id} className="em-node" opacity={dim} style={{ transition: "opacity 120ms" }} onClick={(ev) => { ev.stopPropagation(); setSelectedId(n.id); }}>
                {isSel && <circle className="em-sel" cx={n.x} cy={n.y} r={r + 8} fill="none" stroke={color} strokeWidth={2.2} />}
                <circle className="em-halo" cx={n.x} cy={n.y} r={r + 6} fill={color} fillOpacity={0.14} />
                {protectedFlag && <circle cx={n.x} cy={n.y} r={r + 5} fill="none" stroke="#5bb98c" strokeWidth={1.4} strokeDasharray="2 3" opacity={0.8} />}
                <g filter="url(#em-glow)">
                  <circle className="em-core" cx={n.x} cy={n.y} r={r} fill={color} fillOpacity={isSel ? 0.28 : 0.16} stroke={color} strokeWidth={isSel ? 2.4 : 1.8} />
                </g>
                <circle cx={n.x} cy={n.y} r={r} fill="url(#em-node)" />
                <text x={n.x} y={n.y + (n.kind === "host" ? 6 : 5)} textAnchor="middle" style={{ fontSize: n.kind === "host" ? 18 : 14, pointerEvents: "none" }}>{ICON[n.kind]}</text>
                <text x={n.x} y={n.y + r + 14} textAnchor="middle" className="fill-gray-100" style={{ fontSize: 10.5, fontWeight: 600, pointerEvents: "none" }}>{short}</text>
                {n.kind === "host" && <text x={n.x} y={n.y + r + 25} textAnchor="middle" className="fill-gray-500" style={{ fontSize: 8.5, pointerEvents: "none" }}>{n.t.host}</text>}
                {n.kind === "service" && n.s.exposed === false && <text x={n.x} y={n.y + r + 25} textAnchor="middle" className="fill-gray-600" style={{ fontSize: 8, pointerEvents: "none" }}>internal</text>}
              </g>
            );
          })}
        </g>
      </svg>

      {selected && (
        <MapDetail
          node={selected}
          onClose={() => setSelectedId(null)}
          onDeepScan={onDeepScan}
          onSweep={(id) => sweep.mutate(id)}
          onProtect={(id, port) => protect.mutate({ id, port })}
          onIssueCert={(id, port) => cert.mutate({ id, port })}
          busy={{
            sweep: sweep.isPending,
            protect: protect.isPending ? protect.variables?.port : undefined,
            cert: cert.isPending ? cert.variables?.port : undefined,
          }}
        />
      )}
    </div>
  );
}

function Pqc({ status }: { status?: string }) {
  const c = pqcHex(status);
  const light = status === "hybrid" || status === "pqc_ready";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", borderRadius: 2, padding: "1px 6px", fontSize: 10.5, fontWeight: 600, color: light ? c : "#0b0b0b", background: light ? `${c}22` : c, border: `1px solid ${c}` }}>
      {(status ?? "unknown").replace(/_/g, " ")}
    </span>
  );
}

function MapDetail({ node, onClose, onDeepScan, onSweep, onProtect, onIssueCert, busy }: {
  node: MapNode;
  onClose: () => void;
  onDeepScan: (t: Target) => void;
  onSweep: (id: string) => void;
  onProtect: (id: string, port: number) => void;
  onIssueCert: (id: string, port: number) => void;
  busy: { sweep: boolean; protect?: number; cert?: number };
}) {
  const color = node.kind === "host" ? pqcHex(node.t.pqcStatus) : node.kind === "service" ? pqcHex(node.s.pqcStatus) : "#7a8699";
  const title = node.kind === "host" ? node.t.name : node.kind === "service" ? `:${node.s.port} ${node.s.service}` : node.c.name;
  const kindLabel = node.kind === "host" ? "Host" : node.kind === "service" ? "Network service" : "Container";

  return (
    <Box style={{
      position: "absolute", top: 10, right: 10, width: 288, maxHeight: "calc(100% - 20px)", zIndex: 20,
      display: "flex", flexDirection: "column",
      background: "color-mix(in srgb, var(--mantine-color-dark-7) 92%, transparent)",
      backdropFilter: "blur(6px)", border: `1px solid ${color}55`, borderRadius: 4, boxShadow: "0 12px 40px rgba(0,0,0,0.5)",
    }}>
      <Group justify="space-between" wrap="nowrap" px="sm" py={8} style={{ borderBottom: "1px solid var(--mantine-color-dark-5)" }}>
        <Group gap={8} wrap="nowrap" style={{ minWidth: 0 }}>
          <Box style={{ width: 26, height: 26, flexShrink: 0, display: "grid", placeItems: "center", borderRadius: 4, background: `${color}22`, border: `1px solid ${color}66` }}>
            <Text fz={15} style={{ lineHeight: 1 }}>{ICON[node.kind]}</Text>
          </Box>
          <Box style={{ minWidth: 0 }}>
            <Text fw={700} fz={13} c="gray.1" truncate>{title}</Text>
            <Text fz={9.5} tt="uppercase" c="dimmed" style={{ letterSpacing: "0.06em" }}>{kindLabel}</Text>
          </Box>
        </Group>
        <ActionIcon variant="subtle" color="gray" size="sm" radius={2} onClick={onClose} aria-label="Close">
          <svg width={14} height={14} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
        </ActionIcon>
      </Group>

      <ScrollArea.Autosize mah="calc(100vh - 300px)">
        <Stack gap="xs" p="sm">
          {node.kind === "host" && (
            <>
              <Text ff="monospace" fz={11} c="brand.4">{node.t.host}</Text>
              <Group gap={6}>
                <Pqc status={node.t.pqcStatus} />
                <Badge variant="outline" color="gray" radius={2} size="sm" tt="none">{node.t.kind}</Badge>
                <Badge variant="light" color="gray" radius={2} size="sm" tt="none">{node.t.environment}</Badge>
                {node.t.deepScanned && <Badge variant="light" color="teal" radius={2} size="sm" tt="none">deep-scanned</Badge>}
              </Group>
              {node.t.hostInfo && <Text ff="monospace" fz={10.5} c="teal.4">{node.t.hostInfo}</Text>}
              <Group gap={14}>
                <Text fz={11} c="dimmed">{node.t.exposedServices?.length ?? 0} services</Text>
                <Text fz={11} c="dimmed">{node.t.containers?.length ?? 0} containers</Text>
              </Group>
              {node.t.reachability?.length > 0 && <Text fz={10.5} c="dark.2">reachable via {node.t.reachability.join(", ")}</Text>}
              <Group gap="xs" mt={2}>
                <Button size="compact-xs" radius={2} variant="default" loading={busy.sweep} onClick={() => onSweep(node.t.id)}>Sweep</Button>
                <Button size="compact-xs" radius={2} color="teal" variant="light" onClick={() => onDeepScan(node.t)}>Connect &amp; inventory</Button>
              </Group>
            </>
          )}

          {node.kind === "service" && (
            <>
              <Text ff="monospace" fz={11} c="brand.4">{node.t.host}:{node.s.port}</Text>
              <Group gap={6}>
                <Pqc status={node.s.pqcStatus} />
                <Badge variant="outline" color={node.s.exposed === false ? "gray" : "violet"} radius={2} size="sm" tt="none">
                  {node.s.exposed === false ? "internal (loopback)" : "exposed"}
                </Badge>
                {node.s.source === "host" && <Badge variant="outline" color="teal" radius={2} size="sm" tt="none">host</Badge>}
              </Group>
              <Text fz={10.5} c="dimmed" style={{ lineHeight: 1.5 }}>{node.s.detail}</Text>
              {node.s.protectedListen && <Text ff="monospace" fz={10.5} c="signal.4">✓ protected via PQC overlay → {node.s.protectedListen}</Text>}
              {node.s.certId && <Text fz={10.5} c="cyan.4">✓ hybrid ML-DSA certificate issued</Text>}
              {fixable(node.s.pqcStatus) && (
                <>
                  <Divider my={2} />
                  <Group gap="xs">
                    <Tooltip label="Front this service with a hybrid-PQC listener" withArrow>
                      <Button size="compact-xs" radius={2} color="brand" variant="light" loading={busy.protect === node.s.port} onClick={() => onProtect(node.t.id, node.s.port)}>
                        {node.s.protectedListen ? "Re-protect" : "Protect with overlay"}
                      </Button>
                    </Tooltip>
                    <Tooltip label="Issue a hybrid ML-DSA certificate for this service" withArrow>
                      <Button size="compact-xs" radius={2} color="cyan" variant="light" loading={busy.cert === node.s.port} onClick={() => onIssueCert(node.t.id, node.s.port)}>
                        {node.s.certId ? "Re-issue cert" : "Issue PQC cert"}
                      </Button>
                    </Tooltip>
                  </Group>
                </>
              )}
            </>
          )}

          {node.kind === "container" && (
            <>
              <Text ff="monospace" fz={11} c="cyan.4">{node.c.image}</Text>
              <Text fz={10.5} c="dimmed">on host {node.t.host}</Text>
              {node.c.ports && (
                <>
                  <Divider label="Published ports" labelPosition="left" styles={{ label: { fontSize: 9.5, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--mantine-color-dark-2)" } }} />
                  <Text ff="monospace" fz={10.5} c="gray.3" style={{ lineHeight: 1.5 }}>{node.c.ports}</Text>
                </>
              )}
            </>
          )}
        </Stack>
      </ScrollArea.Autosize>
    </Box>
  );
}
