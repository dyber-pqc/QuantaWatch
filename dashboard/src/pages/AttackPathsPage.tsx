import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { fetchAttackPaths, fetchAttackPathTimeline, simulateAttackPaths, fetchIntegrations, remediateAttackPath, openAuthed, BOARD_REPORT_URL } from "../api/client";
import type { AttackPath, GraphNode, GraphNodeType, SimulateResponse, RemediationTicket, KillChainStage } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState, SeverityBadge, PqcBadge } from "../components/ui";

const COL_INDEX: Record<GraphNodeType, number> = {
  identity: 0, data: 1, agent: 2, provider: 3, certificate: 4, dependency: 4, asset: 4,
};
const COL_X = [80, 305, 530, 745, 930];
const COL_TITLE = ["Identities", "Data", "Agents", "Providers", "Assets"];
const NODE_ICON: Record<GraphNodeType, string> = {
  identity: "🔑", data: "🗄", agent: "🤖", provider: "☁", certificate: "🔏", dependency: "📦", asset: "🌐",
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
  return riskColor(node.risk);
}

function Graph({ nodes, edges, activeIds }: { nodes: GraphNode[]; edges: { source: string; target: string; observed: boolean }[]; activeIds: Set<string> | null }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [view, setView] = useState({ k: 1, tx: 0, ty: 0 });
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

  const toSvg = (clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const pt = svg.createSVGPoint();
    pt.x = clientX; pt.y = clientY;
    const ctm = svg.getScreenCTM();
    if (!ctm) return { x: 0, y: 0 };
    const p = pt.matrixTransform(ctm.inverse());
    return { x: p.x, y: p.y };
  };

  // Native, NON-passive wheel listener. React binds onWheel as passive, so
  // preventDefault() there is ignored and the page scrolls/zooms underneath —
  // which reads as the page freezing/reloading. Attaching manually with
  // { passive: false } lets us actually stop the browser's default.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    let raf = 0;
    const onWheelNative = (e: WheelEvent) => {
      e.preventDefault();
      if (raf) return; // coalesce to one update per frame
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const ctm = svg.getScreenCTM();
      if (!ctm) return;
      const p = pt.matrixTransform(ctm.inverse());
      const factor = Math.exp(-e.deltaY * 0.0015);
      raf = requestAnimationFrame(() => {
        raf = 0;
        setView((v) => {
          const nk = clamp(v.k * factor, 0.5, 4);
          const r = nk / v.k;
          return { k: nk, tx: p.x - (p.x - v.tx) * r, ty: p.y - (p.y - v.ty) * r };
        });
      });
    };
    svg.addEventListener("wheel", onWheelNative, { passive: false });
    return () => {
      svg.removeEventListener("wheel", onWheelNative);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  const onPointerDown = (e: React.PointerEvent) => {
    (e.target as Element).setPointerCapture?.(e.pointerId);
    const { x, y } = toSvg(e.clientX, e.clientY);
    pan.current = { x, y, tx: view.tx, ty: view.ty };
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!pan.current) return;
    const { x, y } = toSvg(e.clientX, e.clientY);
    setView((v) => ({ ...v, tx: pan.current!.tx + (x - pan.current!.x), ty: pan.current!.ty + (y - pan.current!.y) }));
  };
  const endPan = () => { pan.current = null; };
  const zoomBy = (f: number) => setView((v) => {
    const nk = clamp(v.k * f, 0.5, 4);
    const cx = VBW / 2, cy = layout.height / 2, r = nk / v.k;
    return { k: nk, tx: cx - (cx - v.tx) * r, ty: cy - (cy - v.ty) * r };
  });
  const reset = () => setView({ k: 1, tx: 0, ty: 0 });

  const dim = (id: string) => (activeIds && !activeIds.has(id) ? 0.14 : 1);

  return (
    <div className="relative overflow-hidden rounded-lg border border-white/[0.06] bg-gradient-to-b from-surface-950/60 to-surface-900/30">
      {/* Zoom controls */}
      <div className="absolute right-3 top-3 z-10 flex flex-col gap-1 rounded-lg border border-white/10 bg-surface-900/80 p-1 backdrop-blur">
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
      <div className="pointer-events-none absolute left-3 top-3 z-10 rounded bg-surface-900/70 px-2 py-0.5 text-[10px] text-gray-500 backdrop-blur">
        {Math.round(view.k * 100)}% · scroll to zoom · drag to pan
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${VBW} ${layout.height}`}
        className="w-full cursor-grab touch-none active:cursor-grabbing"
        style={{ height: 480 }}
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
        </defs>

        <g transform={`translate(${view.tx} ${view.ty}) scale(${view.k})`}>
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
            const faded = activeIds && !active;
            const mx = (a.x + b.x) / 2;
            const ra = 15 + (a.node.risk / 100) * 9;
            const rb = 15 + (b.node.risk / 100) * 9;
            return (
              <path
                key={i}
                d={`M ${a.x + ra} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - rb - 3} ${b.y}`}
                fill="none"
                stroke={active ? "#a6a8f0" : e.observed ? "#5b8def" : "#3b3a39"}
                strokeWidth={active ? 2.6 : e.observed ? 1.8 : 1.1}
                strokeDasharray={e.observed ? "0" : "4 3"}
                markerEnd={faded ? "url(#ap-arrow-dim)" : "url(#ap-arrow)"}
                opacity={faded ? 0.1 : e.observed ? 0.9 : 0.55}
              />
            );
          })}

          {/* Nodes */}
          {Object.values(layout.pos).map(({ x, y, node }) => {
            const r = 15 + (node.risk / 100) * 9;
            const color = nodeColor(node);
            const label = node.label.length > 15 ? node.label.slice(0, 14) + "…" : node.label;
            const sub = node.blastRadius > 0 ? `blast ${node.blastRadius}` : node.sublabel.slice(0, 18);
            return (
              <g key={node.id} opacity={dim(node.id)} style={{ transition: "opacity 120ms" }}>
                {node.observed && (
                  <circle cx={x} cy={y} r={r + 5.5} fill="none" stroke="#5b8def" strokeWidth={1.3} strokeDasharray="2 3" opacity={0.55} />
                )}
                <circle cx={x} cy={y} r={r} fill={color} fillOpacity={0.16} stroke={color} strokeWidth={1.8} />
                <circle cx={x} cy={y} r={r} fill="url(#ap-node)" />
                <text x={x} y={y + 5} textAnchor="middle" style={{ fontSize: 15 }}>{NODE_ICON[node.type]}</text>
                {/* risk pill */}
                <g transform={`translate(${x + r - 2} ${y - r + 1})`}>
                  <circle r={7} fill="#1f1f1f" stroke={color} strokeWidth={1.2} />
                  <text textAnchor="middle" y={2.6} style={{ fontSize: 7.5, fontWeight: 700 }} fill={color}>{Math.round(node.risk)}</text>
                </g>
                <text x={x} y={y + r + 15} textAnchor="middle" className="fill-gray-100" style={{ fontSize: 11, fontWeight: 600 }}>{label}</text>
                <text x={x} y={y + r + 27} textAnchor="middle" className="fill-gray-500" style={{ fontSize: 8.5 }}>{sub}</text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

const KIND_LABEL: Record<AttackPath["kind"], { label: string; color: string }> = {
  "data-exposure": { label: "Data Exposure", color: "bg-rose-500/15 text-rose-300" },
  "access-risk": { label: "Access Risk", color: "bg-amber-500/15 text-amber-300" },
  "external-asset": { label: "External Asset", color: "bg-brand-500/15 text-brand-200" },
};

function ScoreBox({ score }: { score: number }) {
  const c = riskColor(score);
  return (
    <div className="flex h-12 w-12 shrink-0 flex-col items-center justify-center rounded-lg ring-1"
      style={{ background: `${c}1f`, boxShadow: `inset 0 0 0 1px ${c}55` }}>
      <span className="text-[15px] font-bold leading-none tabular-nums" style={{ color: c }}>{Math.round(score)}</span>
      <span className="mt-0.5 text-[7.5px] font-semibold uppercase tracking-wide text-gray-500">risk</span>
    </div>
  );
}

function Pill({ children, tone }: { children: React.ReactNode; tone: "data" | "agent" | "provider" }) {
  const cls = tone === "data" ? "bg-quantum-500/12 text-quantum-200 ring-quantum-400/20"
    : tone === "agent" ? "bg-brand-500/12 text-brand-200 ring-brand-400/20"
    : "bg-white/[0.06] text-gray-200 ring-white/10";
  return <span className={`inline-flex items-center rounded-md px-2 py-1 text-[11.5px] font-semibold ring-1 ${cls}`}>{children}</span>;
}
function Arrow() {
  return <svg className="h-3 w-3 shrink-0 text-gray-600" fill="none" viewBox="0 0 24 24" strokeWidth={2.2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" /></svg>;
}

const KC_STATUS: Record<KillChainStage["status"], { dot: string; text: string; ring: string }> = {
  active: { dot: "bg-rose-400", text: "text-rose-300", ring: "ring-rose-400/30" },
  feasible: { dot: "bg-amber-400", text: "text-amber-300", ring: "ring-amber-400/30" },
  pending: { dot: "bg-violet-400", text: "text-violet-300", ring: "ring-violet-400/30" },
  blocked: { dot: "bg-emerald-400", text: "text-emerald-300", ring: "ring-emerald-400/30" },
  na: { dot: "bg-gray-600", text: "text-gray-500", ring: "ring-white/10" },
};

function KillChain({ stages }: { stages: KillChainStage[] }) {
  return (
    <div className="mt-2.5 rounded-md border border-white/[0.06] bg-black/20 p-2">
      <div className="mb-1.5 flex items-center gap-1.5">
        <span className="text-[9px] font-semibold uppercase tracking-wider text-gray-500">Crypto kill-chain</span>
      </div>
      <div className="flex items-stretch gap-1">
        {stages.map((s, i) => {
          const m = KC_STATUS[s.status];
          return (
            <div key={s.key} className="flex flex-1 items-center gap-1" title={`${s.label}: ${s.detail} (${s.status})`}>
              <div className={`flex-1 rounded px-1.5 py-1 ring-1 ${m.ring} bg-white/[0.02]`}>
                <div className="flex items-center gap-1">
                  <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
                  <span className={`truncate text-[9.5px] font-semibold ${m.text}`}>{s.label}</span>
                </div>
              </div>
              {i < stages.length - 1 && <span className="text-[9px] text-gray-700">→</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ExploitChip({ value }: { value: number }) {
  const c = value >= 60 ? "#e76a6e" : value >= 30 ? "#f7894a" : value >= 10 ? "#f2c744" : "#5bb98c";
  return (
    <span className="qw-chip" style={{ background: `${c}1f`, color: c }} title="Exploitability — how realistically this path can be executed (reachability × data value × channel weakness)">
      exploit {Math.round(value)}
    </span>
  );
}

function PathRow({ path, onHover, remediable }: { path: AttackPath; onHover: (id: string | null) => void; remediable: { id: string; displayName: string }[] }) {
  const kind = KIND_LABEL[path.kind];
  const [open, setOpen] = useState(false);
  const [ticket, setTicket] = useState<RemediationTicket | null>(null);
  const mut = useMutation({
    mutationFn: (integrationId: string) => remediateAttackPath(path.id, { integrationId }),
    onSuccess: (t) => { setTicket(t); setOpen(false); },
  });
  return (
    <div onMouseEnter={() => onHover(path.id)} onMouseLeave={() => onHover(null)}
      className="cursor-default border-l-2 px-4 py-3.5 transition-colors hover:bg-white/[0.025]" style={{ borderLeftColor: riskColor(path.score) }}>
      <div className="flex items-start gap-3">
        <ScoreBox score={path.score} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={path.severity} />
            <span className={`qw-chip ${kind.color}`}>{kind.label}</span>
            {path.hndl && <span className="qw-chip bg-quantum-500/15 text-quantum-300" title="Harvest-now, decrypt-later">HNDL</span>}
            {path.observed && (
              <span className="qw-chip bg-[#5b8def]/15 text-[#9bc0ff] ring-1 ring-[#5b8def]/25">
                <span className="mr-0.5 inline-block h-1.5 w-1.5 rounded-full bg-[#5b8def]" />observed · {path.requestCount}
              </span>
            )}
            {typeof path.exploitability === "number" && <ExploitChip value={path.exploitability} />}
          </div>

          {/* Chain flow */}
          <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
            <Pill tone="data">{path.dataClass}</Pill>
            <Arrow />
            <Pill tone="agent">{path.agent}</Pill>
            {path.provider !== "—" && (<><Arrow /><Pill tone="provider">{path.provider}</Pill></>)}
            {path.channelPqc && path.provider !== "—" && <PqcBadge status={path.channelPqc} />}
          </div>

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
                  className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11.5px] font-semibold transition-colors ${remediable.length ? "bg-brand-500/15 text-brand-200 ring-1 ring-brand-400/30 hover:bg-brand-500/25" : "cursor-not-allowed bg-white/[0.04] text-gray-600"}`}>
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

export default function AttackPathsPage() {
  const { data, isLoading } = useQuery({ queryKey: ["attack-paths"], queryFn: fetchAttackPaths });
  const { data: timeline } = useQuery({ queryKey: ["attack-path-timeline"], queryFn: fetchAttackPathTimeline });
  const { data: integrationsData } = useQuery({ queryKey: ["integrations"], queryFn: fetchIntegrations });
  const [hovered, setHovered] = useState<string | null>(null);
  const [sim, setSim] = useState<SimulateResponse | null>(null);
  const [hardened, setHardened] = useState<Set<string>>(new Set());
  const [simBusy, setSimBusy] = useState(false);

  if (isLoading) return <Spinner className="h-64" />;

  const live = sim ?? data;
  const paths = live?.paths ?? [];
  const s = live?.summary;
  const activePath = paths.find((p) => p.id === hovered);
  const activeIds = activePath ? new Set(activePath.nodeIds) : null;

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
              <Graph nodes={live?.nodes ?? []} edges={live?.edges ?? []} activeIds={activeIds} />
              <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[10px] text-gray-500">
                <span className="flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full border border-dashed border-[#5b8def]" /> observed in live traffic</span>
                <span className="flex items-center gap-1"><span className="inline-block h-0 w-4 border-t-2 border-[#5b8def]" /> observed flow</span>
                <span className="flex items-center gap-1"><span className="inline-block h-0 w-4 border-t border-dashed border-gray-600" /> possible flow</span>
                <span>node size &amp; ring number = risk</span>
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
              <div className="qw-eyebrow">Toxic Combinations</div>
              <span className="text-[11px] text-gray-500">{paths.length}</span>
            </div>
            <div className="max-h-[640px] divide-y divide-white/5 overflow-y-auto">
              {paths.map((p) => <PathRow key={p.id} path={p} onHover={setHovered} remediable={remediable} />)}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
