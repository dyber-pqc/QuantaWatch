import { useMemo, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { fetchAttackPaths, fetchAttackPathTimeline, simulateAttackPaths, fetchIntegrations, remediateAttackPath, openAuthed, BOARD_REPORT_URL } from "../api/client";
import type { AttackPath, GraphNode, GraphNodeType, SimulateResponse, RemediationTicket } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState, SeverityBadge, PqcBadge } from "../components/ui";

const COL_INDEX: Record<GraphNodeType, number> = {
  identity: 0, data: 1, agent: 2, provider: 3, certificate: 4, dependency: 4, asset: 4,
};
const COL_X = [70, 285, 500, 700, 895];
const COL_TITLE = ["Identities", "Data", "Agents", "Providers", "Assets"];
const NODE_ICON: Record<GraphNodeType, string> = {
  identity: "🔑", data: "🗄", agent: "🤖", provider: "☁", certificate: "🔏", dependency: "📦", asset: "🌐",
};

function riskColor(risk: number): string {
  if (risk >= 70) return "#e76a6e";
  if (risk >= 45) return "#f7894a";
  if (risk >= 20) return "#f2c744";
  return "#5bb98c";
}

function Graph({ nodes, edges, activeIds }: { nodes: GraphNode[]; edges: { source: string; target: string; observed: boolean }[]; activeIds: Set<string> | null }) {
  const layout = useMemo(() => {
    const cols: GraphNode[][] = [[], [], [], [], []];
    nodes.forEach((n) => cols[COL_INDEX[n.type]]?.push(n));
    const rowH = 72;
    const height = Math.max(1, ...cols.map((c) => c.length)) * rowH + 44;
    const pos: Record<string, { x: number; y: number; node: GraphNode }> = {};
    cols.forEach((arr, ci) => {
      const startY = (height - arr.length * rowH) / 2 + rowH / 2 + 10;
      arr.forEach((n, i) => { pos[n.id] = { x: COL_X[ci], y: startY + i * rowH, node: n }; });
    });
    return { pos, height };
  }, [nodes]);

  const dim = (id: string) => (activeIds && !activeIds.has(id) ? 0.16 : 1);

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 980 ${layout.height}`} className="w-full" style={{ minWidth: 820 }}>
        {COL_X.map((x, i) => (
          <text key={i} x={x} y={16} textAnchor="middle" className="fill-gray-500" style={{ fontSize: 10, letterSpacing: 1 }}>
            {COL_TITLE[i].toUpperCase()}
          </text>
        ))}
        {edges.map((e, i) => {
          const a = layout.pos[e.source]; const b = layout.pos[e.target];
          if (!a || !b) return null;
          const active = activeIds ? activeIds.has(e.source) && activeIds.has(e.target) : false;
          const mx = (a.x + b.x) / 2;
          return (
            <path key={i} d={`M ${a.x + 13} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - 13} ${b.y}`} fill="none"
              stroke={active ? "#8b8ef0" : e.observed ? "#5b8def" : "#3b3a39"}
              strokeWidth={active ? 2.5 : e.observed ? 1.8 : 1.1}
              strokeDasharray={e.observed ? "0" : "3 2"}
              opacity={activeIds && !active ? 0.12 : 1} />
          );
        })}
        {Object.values(layout.pos).map(({ x, y, node }) => {
          const r = 11 + (node.risk / 100) * 9;
          const color = node.type === "data" ? "#c084fc" : node.type === "agent" ? "#8b8ef0" : node.type === "identity" ? "#f0abfc" : riskColor(node.risk);
          return (
            <g key={node.id} opacity={dim(node.id)}>
              {node.observed && <circle cx={x} cy={y} r={r + 4} fill="none" stroke="#5b8def" strokeWidth={1} opacity={0.5} />}
              <circle cx={x} cy={y} r={r} fill={color} fillOpacity={0.18} stroke={color} strokeWidth={1.6} />
              <text x={x} y={y + 4} textAnchor="middle" style={{ fontSize: 12 }}>{NODE_ICON[node.type]}</text>
              <text x={x} y={y + r + 12} textAnchor="middle" className="fill-gray-200" style={{ fontSize: 10.5, fontWeight: 600 }}>
                {node.label.length > 16 ? node.label.slice(0, 15) + "…" : node.label}
              </text>
              <text x={x} y={y + r + 23} textAnchor="middle" className="fill-gray-500" style={{ fontSize: 8.5 }}>
                {node.blastRadius > 0 ? `blast ${node.blastRadius}` : node.sublabel.slice(0, 20)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

const KIND_LABEL: Record<AttackPath["kind"], { label: string; color: string }> = {
  "data-exposure": { label: "Data Exposure", color: "bg-rose-500/15 text-rose-300" },
  "access-risk": { label: "Access Risk", color: "bg-amber-500/15 text-amber-300" },
  "external-asset": { label: "External Asset", color: "bg-brand-500/15 text-brand-200" },
};

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
      className="cursor-default border-l-2 px-4 py-3 transition-colors hover:bg-white/[0.03]" style={{ borderLeftColor: riskColor(path.score) }}>
      <div className="flex items-center gap-2">
        <SeverityBadge severity={path.severity} />
        <span className={`qw-chip ${kind.color}`}>{kind.label}</span>
        {path.hndl && <span className="qw-chip bg-quantum-500/15 text-quantum-300">HNDL</span>}
        {path.observed && <span className="qw-chip bg-[#5b8def]/20 text-[#9bc0ff]">● observed · {path.requestCount}</span>}
        <span className="ml-auto text-sm font-semibold tabular-nums text-white">{path.score}</span>
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs">
        <span className="rounded bg-quantum-500/10 px-1.5 py-0.5 text-quantum-300">{path.dataClass}</span>
        <span className="text-gray-600">→</span>
        <span className="rounded bg-brand-500/10 px-1.5 py-0.5 text-brand-200">{path.agent}</span>
        {path.provider !== "—" && (<><span className="text-gray-600">→</span><span className="rounded bg-white/5 px-1.5 py-0.5 text-gray-200">{path.provider}</span></>)}
        {path.channelPqc && path.provider !== "—" && <PqcBadge status={path.channelPqc} />}
      </div>
      <p className="mt-1.5 text-xs leading-relaxed text-gray-500">{path.recommendation}</p>
      <div className="mt-2">
        {ticket ? (
          <a href={ticket.externalUrl} target="_blank" rel="noreferrer" className="qw-chip bg-emerald-400/10 text-emerald-300 ring-1 ring-emerald-400/30">{ticket.externalId} ↗</a>
        ) : (
          <div className="relative inline-block">
            <button
              onClick={() => remediable.length && setOpen((v) => !v)}
              disabled={!remediable.length || mut.isPending}
              title={remediable.length ? "" : "Configure Jira or Linear to auto-remediate"}
              className={`qw-chip ${remediable.length ? "bg-brand-400/10 text-brand-200 ring-1 ring-brand-400/30 hover:bg-brand-400/20" : "cursor-not-allowed bg-white/5 text-gray-600"}`}>
              {mut.isPending ? "Creating…" : "⚡ Auto-remediate"}
            </button>
            {open && (
              <div className="absolute left-0 z-20 mt-1 w-44 overflow-hidden rounded border border-white/10 bg-surface-900/95 shadow-2xl backdrop-blur">
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
        subtitle="Crypto security graph — observed harvest-now-decrypt-later exposure across identities, agents, providers & assets"
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
              <div className="mb-2 flex items-center justify-between">
                <div className="qw-eyebrow">Cryptographic Security Graph {sim && <span className="text-quantum-300">(simulated)</span>}</div>
                {activePath && <div className="text-[11px] text-gray-500">{activePath.title}</div>}
              </div>
              <Graph nodes={live?.nodes ?? []} edges={live?.edges ?? []} activeIds={activeIds} />
              <div className="mt-2 flex flex-wrap gap-3 text-[10px] text-gray-500">
                <span>◯ ring = observed in live traffic</span>
                <span>— solid edge = observed flow</span>
                <span>node size = risk · label = blast radius</span>
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
            <div className="border-b border-white/10 px-4 py-2.5"><div className="qw-eyebrow">Toxic Combinations</div></div>
            <div className="max-h-[620px] divide-y divide-white/5 overflow-y-auto">
              {paths.map((p) => <PathRow key={p.id} path={p} onHover={setHovered} remediable={remediable} />)}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
