import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fetchPosture, fetchPostureHistory, fetchSlos, fetchSloHistory, triggerScan, openAuthed, CBOM_DOWNLOAD_URL } from "../api/client";
import type { PqcStatus } from "../api/types";
import {
  Card,
  PageHeader,
  ScoreRing,
  Spinner,
  EmptyState,
  PqcBadge,
  PQC_META,
  scoreColor,
  scoreText,
} from "../components/ui";

const STATUS_ORDER: PqcStatus[] = [
  "pqc_ready",
  "hybrid",
  "classical_secure",
  "classical_weak",
  "unknown",
];

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { value: number }[];
  label?: string | number;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const score = payload[0].value;
  return (
    <div className="rounded-lg border border-white/10 bg-surface-900/95 px-3 py-2 shadow-xl backdrop-blur">
      <div className="text-[11px] uppercase tracking-wider text-gray-500">
        {label ? new Date(label).toLocaleString() : ""}
      </div>
      <div className={`font-display text-lg font-bold ${scoreText(score)}`}>
        {Math.round(score)}
        <span className="ml-1 text-xs font-normal text-gray-500">/ 100</span>
      </div>
    </div>
  );
}

export default function PosturePage() {
  const queryClient = useQueryClient();
  const { data: posture, isLoading } = useQuery({
    queryKey: ["posture"],
    queryFn: fetchPosture,
  });

  const { data: history = [] } = useQuery({
    queryKey: ["posture-history"],
    queryFn: () => fetchPostureHistory(100),
  });

  const { data: slos } = useQuery({ queryKey: ["slos"], queryFn: fetchSlos });
  const { data: sloHistory } = useQuery({ queryKey: ["sloHistory"], queryFn: fetchSloHistory });

  const scanMutation = useMutation({
    mutationFn: () =>
      triggerScan([
        { target_type: "tls", address: "api.anthropic.com:443" },
        { target_type: "tls", address: "api.openai.com:443" },
      ]),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["posture"] });
      queryClient.invalidateQueries({ queryKey: ["posture-history"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  if (isLoading) {
    return <Spinner className="h-64" />;
  }

  const statusEntries = STATUS_ORDER.filter((s) => (posture?.byStatus?.[s] ?? 0) >= 0).map(
    (s) => [s, posture?.byStatus?.[s] ?? 0] as const,
  );
  const hasStatus = Object.values(posture?.byStatus ?? {}).some((n) => n > 0);

  const chartData = history.map((h) => ({
    timestamp: h.timestamp,
    overallScore: h.overallScore,
  }));

  return (
    <div className="space-y-5">
      <PageHeader
        title="Cryptographic Posture"
        subtitle="PQC readiness across your AI infrastructure"
        actions={
          <>
            <button onClick={() => openAuthed(CBOM_DOWNLOAD_URL, "quantawatch-cbom.json")} className="qw-btn-ghost">
              Download CBOM
            </button>
            <button
              onClick={() => scanMutation.mutate()}
              disabled={scanMutation.isPending}
              className="qw-btn-primary disabled:opacity-50"
            >
              {scanMutation.isPending ? "Scanning..." : "Run Scan"}
            </button>
          </>
        }
      />

      {scanMutation.isSuccess && (
        <div className="qw-fade-up flex items-center gap-2 rounded border border-emerald-400/30 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-300">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          Scan complete: {scanMutation.data.total_findings} findings across{" "}
          {scanMutation.data.scans_completed} scanners
        </div>
      )}

      {/* Hero row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="flex flex-col items-center justify-center p-4" hover>
          <div className="qw-eyebrow mb-3">Overall Score</div>
          <ScoreRing score={posture?.overallScore ?? 0} size={148} />
          <p className="mt-4 text-xs text-gray-500">
            {posture?.totalAssets ?? 0} crypto assets assessed
          </p>
        </Card>

        <Card className="p-4 lg:col-span-2" hover>
          <div className="qw-eyebrow mb-3">Status Distribution</div>
          {!hasStatus ? (
            <EmptyState title="No assets scanned yet">
              Click &quot;Run Scan&quot; to assess your provider endpoints and populate the
              distribution.
            </EmptyState>
          ) : (
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              {statusEntries.map(([status, count]) => {
                const m = PQC_META[status];
                return (
                  <div
                    key={status}
                    className={`rounded p-3 ring-1 ${m.bg} ${m.ring}`}
                  >
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${m.dot}`} />
                      <span className="text-xs uppercase tracking-wider text-gray-400">
                        {m.label}
                      </span>
                    </div>
                    <div className={`mt-3 text-2xl font-semibold ${m.text}`}>
                      {count}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      {/* Policy / SLOs */}
      {(slos?.slos.length ?? 0) > 0 && (
        <Card className="p-4" hover>
          <div className="mb-3 flex items-center justify-between">
            <div className="qw-eyebrow">Policy &amp; SLOs</div>
            <span className={`qw-chip ${slos?.allPass ? "bg-emerald-400/10 text-emerald-300" : slos?.gateBreach ? "bg-rose-500/15 text-rose-300" : "bg-amber-500/15 text-amber-300"}`}>
              {slos?.allPass ? "All passing" : slos?.gateBreach ? "CI gate: FAIL" : "At risk"}
            </span>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {slos?.slos.map((s) => (
              <div key={s.name} className="flex items-center justify-between gap-2 rounded border border-white/[0.06] bg-surface-850/60 px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate text-xs font-medium text-white">{s.name}</div>
                  <div className="text-[11px] text-gray-500">{s.metric} {s.operator === "gte" ? "≥" : "≤"} {s.threshold} · now {s.actual}</div>
                </div>
                <span className={`qw-chip shrink-0 ${s.pass ? "bg-emerald-400/10 text-emerald-300" : s.action === "fail" ? "bg-rose-500/15 text-rose-300" : "bg-amber-500/15 text-amber-300"}`}>
                  {s.pass ? "PASS" : s.action === "fail" ? "FAIL" : "WARN"}
                </span>
              </div>
            ))}
          </div>
          {(sloHistory?.history.length ?? 0) >= 2 && (
            <div className="mt-4 border-t border-white/[0.06] pt-3">
              <div className="mb-2 flex items-center justify-between">
                <div className="text-[11px] uppercase tracking-wide text-gray-500">Breach trend</div>
                <div className="text-[11px] text-gray-500">
                  last {sloHistory!.history.length} evaluations
                </div>
              </div>
              <div className="flex h-12 items-end gap-[3px]">
                {sloHistory!.history.map((h, i) => {
                  const h4 = Math.max(4, Math.round((h.failing / Math.max(1, h.total)) * 48));
                  const color = h.gateBreach
                    ? "bg-rose-500/70"
                    : h.failing > 0
                      ? "bg-amber-400/70"
                      : "bg-emerald-400/60";
                  return (
                    <div
                      key={i}
                      className={`flex-1 rounded-sm ${color}`}
                      style={{ height: `${h.failing === 0 ? 4 : h4}px` }}
                      title={`${new Date(h.timestamp).toLocaleString()} — ${h.failing}/${h.total} failing${h.gateBreach ? " · gate breach" : ""}`}
                    />
                  );
                })}
              </div>
            </div>
          )}
        </Card>
      )}

      {/* Score trend */}
      <Card className="p-4" hover>
        <div className="qw-eyebrow mb-3">Score Trend</div>
        {chartData.length < 2 ? (
          <p className="py-10 text-center text-sm text-gray-500">
            Not enough history yet. Scores are recorded as scans run over time.
          </p>
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="postureTrendFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#7f85f5" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#7f85f5" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#3b3a39" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="timestamp"
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "#3b3a39" }}
                  tickFormatter={(v) =>
                    new Date(v).toLocaleDateString(undefined, {
                      month: "short",
                      day: "numeric",
                    })
                  }
                  minTickGap={32}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "#3b3a39" }}
                  width={36}
                />
                <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#7f85f5", strokeOpacity: 0.3 }} />
                <Area
                  type="monotone"
                  dataKey="overallScore"
                  stroke="#7f85f5"
                  strokeWidth={2.5}
                  fill="url(#postureTrendFill)"
                  dot={false}
                  activeDot={{ r: 4, fill: "#7f85f5", stroke: "#2d2c2c", strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      {/* Score by category */}
      <Card className="p-4" hover>
        <div className="qw-eyebrow mb-3">Score by Category</div>
        {(posture?.byCategory ?? []).length === 0 ? (
          <p className="py-8 text-center text-sm text-gray-500">No category data yet.</p>
        ) : (
          <div className="space-y-5">
            {(posture?.byCategory ?? []).map((cat) => {
              const color = scoreColor(cat.score);
              return (
                <div key={cat.category}>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-sm font-medium text-gray-200">{cat.category}</span>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-gray-500">{cat.assetCount} assets</span>
                      <span
                        className={`w-10 text-right font-display text-sm font-bold ${scoreText(
                          cat.score,
                        )}`}
                      >
                        {Math.round(cat.score)}
                      </span>
                    </div>
                  </div>
                  <div className="h-2.5 w-full overflow-hidden rounded-full bg-white/5">
                    <div
                      className="h-full rounded-full transition-all duration-700 ease-out"
                      style={{
                        width: `${Math.max(2, cat.score)}%`,
                        backgroundColor: color,
                        boxShadow: `0 0 8px ${color}66`,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* AI provider posture */}
      <Card className="p-4" hover>
        <div className="qw-eyebrow mb-3">AI Provider Posture</div>
        {(posture?.byProvider ?? []).length === 0 ? (
          <EmptyState title="No provider data yet">
            Run a TLS scan to assess provider endpoints.
          </EmptyState>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {(posture?.byProvider ?? []).map((provider) => (
              <div
                key={provider.provider}
                className="rounded border border-white/10 bg-white/[0.02] p-3 transition-colors hover:border-brand-400/30 hover:bg-white/[0.04]"
              >
                <div className="mb-4 flex items-center justify-between gap-2">
                  <span className="font-display text-lg font-semibold capitalize text-white">
                    {provider.provider}
                  </span>
                  <PqcBadge status={provider.pqcStatus} />
                </div>
                <div className="flex items-end justify-between">
                  <span className="text-xs text-gray-500">
                    TLS {provider.tlsVersion ?? "?"}
                  </span>
                  <span
                    className={`text-2xl font-semibold ${scoreText(provider.score)}`}
                  >
                    {Math.round(provider.score)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
