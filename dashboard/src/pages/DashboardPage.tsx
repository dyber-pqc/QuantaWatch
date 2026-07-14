import { useQuery } from "@tanstack/react-query";
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
} from "recharts";
import { fetchStats } from "../api/client";
import { Card, PageHeader, Stat, Spinner } from "../components/ui";

const severityDot: Record<string, string> = {
  critical: "bg-rose-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-emerald-500",
};

const severityText: Record<string, string> = {
  critical: "text-rose-300",
  high: "text-orange-300",
  medium: "text-amber-300",
  low: "text-emerald-300",
};

export default function DashboardPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["stats"],
    queryFn: fetchStats,
  });

  if (isLoading || !stats) {
    return <Spinner className="h-64" />;
  }

  const chartData = stats.requests_per_minute.map((rpm, i) => ({
    minute: `${i + 1}m`,
    requests: rpm,
  }));

  return (
    <div className="space-y-5">
      <PageHeader title="Overview" subtitle="Real-time security monitoring for your AI gateway" />

      {/* Stats grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Stat label="Total Sessions" value={stats.total_sessions} accent="brand" sub="↑ 12% from last hour" />
        <Stat label="Total Requests" value={stats.total_requests} accent="violet" sub="↑ 8% from last hour" />
        <Stat label="Active Threats" value={stats.active_threats} accent={stats.active_threats > 0 ? "rose" : "emerald"} sub="Requires attention" />
        <Stat label="Audit Entries" value={stats.audit_entries} accent="emerald" sub="Chain verified" />
      </div>

      {/* Charts & threats row */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="p-4 xl:col-span-2" hover>
          <div className="qw-eyebrow mb-4">Request Rate (per minute)</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="requestGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7f85f5" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#7f85f5" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#3b3a39" vertical={false} />
                <XAxis dataKey="minute" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: "#3b3a39" }} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    background: "#2d2c2c",
                    border: "1px solid #3b3a39",
                    borderRadius: 12,
                    color: "#e2e8f0",
                    fontSize: 12,
                  }}
                  cursor={{ stroke: "#7f85f5", strokeOpacity: 0.3 }}
                />
                <Area type="monotone" dataKey="requests" stroke="#7f85f5" strokeWidth={2.5} fill="url(#requestGradient)" activeDot={{ r: 4, fill: "#7f85f5", stroke: "#2d2c2c", strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="p-4" hover>
          <div className="qw-eyebrow mb-4">Recent Threats</div>
          <div className="space-y-3">
            {stats.recent_threats.map((threat) => (
              <div key={threat.id} className="rounded border border-white/10 bg-surface-850/60 p-3 transition-colors hover:border-white/10">
                <div className="mb-1.5 flex items-center gap-2">
                  <span className={`inline-block h-2 w-2 rounded-full ${severityDot[threat.severity]}`} />
                  <span className={`text-xs font-semibold uppercase tracking-wider ${severityText[threat.severity]}`}>{threat.severity}</span>
                  <span className="ml-auto text-xs text-gray-500">{new Date(threat.timestamp).toLocaleTimeString()}</span>
                </div>
                <p className="text-xs leading-relaxed text-gray-400">{threat.threat_type.replace(/_/g, " ")}</p>
                <p className="mt-1 truncate font-mono text-xs text-gray-600">{threat.session_id}</p>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Threat distribution */}
      <Card className="p-4" hover>
        <div className="qw-eyebrow mb-4">Threat Distribution</div>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {(["critical", "high", "medium", "low"] as const).map((level) => (
            <div key={level} className="flex items-center gap-3 rounded border border-white/10 bg-surface-850/60 p-4">
              <span className={`h-3 w-3 rounded-full ${severityDot[level]}`} />
              <div>
                <p className="font-display text-xl font-bold text-white">{stats.threat_counts[level]}</p>
                <p className="text-xs capitalize text-gray-400">{level}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
