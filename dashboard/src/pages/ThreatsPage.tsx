import { useQuery } from "@tanstack/react-query";
import { fetchThreats } from "../api/client";
import { Card, PageHeader, Stat, Spinner, EmptyState, SeverityBadge } from "../components/ui";

const borderColor: Record<string, string> = {
  critical: "border-l-rose-500",
  high: "border-l-orange-500",
  medium: "border-l-amber-500",
  low: "border-l-emerald-500",
};

export default function ThreatsPage() {
  const { data: threats, isLoading } = useQuery({
    queryKey: ["threats"],
    queryFn: fetchThreats,
  });

  const criticalCount = threats?.filter((t) => t.severity === "critical").length ?? 0;
  const highCount = threats?.filter((t) => t.severity === "high").length ?? 0;
  const blockedCount = threats?.filter((t) => t.blocked).length ?? 0;

  return (
    <div className="space-y-5">
      <PageHeader title="Threats & Violations" subtitle="Security events detected by the AI gateway" />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat label="Critical / High" value={criticalCount + highCount} accent={criticalCount + highCount > 0 ? "rose" : "emerald"} />
        <Stat label="Blocked" value={blockedCount} accent="emerald" />
        <Stat label="Total Events" value={threats?.length ?? 0} accent="brand" />
      </div>

      {isLoading ? (
        <Spinner className="py-16" />
      ) : !threats || threats.length === 0 ? (
        <Card>
          <EmptyState title="No threats detected">The gateway hasn't flagged any security events.</EmptyState>
        </Card>
      ) : (
        <div className="space-y-3">
          {threats.map((threat) => (
            <Card key={threat.id} className={`border-l-2 p-4 ${borderColor[threat.severity] ?? borderColor.low}`} hover>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-3">
                    <SeverityBadge severity={threat.severity} />
                    <span className="text-sm font-medium text-gray-300">{threat.threat_type.replace(/_/g, " ")}</span>
                    {threat.blocked ? (
                      <span className="qw-chip bg-emerald-400/10 text-emerald-300">blocked</span>
                    ) : (
                      <span className="qw-chip bg-amber-400/10 text-amber-300">allowed</span>
                    )}
                  </div>
                  <p className="text-sm leading-relaxed text-gray-400">{threat.description}</p>
                  <div className="flex items-center gap-4 text-xs text-gray-500">
                    <span>{new Date(threat.timestamp).toLocaleString()}</span>
                    <code className="font-mono text-gray-600">{threat.session_id}</code>
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
