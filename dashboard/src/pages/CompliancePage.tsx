import { useQuery } from "@tanstack/react-query";
import { fetchCompliance, openAuthed, COMPLIANCE_REPORT_URL, EVIDENCE_PACK_URL } from "../api/client";
import type { FrameworkSummary, MigrationItem } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState, scoreText, scoreColor } from "../components/ui";

const priorityStyle: Record<string, string> = {
  P0: "bg-rose-500/15 text-rose-300",
  P1: "bg-orange-500/15 text-orange-300",
  P2: "bg-brand-500/15 text-brand-200",
};

function FrameworkCard({ fw }: { fw: FrameworkSummary }) {
  return (
    <Card className="p-4" hover>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-white">{fw.name}</h3>
            <span className="text-[10px] uppercase tracking-wider text-gray-500">{fw.authority}</span>
          </div>
          <p className="mt-1 line-clamp-2 text-xs text-gray-400">{fw.description}</p>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-semibold tabular-nums ${scoreText(fw.compliancePct)}`}>
            {Math.round(fw.compliancePct)}%
          </div>
          {fw.nearestDeadline && <div className="text-[10px] uppercase tracking-wider text-gray-500">by {fw.nearestDeadline}</div>}
        </div>
      </div>
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-surface-800">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${fw.compliancePct}%`, backgroundColor: scoreColor(fw.compliancePct) }} />
      </div>
      <div className="mt-3 flex items-center gap-4 text-[11px]">
        <span className="text-emerald-300">{fw.compliant} pass</span>
        <span className="text-amber-300">{fw.atRisk} at risk</span>
        <span className="text-rose-300">{fw.nonCompliant} fail</span>
      </div>
    </Card>
  );
}

function RoadmapRow({ item }: { item: MigrationItem }) {
  return (
    <tr className="align-top transition-colors hover:bg-white/5">
      <td className="px-4 py-3">
        <span className={`qw-chip ${priorityStyle[item.priority] ?? priorityStyle.P2}`}>{item.priority}</span>
      </td>
      <td className="px-4 py-3">
        <div className="text-sm font-medium text-white">{item.title}</div>
        <div className="mt-0.5 text-xs text-gray-500">{item.currentState}</div>
        <div className="mt-1 text-xs text-brand-300">&rarr; {item.targetState}</div>
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {item.frameworks.map((f) => (
            <span key={f} className="qw-chip bg-white/5 text-gray-400">{f}</span>
          ))}
        </div>
      </td>
      <td className="px-4 py-3 text-right text-sm font-semibold tabular-nums text-white">{item.affectedCount}</td>
      <td className="px-4 py-3 text-right text-sm tabular-nums text-gray-300">{item.deadlineYear}</td>
    </tr>
  );
}

export default function CompliancePage() {
  const { data, isLoading } = useQuery({
    queryKey: ["compliance"],
    queryFn: fetchCompliance,
  });

  if (isLoading) return <Spinner className="h-64" />;

  const frameworks = data?.frameworks ?? [];
  const items = data?.migrationItems ?? [];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Compliance & Migration"
        subtitle="PQC compliance mapped to CNSA 2.0, NIST IR 8547 and FIPS 203/204, with a prioritized roadmap"
        actions={
          <>
            <button onClick={() => openAuthed(EVIDENCE_PACK_URL, "quantawatch-evidence-pack.json")} className="qw-btn-ghost">
              Evidence Pack
            </button>
            <button onClick={() => openAuthed(COMPLIANCE_REPORT_URL)} className="qw-btn-primary">
              Export Report (PDF)
            </button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Stat label="CNSA 2.0 Compliance" value={`${Math.round(data?.overallCompliancePct ?? 100)}%`} accent="brand" />
        <Stat label="Compliant" value={data?.compliant ?? 0} accent="emerald" />
        <Stat label="At Risk" value={data?.atRisk ?? 0} accent="amber" />
        <Stat label="Non-Compliant" value={data?.nonCompliant ?? 0} accent={(data?.nonCompliant ?? 0) > 0 ? "rose" : "emerald"} />
      </div>

      <div>
        <div className="qw-eyebrow mb-2">Frameworks</div>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {frameworks.map((fw) => (
            <FrameworkCard key={fw.id} fw={fw} />
          ))}
        </div>
      </div>

      <Card>
        <div className="border-b border-white/10 px-4 py-2.5">
          <div className="qw-eyebrow">Prioritized Migration Roadmap</div>
        </div>
        {items.length === 0 ? (
          <EmptyState title="No migration actions required">
            Every assessed asset is post-quantum safe, or no scans have run yet.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="qw-eyebrow border-b border-white/10 text-left">
                  <th className="px-4 py-2.5 font-semibold">Priority</th>
                  <th className="px-4 py-2.5 font-semibold">Action</th>
                  <th className="px-4 py-2.5 text-right font-semibold">Assets</th>
                  <th className="px-4 py-2.5 text-right font-semibold">Deadline</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {items.map((item) => (
                  <RoadmapRow key={item.id} item={item} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
