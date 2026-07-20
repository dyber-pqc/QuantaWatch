import { useQuery } from "@tanstack/react-query";
import { fetchSoc2 } from "../api/client";
import type { Soc2Control, Soc2Status } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const STATUS_META: Record<Soc2Status, { label: string; text: string; bg: string; ring: string; dot: string }> = {
  enforced: { label: "Enforced", text: "text-emerald-300", bg: "bg-emerald-500/10", ring: "ring-emerald-400/30", dot: "bg-emerald-400" },
  partial: { label: "Partial", text: "text-amber-300", bg: "bg-amber-500/10", ring: "ring-amber-400/30", dot: "bg-amber-400" },
  configurable: { label: "Configurable", text: "text-brand-200", bg: "bg-brand-500/10", ring: "ring-brand-400/30", dot: "bg-brand-400" },
  manual: { label: "Manual", text: "text-gray-400", bg: "bg-white/5", ring: "ring-white/15", dot: "bg-gray-500" },
};

const FAMILY: Record<string, string> = {
  CC6: "CC6 · Logical & Physical Access",
  CC7: "CC7 · System Monitoring",
  CC8: "CC8 · Change Management",
  A1: "A1 · Availability",
};

function StatusBadge({ status }: { status: Soc2Status }) {
  const m = STATUS_META[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold ring-1 ${m.bg} ${m.text} ${m.ring}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  );
}

function ControlRow({ c }: { c: Soc2Control }) {
  return (
    <div className="flex flex-col gap-2 px-4 py-3.5 sm:flex-row sm:items-start">
      <div className="flex w-full items-start gap-3 sm:w-auto sm:flex-1">
        <span className="mt-0.5 shrink-0 rounded bg-white/[0.05] px-1.5 py-0.5 font-mono text-[10.5px] font-semibold text-gray-400">
          {c.criteria}
        </span>
        <div className="min-w-0">
          <div className="text-[13.5px] font-semibold text-gray-100">{c.title}</div>
          <p className="mt-1 text-[12px] leading-relaxed text-gray-500">{c.evidence}</p>
          <div className="mt-1.5 font-mono text-[10.5px] text-gray-600">
            <span className="text-gray-500">verify:</span> {c.verify_at}
          </div>
        </div>
      </div>
      <div className="shrink-0 sm:pt-0.5">
        <StatusBadge status={c.status} />
      </div>
    </div>
  );
}

export default function Soc2Page() {
  const { data, isLoading, isError } = useQuery({ queryKey: ["soc2"], queryFn: fetchSoc2 });

  if (isLoading) return <Spinner className="h-64" />;
  if (isError || !data)
    return (
      <div className="space-y-5">
        <PageHeader title="SOC 2 Controls" subtitle="Technical controls mapped to the Trust Services Criteria" />
        <Card><EmptyState title="Controls report unavailable">Enable authentication to evaluate SOC 2 controls against your configuration.</EmptyState></Card>
      </div>
    );

  const s = data.summary;
  const families = ["CC6", "CC7", "CC8", "A1"];
  const grouped = families
    .map((f) => ({ family: f, controls: data.controls.filter((c) => c.criteria.startsWith(f)) }))
    .filter((g) => g.controls.length > 0);
  const coverage = s.total > 0 ? Math.round((s.enforced / s.total) * 100) : 0;

  return (
    <div className="space-y-5">
      <PageHeader
        title="SOC 2 Controls"
        subtitle="Technical controls mapped to the Trust Services Criteria — evaluated live against your running configuration"
      />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <Stat label="Enforced" value={s.enforced} accent="emerald" sub={`${coverage}% of controls`} />
        <Stat label="Partial" value={s.partial} accent="amber" />
        <Stat label="Configurable" value={s.configurable} accent="brand" sub="deployment choice" />
        <Stat label="Manual" value={s.manual} accent="violet" sub="org process" />
        <Stat label="Total" value={s.total} accent="brand" sub={data.framework.replace(" (Trust Services Criteria)", "")} />
      </div>

      <Card className="flex items-start gap-3 p-4">
        <svg className="mt-0.5 h-4 w-4 shrink-0 text-brand-300" fill="none" viewBox="0 0 24 24" strokeWidth={1.7} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z" />
        </svg>
        <p className="text-[12.5px] leading-relaxed text-gray-400">{data.note}</p>
      </Card>

      <div className="space-y-4">
        {grouped.map((g) => (
          <Card key={g.family}>
            <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
              <div className="qw-eyebrow">{FAMILY[g.family] ?? g.family}</div>
              <span className="text-[11px] text-gray-500">{g.controls.length} controls</span>
            </div>
            <div className="divide-y divide-white/[0.06]">
              {g.controls.map((c, i) => <ControlRow key={i} c={c} />)}
            </div>
          </Card>
        ))}
      </div>

      <p className="px-1 text-[11px] leading-relaxed text-gray-600">
        This is a technical control surface — not a SOC 2 certification, which requires an engagement with a licensed audit firm.
        Evidence for auditors lives in the ML-DSA-signed audit log (Monitor → Audit Log).
      </p>
    </div>
  );
}
