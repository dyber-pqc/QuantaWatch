import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchFrameworks, fetchFramework } from "../api/client";
import type { FrameworkStatus } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const STATUS_META: Record<FrameworkStatus, { label: string; text: string; bg: string; ring: string; dot: string }> = {
  enforced: { label: "Enforced", text: "text-emerald-300", bg: "bg-emerald-500/10", ring: "ring-emerald-400/30", dot: "bg-emerald-400" },
  partial: { label: "Partial", text: "text-amber-300", bg: "bg-amber-500/10", ring: "ring-amber-400/30", dot: "bg-amber-400" },
  configurable: { label: "Configurable", text: "text-brand-200", bg: "bg-brand-500/10", ring: "ring-brand-400/30", dot: "bg-brand-400" },
  manual: { label: "Manual", text: "text-gray-400", bg: "bg-white/5", ring: "ring-white/15", dot: "bg-gray-500" },
};

function StatusBadge({ status }: { status: FrameworkStatus }) {
  const m = STATUS_META[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold ring-1 ${m.bg} ${m.text} ${m.ring}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />{m.label}
    </span>
  );
}

function Verdict({ verdict }: { verdict: "PASS" | "GAPS" }) {
  return verdict === "PASS" ? (
    <span className="rounded-md bg-emerald-500/15 px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide text-emerald-300 ring-1 ring-emerald-400/30">Pass</span>
  ) : (
    <span className="rounded-md bg-amber-500/15 px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide text-amber-300 ring-1 ring-amber-400/30">Gaps</span>
  );
}

export default function FrameworksPage() {
  const { data, isLoading, isError } = useQuery({ queryKey: ["frameworks"], queryFn: fetchFrameworks });
  const [selected, setSelected] = useState<string | null>(null);
  const activeId = selected ?? data?.frameworks[0]?.id ?? null;
  const { data: detail } = useQuery({
    queryKey: ["framework", activeId],
    queryFn: () => fetchFramework(activeId!),
    enabled: !!activeId,
  });

  if (isLoading) return <Spinner className="h-64" />;
  if (isError || !data)
    return (
      <div className="space-y-5">
        <PageHeader title="Compliance Frameworks" subtitle="Controls evaluated live against your configuration" />
        <Card><EmptyState title="Frameworks unavailable">Enable authentication to evaluate compliance controls.</EmptyState></Card>
      </div>
    );

  const s = detail?.summary;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Compliance Frameworks"
        subtitle="CNSA 2.0 · NIST SP 800-53 · PCI-DSS · FedRAMP — every control evaluated live against the running config, backed by enforcement rather than a questionnaire"
      />

      {/* Framework picker */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {data.frameworks.map((f) => {
          const active = f.id === activeId;
          return (
            <button
              key={f.id}
              onClick={() => setSelected(f.id)}
              className={`rounded-lg border p-3 text-left transition-colors ${active ? "border-brand-400/50 bg-brand-500/10" : "border-white/[0.07] bg-surface-900 hover:bg-white/[0.03]"}`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className={`text-[13px] font-semibold ${active ? "text-brand-100" : "text-gray-200"}`}>{f.name}</span>
                <Verdict verdict={f.verdict} />
              </div>
              <div className="mt-2 flex items-center gap-1.5">
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                  <div className="h-full rounded-full bg-emerald-400/70" style={{ width: `${(f.summary.enforced / f.summary.total) * 100}%` }} />
                </div>
                <span className="text-[10.5px] tabular-nums text-gray-500">{f.summary.enforced}/{f.summary.total}</span>
              </div>
            </button>
          );
        })}
      </div>

      {detail && (
        <>
          <div className="flex items-baseline justify-between px-1">
            <div>
              <h2 className="text-lg font-semibold text-white">{detail.name}</h2>
              <p className="text-[12.5px] text-gray-500">{detail.description}</p>
            </div>
            <Verdict verdict={detail.verdict} />
          </div>

          {s && (
            <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
              <Stat label="Enforced" value={s.enforced} accent="emerald" />
              <Stat label="Partial" value={s.partial} accent="amber" />
              <Stat label="Configurable" value={s.configurable} accent="brand" />
              <Stat label="Manual" value={s.manual} accent="violet" />
              <Stat label="Gaps" value={s.gaps} accent={s.gaps > 0 ? "rose" : "emerald"} sub="required, not enforced" />
            </div>
          )}

          <Card>
            <div className="border-b border-white/10 px-4 py-2.5"><div className="qw-eyebrow">Controls</div></div>
            <div className="divide-y divide-white/[0.06]">
              {detail.controls.map((ctl) => {
                const gap = ctl.required && ctl.status !== "enforced";
                return (
                  <div key={ctl.id} className="flex flex-col gap-2 px-4 py-3.5 sm:flex-row sm:items-start" style={gap ? { boxShadow: "inset 3px 0 0 var(--color-threat-medium)" } : undefined}>
                    <div className="flex w-full items-start gap-3 sm:flex-1">
                      <span className="mt-0.5 shrink-0 rounded bg-white/[0.05] px-1.5 py-0.5 font-mono text-[10.5px] font-semibold text-gray-400">{ctl.id}</span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[13.5px] font-semibold text-gray-100">{ctl.title}</span>
                          {ctl.required && <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-gray-500">required</span>}
                        </div>
                        <p className="mt-1 text-[12px] leading-relaxed text-gray-500">{ctl.evidence}</p>
                        <div className="mt-1.5 font-mono text-[10.5px] text-gray-600"><span className="text-gray-500">verify:</span> {ctl.verify_at}</div>
                      </div>
                    </div>
                    <div className="shrink-0 sm:pt-0.5"><StatusBadge status={ctl.status} /></div>
                  </div>
                );
              })}
            </div>
          </Card>
        </>
      )}

      <p className="px-1 text-[11px] leading-relaxed text-gray-600">
        {data.note} Gate any framework in CI with <span className="font-mono text-gray-400">GET /api/frameworks/&#123;id&#125;?gate=1</span> — it returns HTTP 422 while any required control is unmet.
      </p>
    </div>
  );
}
