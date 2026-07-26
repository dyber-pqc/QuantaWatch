import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { fetchAuditEntries, verifyAuditChain } from "../api/client";
import type { AuditVerifyResult } from "../api/types";
import { Card, PageHeader, Spinner, EmptyState } from "../components/ui";

const eventTypeStyles: Record<string, string> = {
  request: "bg-brand-400/10 text-brand-200",
  response: "bg-emerald-400/10 text-emerald-300",
  threat_detected: "bg-rose-400/10 text-rose-300",
  session_start: "bg-quantum-500/15 text-quantum-300",
  session_end: "bg-slate-400/10 text-slate-300",
  policy_check: "bg-amber-400/10 text-amber-300",
};

export default function AuditPage() {
  const [limit, setLimit] = useState(25);

  const { data: entries, isLoading } = useQuery({
    queryKey: ["audit", limit],
    queryFn: () => fetchAuditEntries(limit),
  });

  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);

  const verifyMutation = useMutation({
    mutationFn: verifyAuditChain,
    onSuccess: (data) => setVerifyResult(data),
  });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Audit Log"
        subtitle="Tamper-evident, ML-DSA-signed hash chain of all gateway events"
        actions={
          <>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="rounded border border-white/10 bg-surface-850 px-3 py-2.5 text-sm text-gray-300 outline-none focus:border-brand-400/50 focus:ring-2 focus:ring-brand-400/20"
            >
              <option value={10}>Last 10</option>
              <option value={25}>Last 25</option>
              <option value={50}>Last 50</option>
              <option value={100}>Last 100</option>
            </select>
            <button onClick={() => verifyMutation.mutate()} disabled={verifyMutation.isPending} className="qw-btn-primary">
              {verifyMutation.isPending ? "Verifying…" : "Verify Chain"}
            </button>
          </>
        }
      />

      {verifyResult && (
        <div className={`qw-fade-up rounded border p-3 ${verifyResult.valid ? "border-emerald-400/30 bg-emerald-400/10" : "border-rose-400/30 bg-rose-400/10"}`}>
          <div className="flex items-center gap-3">
            <span className={`flex h-7 w-7 items-center justify-center rounded-full ${verifyResult.valid ? "bg-emerald-400/20" : "bg-rose-400/20"}`}>
              <svg className={`h-4 w-4 ${verifyResult.valid ? "text-emerald-300" : "text-rose-300"}`} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                {verifyResult.valid ? (
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" d="m9.75 9.75 4.5 4.5m0-4.5-4.5 4.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                )}
              </svg>
            </span>
            <div>
              <p className={`text-sm font-medium ${verifyResult.valid ? "text-emerald-300" : "text-rose-300"}`}>
                {verifyResult.valid ? "Audit chain integrity verified" : "Chain integrity violation detected"}
              </p>
              <p className="mt-0.5 text-xs text-gray-400">
                {verifyResult.entries_checked.toLocaleString()} entries across {verifyResult.writers_checked} writer chain(s)
                {verifyResult.errors.length > 0 && ` · ${verifyResult.errors.length} error(s)`}
              </p>
            </div>
            <button onClick={() => setVerifyResult(null)} className="ml-auto text-gray-500 hover:text-gray-300">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          {verifyResult.valid && (
            <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1.5 border-t border-white/5 pt-3 text-xs sm:grid-cols-4">
              {[
                { k: "Hash chain", v: verifyResult.chain_intact ? "Intact" : "Broken", hint: "SHA3-256 links, no gaps/reorders" },
                { k: "Signatures", v: `${verifyResult.signatures_valid.toLocaleString()}/${verifyResult.entries_checked.toLocaleString()}`, hint: "ML-DSA-65 vs gateway public key" },
                { k: "Merkle roots", v: `${verifyResult.merkle_roots_valid} verified`, hint: "batch roots" },
                { k: "Checkpoints", v: `${verifyResult.checkpoints_checked} anchored`, hint: "signed global anchors" },
              ].map((c) => (
                <div key={c.k} title={c.hint}>
                  <dt className="qw-eyebrow text-gray-500">{c.k}</dt>
                  <dd className="mt-0.5 font-mono text-emerald-300">{c.v}</dd>
                </div>
              ))}
            </dl>
          )}
          {verifyResult.errors.length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-rose-400">
              {verifyResult.errors.map((err, i) => (
                <li key={i}>· {err}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <Card>
        {isLoading ? (
          <Spinner className="py-16" />
        ) : !entries || entries.length === 0 ? (
          <EmptyState title="No audit entries yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="qw-eyebrow border-b border-white/5 text-left">
                  <th className="px-4 py-2.5 font-semibold">#</th>
                  <th className="px-4 py-2.5 font-semibold">Timestamp</th>
                  <th className="px-4 py-2.5 font-semibold">Event Type</th>
                  <th className="px-4 py-2.5 font-semibold">Session</th>
                  <th className="px-4 py-2.5 font-semibold">Details</th>
                  <th className="px-4 py-2.5 font-semibold">Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {entries.map((entry) => (
                  <tr key={entry.id} className="transition-colors hover:bg-white/5">
                    <td className="px-4 py-2.5 font-mono text-sm text-gray-500">{entry.id}</td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-sm text-gray-400">{new Date(entry.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-2.5">
                      <span className={`qw-chip ${eventTypeStyles[entry.event_type] ?? "bg-slate-400/10 text-slate-300"}`}>
                        {entry.event_type.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <code className="font-mono text-xs text-brand-300/70">{entry.session_id}</code>
                    </td>
                    <td className="max-w-xs truncate px-4 py-2.5 text-sm text-gray-400">{entry.details}</td>
                    <td className="px-4 py-2.5">
                      <code className="block max-w-[140px] truncate font-mono text-xs text-gray-600">{entry.hash}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
