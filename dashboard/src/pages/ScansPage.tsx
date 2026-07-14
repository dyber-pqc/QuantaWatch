import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchScans, fetchFindings, triggerScan, fetchIntegrations, remediateFinding } from "../api/client";
import type { FindingRecord, RemediationTicket } from "../api/types";
import { Card, PageHeader, Stat, PqcBadge, SeverityBadge, Spinner, EmptyState } from "../components/ui";

function RemediateCell({
  finding,
  remediable,
  ticket,
  onCreate,
}: {
  finding: FindingRecord;
  remediable: { id: string; displayName: string }[];
  ticket?: RemediationTicket;
  onCreate: (findingId: string, integrationId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const mutation = useMutation({
    mutationFn: (integrationId: string) => remediateFinding(finding.id, { integrationId }),
    onSuccess: (t) => {
      onCreate(finding.id, t.integrationId);
      setOpen(false);
    },
  });

  if (ticket) {
    return (
      <a
        href={ticket.externalUrl}
        target="_blank"
        rel="noreferrer"
        className="qw-chip bg-emerald-400/10 text-emerald-300 ring-1 ring-emerald-400/30 hover:bg-emerald-400/20"
      >
        {ticket.externalId} ↗
      </a>
    );
  }

  if (remediable.length === 0) {
    return (
      <button
        disabled
        title="Configure Jira or Linear to create tickets"
        className="qw-chip cursor-not-allowed bg-white/5 text-gray-600"
      >
        Create ticket
      </button>
    );
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        disabled={mutation.isPending}
        className="qw-chip bg-brand-400/10 text-brand-200 ring-1 ring-brand-400/30 hover:bg-brand-400/20"
      >
        {mutation.isPending ? "Creating…" : "Create ticket"}
      </button>
      {open && (
        <div className="absolute right-0 z-20 mt-1 w-44 overflow-hidden rounded border border-white/10 bg-surface-900/95 shadow-2xl backdrop-blur">
          {remediable.map((it) => (
            <button
              key={it.id}
              onClick={() => mutation.mutate(it.id)}
              className="block w-full px-3 py-2 text-left text-xs text-gray-300 hover:bg-white/5"
            >
              {it.displayName}
            </button>
          ))}
        </div>
      )}
      {mutation.isError && <div className="mt-1 text-[10px] text-rose-400">Failed to create</div>}
    </div>
  );
}

export default function ScansPage() {
  const queryClient = useQueryClient();
  const [scanTarget, setScanTarget] = useState("api.anthropic.com:443");
  const [tickets, setTickets] = useState<Record<string, RemediationTicket>>({});

  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => fetchScans(50),
  });

  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: fetchFindings,
  });

  const { data: integrationsData } = useQuery({
    queryKey: ["integrations"],
    queryFn: fetchIntegrations,
  });

  const scanMutation = useMutation({
    mutationFn: (address: string) => triggerScan([{ target_type: "tls", address }]),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["posture"] });
      queryClient.invalidateQueries({ queryKey: ["posture-history"] });
    },
  });

  const remediable = (integrationsData?.integrations ?? [])
    .filter((i) => i.capabilities.includes("create_remediation"))
    .map((i) => ({ id: i.id, displayName: i.displayName }));

  const findings = findingsData?.findings ?? [];
  const scans = scansData?.scans ?? [];
  const criticalHigh = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;

  const recordTicket = (findingId: string, integrationId: string) => {
    // Optimistic local record; the remediations list refetches on the Integrations page.
    setTickets((prev) => ({
      ...prev,
      [findingId]: {
        id: findingId,
        integrationId,
        externalId: "ticket",
        externalUrl: "#",
        status: "open",
        findingId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    }));
    queryClient.invalidateQueries({ queryKey: ["remediations"] });
  };

  return (
    <div className="space-y-5">
      <PageHeader title="Security Scans" subtitle="Cryptographic discovery and vulnerability scanning" />

      {/* Trigger scan */}
      <Card className="p-4" hover>
        <div className="qw-eyebrow mb-3">Trigger Scan</div>
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            type="text"
            value={scanTarget}
            onChange={(e) => setScanTarget(e.target.value)}
            placeholder="hostname:port"
            className="flex-1 rounded border border-white/10 bg-surface-850 px-4 py-2.5 font-mono text-sm text-white outline-none focus:border-brand-400/50 focus:ring-2 focus:ring-brand-400/20"
          />
          <button
            onClick={() => scanMutation.mutate(scanTarget)}
            disabled={scanMutation.isPending || !scanTarget}
            className="qw-btn-primary"
          >
            {scanMutation.isPending ? "Scanning…" : "Scan"}
          </button>
        </div>
        {scanMutation.isSuccess && (
          <p className="mt-3 text-sm text-emerald-300">Found {scanMutation.data.total_findings} findings</p>
        )}
        {scanMutation.isError && (
          <p className="mt-3 text-sm text-rose-400">Scan failed. Check the target address.</p>
        )}
      </Card>

      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Stat label="Total Scans" value={scansData?.total ?? 0} accent="brand" />
        <Stat label="Total Findings" value={findingsData?.total ?? 0} accent="violet" />
        <Stat label="Critical / High" value={criticalHigh} accent={criticalHigh > 0 ? "rose" : "emerald"} />
      </div>

      {/* Findings */}
      <Card>
        <div className="border-b border-white/10 px-4 py-2.5">
          <div className="qw-eyebrow">Findings</div>
        </div>
        {findingsLoading ? (
          <Spinner className="py-12" />
        ) : findings.length === 0 ? (
          <EmptyState title="No findings yet">Run a scan to discover crypto assets.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="qw-eyebrow border-b border-white/5 text-left">
                  <th className="px-4 py-2.5 font-semibold">Severity</th>
                  <th className="px-4 py-2.5 font-semibold">Title</th>
                  <th className="px-4 py-2.5 font-semibold">PQC Status</th>
                  <th className="px-4 py-2.5 font-semibold">Category</th>
                  <th className="px-4 py-2.5 font-semibold">Location</th>
                  <th className="px-4 py-2.5 text-right font-semibold">Remediation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {findings.map((f) => (
                  <tr key={f.id} className="transition-colors hover:bg-white/5">
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="text-sm font-medium text-white">{f.title}</div>
                      <div className="mt-0.5 max-w-md truncate text-xs text-gray-500">{f.description}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      <PqcBadge status={f.pqcStatus} />
                    </td>
                    <td className="px-4 py-2.5 text-sm text-gray-400">{f.category.replace(/_/g, " ")}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-500">{f.location}</td>
                    <td className="px-4 py-2.5 text-right">
                      <RemediateCell
                        finding={f}
                        remediable={remediable}
                        ticket={tickets[f.id]}
                        onCreate={recordTicket}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Scan history */}
      <Card>
        <div className="border-b border-white/10 px-4 py-2.5">
          <div className="qw-eyebrow">Scan History</div>
        </div>
        {scansLoading ? (
          <Spinner className="py-12" />
        ) : scans.length === 0 ? (
          <EmptyState title="No scans recorded yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="qw-eyebrow border-b border-white/5 text-left">
                  <th className="px-4 py-2.5 font-semibold">Scanner</th>
                  <th className="px-4 py-2.5 font-semibold">Target</th>
                  <th className="px-4 py-2.5 font-semibold">Findings</th>
                  <th className="px-4 py-2.5 font-semibold">Status</th>
                  <th className="px-4 py-2.5 font-semibold">Completed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {scans.map((scan) => (
                  <tr key={scan.id} className="transition-colors hover:bg-white/5">
                    <td className="px-4 py-2.5 text-sm text-white">{scan.scannerId}</td>
                    <td className="px-4 py-2.5 font-mono text-sm text-gray-300">{scan.targetAddress}</td>
                    <td className="px-4 py-2.5 text-sm text-white">{scan.findingCount}</td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`qw-chip ${
                          scan.status === "completed"
                            ? "bg-emerald-400/10 text-emerald-300"
                            : scan.status === "failed"
                              ? "bg-rose-400/10 text-rose-300"
                              : "bg-amber-400/10 text-amber-300"
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-gray-500">
                      {new Date(scan.completedAt).toLocaleString()}
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
