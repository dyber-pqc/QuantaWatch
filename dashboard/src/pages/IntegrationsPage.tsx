import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchIntegrations,
  testIntegration,
  syncIntegration,
  scanIntegration,
  fetchRemediations,
  syncRemediations,
  registerIntegrationWebhook,
} from "../api/client";
import type { IntegrationInfo, DiscoveredTarget, TicketStatus } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const capabilityLabels: Record<string, { label: string; color: string }> = {
  discover_targets: { label: "Discovery", color: "bg-brand-400/10 text-brand-200" },
  create_remediation: { label: "Remediation", color: "bg-quantum-500/15 text-quantum-300" },
  sync_status: { label: "Sync", color: "bg-emerald-400/10 text-emerald-300" },
};

const ticketStatusColor: Record<TicketStatus, string> = {
  open: "bg-amber-400/10 text-amber-300",
  in_progress: "bg-brand-400/10 text-brand-200",
  resolved: "bg-emerald-400/10 text-emerald-300",
  closed: "bg-emerald-400/10 text-emerald-300",
  unknown: "bg-slate-400/10 text-slate-300",
};

function IntegrationCard({ integration }: { integration: IntegrationInfo }) {
  const queryClient = useQueryClient();
  const [targets, setTargets] = useState<DiscoveredTarget[] | null>(null);

  const testMutation = useMutation({ mutationFn: () => testIntegration(integration.id) });
  const syncMutation = useMutation({
    mutationFn: () => syncIntegration(integration.id),
    onSuccess: (d) => setTargets(d.targets ?? []),
  });
  const scanMutation = useMutation({
    mutationFn: () => scanIntegration(integration.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["posture"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const webhookMutation = useMutation({
    mutationFn: () => registerIntegrationWebhook(
      integration.id,
      `${window.location.origin}/api/webhooks/${integration.integrationType}`,
    ),
  });

  const connected = integration.status.connected;
  const canDiscover = integration.capabilities.includes("discover_targets");
  const canRemediate = integration.capabilities.includes("create_remediation");

  return (
    <Card className="p-4" hover>
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-brand-600/90 text-sm font-semibold text-white">
            {integration.displayName.charAt(0)}
          </div>
          <div>
            <h3 className="font-medium text-white">{integration.displayName}</h3>
            <p className="font-mono text-xs text-gray-500">{integration.id}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            {connected && (
              <span className="qw-pulse-glow absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            )}
            <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${connected ? "bg-emerald-500" : "bg-rose-500"}`} />
          </span>
          <span className={`text-xs ${connected ? "text-emerald-300" : "text-rose-300"}`}>
            {connected ? "Connected" : "Disconnected"}
          </span>
        </div>
      </div>

      {integration.status.user && (
        <p className="mb-3 text-xs text-gray-500">Authenticated as: {integration.status.user}</p>
      )}
      {integration.status.error && <p className="mb-3 text-xs text-rose-400">{integration.status.error}</p>}

      <div className="mb-4 flex flex-wrap gap-2">
        {integration.capabilities.map((cap) => {
          const style = capabilityLabels[cap] ?? { label: cap, color: "bg-slate-400/10 text-slate-300" };
          return (
            <span key={cap} className={`qw-chip ${style.color}`}>
              {style.label}
            </span>
          );
        })}
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={() => testMutation.mutate()} disabled={testMutation.isPending} className="qw-btn-ghost !px-3 !py-1.5 !text-xs">
          {testMutation.isPending ? "Testing…" : "Test Connection"}
        </button>
        {canDiscover && (
          <>
            <button onClick={() => syncMutation.mutate()} disabled={syncMutation.isPending} className="qw-btn-ghost !px-3 !py-1.5 !text-xs">
              {syncMutation.isPending ? "Discovering…" : "Discover Targets"}
            </button>
            <button onClick={() => scanMutation.mutate()} disabled={scanMutation.isPending} className="qw-btn-primary !px-3 !py-1.5 !text-xs">
              {scanMutation.isPending ? "Scanning…" : "Scan Now"}
            </button>
          </>
        )}
        <button onClick={() => webhookMutation.mutate()} disabled={webhookMutation.isPending} className="qw-btn-ghost !px-3 !py-1.5 !text-xs">
          {webhookMutation.isPending ? "Registering…" : "Register Webhook"}
        </button>
      </div>

      {webhookMutation.isSuccess && (
        <div className="mt-3 rounded-lg bg-emerald-400/10 p-2 text-xs text-emerald-300">{webhookMutation.data.detail}</div>
      )}
      {webhookMutation.isError && (
        <div className="mt-3 rounded-lg bg-rose-400/10 p-2 text-xs text-rose-300">Webhook registration failed (needs a repo + token).</div>
      )}

      {canRemediate && (
        <p className="mt-3 text-xs text-gray-500">Creates Jira/Linear tickets from findings.</p>
      )}

      {testMutation.isSuccess && (
        <div className={`mt-3 rounded-lg p-2 text-xs ${testMutation.data.connected ? "bg-emerald-400/10 text-emerald-300" : "bg-rose-400/10 text-rose-300"}`}>
          {testMutation.data.connected
            ? `Connected as ${testMutation.data.user ?? "unknown"}`
            : `Failed: ${testMutation.data.error ?? "unknown error"}`}
        </div>
      )}

      {scanMutation.isSuccess && (
        <div className="mt-3 rounded-lg bg-brand-400/10 p-2 text-xs text-brand-200">
          {scanMutation.data.reposScanned} repos · {scanMutation.data.filesScanned} files · {scanMutation.data.findings} findings
        </div>
      )}

      {targets && (
        <div className="mt-3 rounded-lg border border-white/5 bg-surface-850/60 p-3">
          <div className="qw-eyebrow mb-2">Discovered Targets ({targets.length})</div>
          {targets.length === 0 ? (
            <p className="text-xs text-gray-500">No dependency files found in connected repositories.</p>
          ) : (
            <ul className="max-h-40 space-y-1 overflow-y-auto">
              {targets.map((t) => (
                <li key={t.id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="truncate font-mono text-gray-300">{t.address}</span>
                  {t.metadata?.repo && <span className="shrink-0 text-gray-600">{t.metadata.repo}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}

function RemediationHistory() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["remediations"], queryFn: fetchRemediations });
  const remediations = data?.remediations ?? [];
  const sync = useMutation({
    mutationFn: syncRemediations,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["remediations"] }),
  });

  return (
    <Card>
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
        <div className="qw-eyebrow">Remediation History</div>
        <button onClick={() => sync.mutate()} disabled={sync.isPending} className="qw-chip bg-white/5 text-gray-300 hover:bg-white/10">
          {sync.isPending ? "Syncing…" : sync.isSuccess ? `Synced (${sync.data.changed} updated)` : "↻ Sync status"}
        </button>
      </div>
      {isLoading ? (
        <Spinner className="py-10" />
      ) : remediations.length === 0 ? (
        <EmptyState title="No remediation tickets yet">
          Create one from a finding on the Scans page.
        </EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="qw-eyebrow border-b border-white/5 text-left">
                <th className="px-4 py-2.5 font-semibold">Ticket</th>
                <th className="px-4 py-2.5 font-semibold">Integration</th>
                <th className="px-4 py-2.5 font-semibold">Status</th>
                <th className="px-4 py-2.5 font-semibold">Finding</th>
                <th className="px-4 py-2.5 font-semibold">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {remediations.map((r) => (
                <tr key={r.id} className="transition-colors hover:bg-white/5">
                  <td className="px-4 py-2.5">
                    <a href={r.externalUrl} target="_blank" rel="noreferrer" className="text-sm text-brand-300 hover:text-brand-200">
                      {r.externalId} ↗
                    </a>
                  </td>
                  <td className="px-4 py-2.5 text-sm text-gray-300">{r.integrationId}</td>
                  <td className="px-4 py-2.5">
                    <span className={`qw-chip ${ticketStatusColor[r.status] ?? ticketStatusColor.unknown}`}>{r.status}</span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-500">{r.findingId.slice(0, 8)}</td>
                  <td className="px-4 py-2.5 text-xs text-gray-500">{new Date(r.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export default function IntegrationsPage() {
  const { data, isLoading } = useQuery({ queryKey: ["integrations"], queryFn: fetchIntegrations });

  if (isLoading) return <Spinner className="h-64" />;

  const integrations = data?.integrations ?? [];
  const connected = integrations.filter((i) => i.status.connected).length;

  return (
    <div className="space-y-5">
      <PageHeader title="Integrations" subtitle="Connected services for discovery, scanning, and remediation" />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Stat label="Total Integrations" value={integrations.length} accent="brand" />
        <Stat label="Connected" value={connected} accent="emerald" />
        <Stat label="Disconnected" value={integrations.length - connected} accent="rose" />
      </div>

      {integrations.length === 0 ? (
        <Card className="p-12">
          <EmptyState
            title="No Integrations Configured"
            icon={
              <svg className="h-12 w-12" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M14.25 6.087c0-.355.186-.676.401-.959.221-.29.349-.634.349-1.003 0-1.036-1.007-1.875-2.25-1.875s-2.25.84-2.25 1.875c0 .369.128.713.349 1.003.215.283.401.604.401.959v0a.64.64 0 0 1-.657.643 48.39 48.39 0 0 1-4.163-.3c.186 1.613.293 3.25.315 4.907a.656.656 0 0 1-.658.663v0c-.355 0-.676-.186-.959-.401a1.647 1.647 0 0 0-1.003-.349c-1.036 0-1.875 1.007-1.875 2.25s.84 2.25 1.875 2.25c.369 0 .713-.128 1.003-.349.283-.215.604-.401.959-.401v0c.31 0 .555.26.532.57a48.039 48.039 0 0 1-.642 5.056c1.518.19 3.058.309 4.616.354a.64.64 0 0 0 .657-.643v0c0-.355-.186-.676-.401-.959a1.647 1.647 0 0 1-.349-1.003c0-1.035 1.008-1.875 2.25-1.875 1.243 0 2.25.84 2.25 1.875 0 .369-.128.713-.349 1.003-.215.283-.4.604-.4.959v0c0 .333.277.599.61.58a48.1 48.1 0 0 0 5.427-.63 48.05 48.05 0 0 0 .582-4.717.532.532 0 0 0-.533-.57v0c-.355 0-.676.186-.959.401-.29.221-.634.349-1.003.349-1.035 0-1.875-1.007-1.875-2.25s.84-2.25 1.875-2.25c.37 0 .713.128 1.003.349.283.215.604.401.96.401v0a.656.656 0 0 0 .658-.663 48.422 48.422 0 0 0-.37-5.36c-1.886.342-3.81.574-5.766.689a.578.578 0 0 1-.61-.58v0Z" />
              </svg>
            }
          >
            <p>Add integrations in your quantawatch.yaml config to connect GitHub, GitLab, Jira, or Linear for automated scanning and remediation.</p>
            <pre className="mt-4 rounded-lg bg-surface-850 p-4 text-left font-mono text-xs text-gray-400">
{`integrations:
  - id: github-main
    integration_type: github
    api_token_env: GITHUB_TOKEN
    settings:
      org: your-org`}
            </pre>
          </EmptyState>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {integrations.map((integration) => (
            <IntegrationCard key={integration.id} integration={integration} />
          ))}
        </div>
      )}

      <RemediationHistory />

      <Card className="p-4">
        <div className="qw-eyebrow mb-4">Supported Integrations</div>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[
            { name: "GitHub", type: "Discovery", desc: "Scan repos for crypto dependencies" },
            { name: "GitLab", type: "Discovery", desc: "Scan projects for crypto usage" },
            { name: "Jira", type: "Remediation", desc: "Create tickets from findings" },
            { name: "Linear", type: "Remediation", desc: "Create issues from findings" },
          ].map((item) => (
            <div key={item.name} className="rounded border border-white/10 bg-surface-850/60 p-3">
              <div className="text-sm font-medium text-white">{item.name}</div>
              <div className="mt-0.5 text-xs text-brand-300">{item.type}</div>
              <div className="mt-1 text-xs text-gray-500">{item.desc}</div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
