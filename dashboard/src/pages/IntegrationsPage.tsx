import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Badge, Box, Group, Stack, Text, Button, TextInput, PasswordInput, Select,
  Divider, Alert, ActionIcon, Tooltip,
} from "@mantine/core";
import { OverlayModal } from "../components/OverlayModal";
import {
  fetchIntegrations,
  testIntegration,
  syncIntegration,
  scanIntegration,
  fetchRemediations,
  syncRemediations,
  registerIntegrationWebhook,
  fetchConnections,
  createConnection,
  testConnection,
  scanConnection,
  deleteConnection,
} from "../api/client";
import type { IntegrationInfo, DiscoveredTarget, TicketStatus, Connection, ConnectionScanResult, MigrationStep } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";
import { useContextMenu, type ContextMenuItem } from "../components/ContextMenu";

const SOURCE_META: Record<string, { label: string; hint: string; needs: ("org" | "repo" | "baseUrl" | "project")[] }> = {
  github: { label: "GitHub", hint: "Personal access token (repo scope). Scans repos for quantum-vulnerable crypto in code & dependencies.", needs: ["org", "repo"] },
  gitlab: { label: "GitLab", hint: "Personal/project access token (read_api). Set a base URL for self-hosted.", needs: ["org", "baseUrl"] },
  jira: { label: "Jira", hint: "API token — opens migration tickets from findings. Base URL is your Atlassian site.", needs: ["baseUrl", "project"] },
  linear: { label: "Linear", hint: "API key — opens migration issues from findings.", needs: ["project"] },
};
const SEV_COLOR: Record<string, string> = { critical: "red", high: "orange", medium: "yellow", low: "gray" };

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

function MigrationPlanView({ plan }: { plan: MigrationStep[] }) {
  if (!plan || plan.length === 0) return null;
  return (
    <Stack gap={6} mt={8}>
      <Text size="11px" fw={700} tt="uppercase" c="dark.2" style={{ letterSpacing: "0.08em" }}>PQC migration plan</Text>
      {plan.map((m) => (
        <Box key={m.algorithm} px="sm" py="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
          <Group justify="space-between" gap={8} wrap="nowrap">
            <Group gap={8} wrap="nowrap">
              <Badge color={SEV_COLOR[m.severity] ?? "gray"} radius={2} size="xs" variant="filled">{m.severity}</Badge>
              <Text ff="monospace" size="12px" fw={600} c="gray.2">{m.algorithm}</Text>
              <Text size="11px" c="dimmed">×{m.occurrences}</Text>
            </Group>
          </Group>
          <Text size="11px" c="teal.4" mt={4}>→ {m.migrateTo}</Text>
          {m.locations.length > 0 && (
            <Text ff="monospace" size="10px" c="dark.3" mt={2} lineClamp={2}>{m.locations.join("  ·  ")}</Text>
          )}
        </Box>
      ))}
    </Stack>
  );
}

function ConnectionCard({ c, openMenu }: { c: Connection; openMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void }) {
  const qc = useQueryClient();
  const [scan, setScan] = useState<ConnectionScanResult | null>(null);
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["connections"] });
    qc.invalidateQueries({ queryKey: ["posture"] });
    qc.invalidateQueries({ queryKey: ["attack-paths"] });
  };
  const test = useMutation({ mutationFn: () => testConnection(c.id), onSuccess: invalidate });
  const scanM = useMutation({ mutationFn: () => scanConnection(c.id), onSuccess: (d) => { setScan(d); invalidate(); } });
  const del = useMutation({ mutationFn: () => deleteConnection(c.id), onSuccess: invalidate });

  const status = c.lastStatus ?? "untested";
  const statusColor = status === "connected" ? "signal" : status === "failed" ? "red" : "gray";
  const meta = SOURCE_META[c.integrationType];

  const menuItems: ContextMenuItem[] = [
    { label: "Test connection", onClick: () => test.mutate() },
    { label: "Scan for PQC issues", onClick: () => scanM.mutate() },
    { label: "Delete connection", color: "red", divider: true, onClick: () => del.mutate() },
  ];

  return (
    <Box
      onContextMenu={(e) => openMenu(e, menuItems)}
      p="md"
      style={{ border: "1px solid var(--mantine-color-dark-4)", borderLeft: `3px solid var(--mantine-color-${statusColor}-6)`, borderRadius: 2, background: "var(--mantine-color-dark-6)" }}
    >
      <Group justify="space-between" wrap="nowrap" align="flex-start">
        <Group gap={10} wrap="nowrap">
          <Box w={30} h={30} style={{ borderRadius: 2, display: "grid", placeItems: "center", background: "var(--mantine-color-brand-6)", color: "#fff", fontWeight: 700, fontSize: 13 }}>
            {(meta?.label ?? c.integrationType).charAt(0)}
          </Box>
          <Box>
            <Text size="13px" fw={600} c="gray.1">{c.displayName}</Text>
            <Text ff="monospace" size="11px" c="dimmed">{c.integrationType}{c.org ? ` · ${c.org}` : ""}{c.repo ? ` · ${c.repo}` : ""}</Text>
          </Box>
        </Group>
        <Group gap={4} wrap="nowrap">
          <Tooltip label="Test" withArrow><ActionIcon size="sm" radius={2} variant="light" color="gray" loading={test.isPending} onClick={() => test.mutate()}>✓</ActionIcon></Tooltip>
          <ActionIcon size="sm" radius={2} variant="subtle" color="gray" onClick={(e) => openMenu(e, menuItems)}>⋯</ActionIcon>
        </Group>
      </Group>

      <Group gap={6} mt={8} wrap="wrap">
        <Badge color={statusColor} radius={2} size="xs" variant={status === "connected" ? "light" : "filled"}>{status}</Badge>
        {c.lastUser && <Badge color="gray" radius={2} size="xs" variant="outline">{c.lastUser}</Badge>}
        {typeof c.findingsCount === "number" && <Badge color="violet" radius={2} size="xs" variant="light">{c.findingsCount} findings</Badge>}
        {!c.hasToken && <Badge color="red" radius={2} size="xs" variant="light">no token</Badge>}
      </Group>

      <Group gap="xs" mt={10}>
        <Button size="xs" radius={2} variant="default" loading={test.isPending} onClick={() => test.mutate()}>Test</Button>
        <Button size="xs" radius={2} color="brand" loading={scanM.isPending} onClick={() => scanM.mutate()}>Scan for PQC issues</Button>
      </Group>

      {test.isSuccess && (
        <Text size="11px" c={test.data.status.connected ? "signal.4" : "red.4"} mt={6}>
          {test.data.status.connected ? `Connected as ${test.data.status.user ?? "unknown"}` : `Failed: ${test.data.status.error ?? "check token"}`}
        </Text>
      )}
      {scanM.isError && <Text size="11px" c="red.4" mt={6}>{(scanM.error as Error)?.message ?? "Scan failed."}</Text>}
      {scan && (
        <Box mt={8}>
          <Text size="11px" c="dimmed">{scan.reposScanned} repos · {scan.filesScanned} files · {scan.findings} findings</Text>
          <MigrationPlanView plan={scan.migrationPlan} />
        </Box>
      )}
    </Box>
  );
}

function AddConnectionModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [type, setType] = useState<string>("github");
  const [displayName, setDisplayName] = useState("");
  const [token, setToken] = useState("");
  const [org, setOrg] = useState("");
  const [repo, setRepo] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [project, setProject] = useState("");
  const meta = SOURCE_META[type];

  const create = useMutation({
    mutationFn: () => createConnection({
      integrationType: type, displayName: displayName || undefined, token,
      org: org || undefined, repo: repo || undefined, baseUrl: baseUrl || undefined, project: project || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["connections"] });
      setToken(""); setDisplayName(""); setOrg(""); setRepo(""); setBaseUrl(""); setProject("");
      onClose();
    },
  });

  return (
    <OverlayModal opened={opened} onClose={onClose} title="Connect a source" width={620}>
      <Stack gap="sm">
        <Select size="xs" radius={2} label="Source type" value={type} onChange={(v) => setType(v ?? "github")}
          data={Object.entries(SOURCE_META).map(([value, m]) => ({ value, label: m.label }))} comboboxProps={{ radius: 2 }} />
        <Alert color="brand" radius={2} variant="light" p="xs"><Text size="11px">{meta?.hint}</Text></Alert>
        <TextInput size="xs" radius={2} label="Display name (optional)" placeholder={meta?.label} value={displayName} onChange={(e) => setDisplayName(e.currentTarget.value)} />
        <PasswordInput size="xs" radius={2} label="Token / API key" placeholder="paste the secret" value={token} onChange={(e) => setToken(e.currentTarget.value)} />
        <Group grow>
          {meta?.needs.includes("org") && <TextInput size="xs" radius={2} label={type === "gitlab" ? "Group" : "Org"} placeholder="optional" value={org} onChange={(e) => setOrg(e.currentTarget.value)} />}
          {meta?.needs.includes("repo") && <TextInput size="xs" radius={2} label="Repo (owner/repo)" placeholder="for PR remediation" value={repo} onChange={(e) => setRepo(e.currentTarget.value)} />}
        </Group>
        <Group grow>
          {meta?.needs.includes("baseUrl") && <TextInput size="xs" radius={2} label="Base URL" placeholder={type === "jira" ? "https://you.atlassian.net" : "https://gitlab.example.com"} value={baseUrl} onChange={(e) => setBaseUrl(e.currentTarget.value)} />}
          {meta?.needs.includes("project") && <TextInput size="xs" radius={2} label="Project" placeholder="key / id" value={project} onChange={(e) => setProject(e.currentTarget.value)} />}
        </Group>
        <Text size="10px" c="dimmed">The secret is stored on the gateway to drive scans and is never returned to the browser.</Text>
        {create.isError && <Alert color="red" radius={2} variant="light" p="xs"><Text size="11px">{(create.error as Error)?.message ?? "Failed to save."}</Text></Alert>}
        <Divider my={2} />
        <Group justify="flex-end">
          <Button size="xs" radius={2} variant="default" onClick={onClose}>Cancel</Button>
          <Button size="xs" radius={2} color="brand" loading={create.isPending} disabled={!token.trim()} onClick={() => create.mutate()}>Add connection</Button>
        </Group>
      </Stack>
    </OverlayModal>
  );
}

function ConnectionsSection() {
  const { openMenu, menu } = useContextMenu();
  const [adding, setAdding] = useState(false);
  const { data } = useQuery({ queryKey: ["connections"], queryFn: fetchConnections });
  const connections = data?.connections ?? [];

  return (
    <Card className="p-4">
      {menu}
      <AddConnectionModal opened={adding} onClose={() => setAdding(false)} />
      <Group justify="space-between" mb="sm">
        <Box>
          <Text fw={700} c="gray.1">Connect a source</Text>
          <Text size="12px" c="dimmed">Add GitHub / GitLab / Jira / Linear with a token, then scan for PQC issues and get a migration plan — no config file needed.</Text>
        </Box>
        <Button size="xs" radius={2} color="brand" onClick={() => setAdding(true)}>+ Add connection</Button>
      </Group>
      {connections.length === 0 ? (
        <Box py="md"><EmptyState title="No sources connected">Click “Add connection”, pick a type, and paste a token to start scanning.</EmptyState></Box>
      ) : (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {connections.map((c) => <ConnectionCard key={c.id} c={c} openMenu={openMenu} />)}
        </div>
      )}
    </Card>
  );
}

export default function IntegrationsPage() {
  const { data, isLoading } = useQuery({ queryKey: ["integrations"], queryFn: fetchIntegrations });

  const integrations = data?.integrations ?? [];
  const connected = integrations.filter((i) => i.status.connected).length;

  return (
    <div className="space-y-5">
      <PageHeader title="Integrations" subtitle="Connect your code hosts and trackers — scan for post-quantum risk and open migration work" />

      <ConnectionsSection />

      {isLoading ? <Spinner className="h-32" /> : integrations.length > 0 && (
      <>
      <Text size="11px" fw={700} tt="uppercase" c="dimmed" style={{ letterSpacing: "0.08em" }}>Config-defined integrations</Text>

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
      </>
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
