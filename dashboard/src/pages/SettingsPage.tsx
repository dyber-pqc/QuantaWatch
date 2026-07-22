import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Box, Group, Stack, Text, Button, Switch, NumberInput, TextInput, Divider, Table, Alert } from "@mantine/core";
import { fetchSettings, saveSettings } from "../api/client";
import type { RuntimeSettings } from "../api/client";
import { Card, PageHeader, Stat, Spinner } from "../components/ui";

function SectionTitle({ children, hint }: { children: React.ReactNode; hint?: string }) {
  return (
    <Box mb="xs">
      <Text fw={700} c="gray.1">{children}</Text>
      {hint && <Text size="12px" c="dimmed">{hint}</Text>}
    </Box>
  );
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["settings"], queryFn: fetchSettings });
  const [draft, setDraft] = useState<RuntimeSettings | null>(null);
  const [allowlist, setAllowlist] = useState("");

  useEffect(() => {
    if (data) {
      setDraft(data.settings);
      setAllowlist(data.settings.scanAllowlist.join(", "));
    }
  }, [data]);

  const save = useMutation({
    mutationFn: (s: RuntimeSettings) => saveSettings(s),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (isLoading || !draft || !data) return <Spinner className="py-16" />;
  const ac = data.adminCenter;
  const set = <K extends keyof RuntimeSettings>(k: K, v: RuntimeSettings[K]) => setDraft({ ...draft, [k]: v });
  const toggleScanner = (id: string, enabled: boolean) => {
    const next = enabled ? draft.disabledScanners.filter((s) => s !== id) : [...new Set([...draft.disabledScanners, id])];
    set("disabledScanners", next);
  };
  const commit = () => save.mutate({ ...draft, scanAllowlist: allowlist.split(",").map((s) => s.trim()).filter(Boolean) });
  const dirty = JSON.stringify({ ...draft, scanAllowlist: allowlist.split(",").map((s) => s.trim()).filter(Boolean) }) !== JSON.stringify(data.settings);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Settings"
        subtitle="Admin center and scanning controls — the guardrails and limits an organisation runs QuantaWatch with"
        actions={<Button size="compact-sm" radius={2} color="brand" loading={save.isPending} disabled={!dirty} onClick={commit}>Save changes</Button>}
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Signed in as" value={ac.identity} accent="brand" sub={ac.role} />
        <Stat label="Tenant" value={ac.tenant} accent="violet" />
        <Stat label="Users" value={ac.users.length} accent="emerald" />
        <Stat label="API keys" value={ac.apiKeys.length} accent="amber" />
      </div>

      {save.isSuccess && !dirty && <Alert color="teal" radius={2} variant="light" p="xs"><Text size="12px">Settings saved — they take effect immediately (no restart).</Text></Alert>}

      {/* Scanning controls */}
      <Card className="p-4">
        <SectionTitle hint="Master controls for how QuantaWatch scans your estate.">Scanning</SectionTitle>
        <Stack gap="sm">
          <Switch checked={draft.scanningPaused} onChange={(e) => set("scanningPaused", e.currentTarget.checked)}
            label="Pause all automated scanning" description="Stops scheduled/background scans across every tenant. Manual scans stay available." color="red" />
          <Switch checked={draft.requireApprovalForActiveScans} onChange={(e) => set("requireApprovalForActiveScans", e.currentTarget.checked)}
            label="Require approval for active scans" description="Intrusive (network/SSH/RDP) scans must be approved before they run." />
          <Switch checked={draft.externalLookupsEnabled} onChange={(e) => set("externalLookupsEnabled", e.currentTarget.checked)}
            label="Allow outbound lookups" description="Third-party lookups (certificate-transparency / crt.sh, connector APIs). Disable in restricted environments." color="cyan" />
          <Switch checked={draft.k8sAdmissionEnforce} onChange={(e) => set("k8sAdmissionEnforce", e.currentTarget.checked)}
            label="Kubernetes admission: enforce" description="When the admission webhook is installed, DENY workloads with quantum-vulnerable crypto (TLS secrets / ingresses). Off = monitor (admit with a warning)." color="red" />
          <Group gap="lg" wrap="wrap">
            <NumberInput size="xs" radius={2} label="Max scan concurrency" description="0 = unlimited" value={draft.maxScanConcurrency} onChange={(v) => set("maxScanConcurrency", typeof v === "number" ? v : 0)} min={0} max={256} w={180} />
            <NumberInput size="xs" radius={2} label="Finding retention (days)" description="0 = keep forever" value={draft.findingRetentionDays} onChange={(v) => set("findingRetentionDays", typeof v === "number" ? v : 0)} min={0} max={3650} w={180} />
          </Group>
          <TextInput size="xs" radius={2} label="Scan allowlist (comma-separated)" description="If set, only hosts/domains matching one of these may be actively scanned — a guardrail for large estates." placeholder="10.0.0.0/8, .internal.example.com" value={allowlist} onChange={(e) => setAllowlist(e.currentTarget.value)} />
        </Stack>
      </Card>

      {/* Per-scanner enable */}
      <Card className="p-4">
        <SectionTitle hint="Turn individual scanners off — e.g. disable RDP probing, or CT lookups in an air-gapped estate.">Scanners</SectionTitle>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {ac.scanners.map((s) => {
            const enabled = !draft.disabledScanners.includes(s.id);
            return (
              <Group key={s.id} justify="space-between" px="sm" py={6} style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
                <Box>
                  <Text size="13px" fw={600} c="gray.2">{s.label}</Text>
                  <Text ff="monospace" size="10px" c="dimmed">{s.id}</Text>
                </Box>
                <Switch size="sm" checked={enabled} onChange={(e) => toggleScanner(s.id, e.currentTarget.checked)} />
              </Group>
            );
          })}
        </div>
      </Card>

      {/* Admin center — access */}
      <Card className="p-4">
        <SectionTitle hint="Who can reach this QuantaWatch. Managed in the gateway config / RBAC.">Admin center — access</SectionTitle>
        <Group gap={8} mb="sm">
          <Badge color={ac.authEnabled ? "signal" : "red"} radius={2} variant="light">{ac.authEnabled ? "authentication on" : "authentication OFF"}</Badge>
          {ac.airGapped && <Badge color="orange" radius={2} variant="light">air-gapped</Badge>}
        </Group>
        <Text size="11px" fw={700} tt="uppercase" c="dimmed" mb={4}>Users ({ac.users.length})</Text>
        <Table verticalSpacing={4} fz="12px" mb="md">
          <Table.Thead><Table.Tr><Table.Th>Username</Table.Th><Table.Th>Role</Table.Th><Table.Th>Org</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {ac.users.map((u) => (
              <Table.Tr key={u.username}><Table.Td>{u.username}</Table.Td><Table.Td><Badge size="xs" radius={2} variant="light" color={u.role === "admin" ? "brand" : "gray"}>{u.role}</Badge></Table.Td><Table.Td c="dimmed">{u.org}</Table.Td></Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {ac.apiKeys.length > 0 && (
          <>
            <Text size="11px" fw={700} tt="uppercase" c="dimmed" mb={4}>API keys ({ac.apiKeys.length})</Text>
            <Table verticalSpacing={4} fz="12px">
              <Table.Thead><Table.Tr><Table.Th>Name</Table.Th><Table.Th>Role</Table.Th><Table.Th>Org</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {ac.apiKeys.map((k) => (
                  <Table.Tr key={k.name}><Table.Td ff="monospace">{k.name}</Table.Td><Table.Td><Badge size="xs" radius={2} variant="light" color={k.role === "admin" ? "brand" : "gray"}>{k.role}</Badge></Table.Td><Table.Td c="dimmed">{k.org}</Table.Td></Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </>
        )}
        <Divider my="sm" />
        <Text size="11px" c="dimmed">Users, API keys and roles are declared in the gateway config (RBAC). This view is read-only; edit the config and reload to change access.</Text>
      </Card>
    </div>
  );
}
