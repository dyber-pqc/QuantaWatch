import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Badge,
  Box,
  Group,
  Stack,
  Text,
  Button,
  TextInput,
  Select,
  ScrollArea,
  ActionIcon,
  Tooltip,
} from "@mantine/core";
import { fetchTargets, registerTarget, scanTarget, deleteTarget } from "../api/client";
import type { Target } from "../api/types";
import { PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const PQC_COLOR: Record<string, string> = {
  classical_weak: "red",
  classical_secure: "orange",
  unknown: "gray",
  hybrid: "cyan",
  pqc_ready: "signal",
};
const pqcLabel = (s: string) => s.replace(/_/g, " ");

function PqcBadge({ status, size = "sm" }: { status: string; size?: string }) {
  return (
    <Badge color={PQC_COLOR[status] ?? "gray"} radius={2} size={size as never} variant={status === "pqc_ready" || status === "hybrid" ? "light" : "filled"}>
      {pqcLabel(status)}
    </Badge>
  );
}

export default function EstatePage() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);

  const { data: board, isLoading } = useQuery({ queryKey: ["targets"], queryFn: fetchTargets });
  const targets = board?.targets ?? [];
  const activeId = selected ?? targets[0]?.id ?? null;
  const active = targets.find((t) => t.id === activeId) ?? null;

  const invalidate = () => qc.invalidateQueries({ queryKey: ["targets"] });
  const scan = useMutation({ mutationFn: scanTarget, onSuccess: invalidate });
  const del = useMutation({ mutationFn: deleteTarget, onSuccess: invalidate });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Estate"
        subtitle="Register any connected system — a VM, a server over SSH/RDP, a network host — then sweep it for exposed services and their post-quantum posture"
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Targets" value={board?.total ?? 0} accent="brand" />
        <Stat label="Exposed services" value={board?.exposedServices ?? 0} accent="violet" />
        <Stat label="Quantum-vulnerable" value={board?.quantumVulnerable ?? 0} accent={(board?.quantumVulnerable ?? 0) > 0 ? "rose" : "emerald"} />
        <Stat label="PQC-ready" value={targets.filter((t) => t.pqcStatus === "pqc_ready" || t.pqcStatus === "hybrid").length} accent="emerald" />
      </div>

      <AddTarget onAdded={invalidate} />

      {isLoading ? (
        <Spinner className="py-16" />
      ) : targets.length === 0 ? (
        <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2 }} py="xl">
          <EmptyState title="No targets yet">Add a host above, then scan it to inventory what it exposes.</EmptyState>
        </Box>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,340px)_1fr]">
          <Stack gap={8}>
            {targets.map((t) => (
              <TargetRow
                key={t.id}
                t={t}
                active={t.id === activeId}
                scanning={scan.isPending && scan.variables === t.id}
                onSelect={() => setSelected(t.id)}
                onScan={() => scan.mutate(t.id)}
                onDelete={() => del.mutate(t.id)}
              />
            ))}
          </Stack>
          <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-6)" }} p="md">
            {active ? <Detail t={active} scanning={scan.isPending} onScan={() => scan.mutate(active.id)} /> : <Text c="dimmed" size="sm">Select a target.</Text>}
          </Box>
        </div>
      )}
    </div>
  );
}

function TargetRow({ t, active, scanning, onSelect, onScan, onDelete }: {
  t: Target; active: boolean; scanning: boolean;
  onSelect: () => void; onScan: () => void; onDelete: () => void;
}) {
  return (
    <Box
      px="md"
      py="sm"
      onClick={onSelect}
      style={{
        cursor: "pointer",
        border: "1px solid var(--mantine-color-dark-4)",
        borderLeft: `3px solid var(--mantine-color-${PQC_COLOR[t.pqcStatus] ?? "gray"}-6)`,
        borderRadius: 2,
        background: active ? "var(--mantine-color-dark-5)" : "var(--mantine-color-dark-6)",
      }}
    >
      <Group justify="space-between" gap={6} wrap="nowrap">
        <Box style={{ minWidth: 0 }}>
          <Text size="13px" fw={600} c="gray.2" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.name}</Text>
          <Text ff="monospace" size="11px" c="dimmed">{t.host}</Text>
        </Box>
        <Group gap={4} wrap="nowrap">
          <Tooltip label="Sweep for exposed services" withArrow>
            <ActionIcon size="sm" radius={2} variant="light" color="brand" loading={scanning} onClick={(e) => { e.stopPropagation(); onScan(); }}>
              <svg width={13} height={13} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" /></svg>
            </ActionIcon>
          </Tooltip>
          <ActionIcon size="sm" radius={2} variant="subtle" color="gray" onClick={(e) => { e.stopPropagation(); onDelete(); }}>
            <svg width={13} height={13} fill="none" viewBox="0 0 24 24" strokeWidth={1.8} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
          </ActionIcon>
        </Group>
      </Group>
      <Group gap={6} mt={8} wrap="wrap">
        <Badge color="gray" radius={2} size="xs" variant="outline">{t.kind}</Badge>
        <PqcBadge status={t.pqcStatus} size="xs" />
        {t.exposedServices.length > 0 && <Badge color="violet" radius={2} size="xs" variant="light">{t.exposedServices.length} exposed</Badge>}
        {!t.lastScanned && <Badge color="gray" radius={2} size="xs" variant="light">not scanned</Badge>}
      </Group>
    </Box>
  );
}

function Detail({ t, scanning, onScan }: { t: Target; scanning: boolean; onScan: () => void }) {
  return (
    <Stack gap="sm">
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <Box>
          <Group gap={8}>
            <Text size="15px" fw={700} c="gray.1">{t.name}</Text>
            <PqcBadge status={t.pqcStatus} />
          </Group>
          <Group gap={10} mt={4}>
            <Text ff="monospace" size="12px" c="brand.4">{t.host}</Text>
            <Text size="12px" c="dimmed">{t.kind} · {t.environment}</Text>
            {t.reachability.length > 0 && <Text size="11px" c="dark.2">via {t.reachability.join(", ")}</Text>}
          </Group>
        </Box>
        <Button size="xs" radius={2} color="brand" loading={scanning} onClick={onScan}>Scan now</Button>
      </Group>

      {t.exposedServices.length === 0 ? (
        <Box py="lg"><EmptyState title={t.lastScanned ? "No crypto-relevant services exposed" : "Not scanned yet"}>{t.lastScanned ? "The sweep found no open crypto ports." : "Run a scan to inventory this host."}</EmptyState></Box>
      ) : (
        <ScrollArea.Autosize mah="calc(100vh - 380px)">
          <Stack gap={6}>
            {t.exposedServices.map((s) => (
              <Box key={s.port} px="sm" py="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
                <Group justify="space-between" gap={8} wrap="nowrap">
                  <Group gap={8} wrap="nowrap">
                    <Text ff="monospace" size="13px" fw={600} c="gray.2">:{s.port}</Text>
                    <Text ff="monospace" size="12px" c="gray.4">{s.service}</Text>
                  </Group>
                  <PqcBadge status={s.pqcStatus} size="xs" />
                </Group>
                <Text size="11px" c="dimmed" mt={4} style={{ lineHeight: 1.5 }}>{s.detail}</Text>
              </Box>
            ))}
          </Stack>
        </ScrollArea.Autosize>
      )}
      {t.lastScanned && <Text ff="monospace" size="10px" c="dark.3">last swept {new Date(t.lastScanned).toLocaleString()}</Text>}
    </Stack>
  );
}

function AddTarget({ onAdded }: { onAdded: () => void }) {
  const [host, setHost] = useState("");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<string>("server");
  const [env, setEnv] = useState("production");

  const add = useMutation({
    mutationFn: () => registerTarget({ name: name || host, host, kind, reachability: ["tls", "ssh"], environment: env, tags: [] }),
    onSuccess: () => { setHost(""); setName(""); onAdded(); },
  });

  return (
    <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }} px="sm" py="xs">
      <Group gap="sm" wrap="wrap">
        <TextInput size="xs" radius={2} placeholder="host or host:port" value={host} onChange={(e) => setHost(e.currentTarget.value)} w={200} />
        <TextInput size="xs" radius={2} placeholder="name (optional)" value={name} onChange={(e) => setName(e.currentTarget.value)} w={160} />
        <Select size="xs" radius={2} value={kind} onChange={(v) => setKind(v ?? "server")} data={["server", "vm", "network_device", "container", "database", "endpoint"]} w={140} comboboxProps={{ radius: 2 }} />
        <Select size="xs" radius={2} value={env} onChange={(v) => setEnv(v ?? "production")} data={["production", "staging", "development", "default"]} w={130} comboboxProps={{ radius: 2 }} />
        <Button size="xs" radius={2} color="brand" loading={add.isPending} disabled={!host.trim()} onClick={() => add.mutate()}>Add target</Button>
      </Group>
    </Box>
  );
}
