import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Box, Group, Stack, Text, Button, ActionIcon, Collapse, CopyButton, Code } from "@mantine/core";
import { fetchEndpoints, fetchEnrollInfo, deleteEndpoint } from "../api/client";
import type { Endpoint, EndpointComponent } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const PQC_COLOR: Record<string, string> = {
  classical_weak: "red",
  classical_secure: "orange",
  unknown: "gray",
  hybrid: "cyan",
  pqc_ready: "signal",
};
const SEV_COLOR: Record<string, string> = { critical: "red", high: "red", medium: "orange", low: "yellow", info: "gray" };
const CAT_ICON: Record<string, string> = {
  secure_boot: "🛡️",
  tpm: "🔐",
  measured_boot: "📏",
  disk_encryption: "💽",
  ssh_host_key: "🔑",
  certificate: "📜",
  crypto_library: "📦",
};
const OS_ICON = (k: string) => (k === "windows" ? "🪟" : k === "macos" ? "🍎" : k === "linux" ? "🐧" : "🖥️");

function PqcBadge({ status, size = "sm" }: { status: string; size?: string }) {
  return (
    <Badge color={PQC_COLOR[status] ?? "gray"} radius={2} size={size as never} variant={status === "pqc_ready" || status === "hybrid" ? "light" : "filled"}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function CopyLine({ label, value }: { label: string; value: string }) {
  return (
    <Box>
      <Text size="10px" fw={700} tt="uppercase" c="dimmed" mb={3} style={{ letterSpacing: "0.06em" }}>{label}</Text>
      <Group gap={6} wrap="nowrap" align="stretch">
        <Code block style={{ flex: 1, fontSize: 11, overflowX: "auto", whiteSpace: "pre" }}>{value}</Code>
        <CopyButton value={value}>
          {({ copied, copy }) => (
            <Button size="xs" radius={2} variant={copied ? "filled" : "default"} color={copied ? "teal" : "gray"} onClick={copy} style={{ flexShrink: 0 }}>
              {copied ? "Copied" : "Copy"}
            </Button>
          )}
        </CopyButton>
      </Group>
    </Box>
  );
}

function EnrollCard() {
  const [open, setOpen] = useState(false);
  const { data } = useQuery({ queryKey: ["endpoint-enroll"], queryFn: fetchEnrollInfo, enabled: open });
  return (
    <Card className="p-4">
      <Group justify="space-between">
        <Box>
          <Text fw={700} c="gray.1">Enroll an agent</Text>
          <Text size="12px" c="dimmed">Install the read-only agent on a host to inventory its firmware / boot-chain crypto (TPM, Secure Boot, measured boot, disk encryption).</Text>
        </Box>
        <Button size="xs" radius={2} color="brand" variant={open ? "light" : "filled"} onClick={() => setOpen((v) => !v)}>
          {open ? "Hide" : "Show install command"}
        </Button>
      </Group>
      <Collapse in={open}>
        <Stack gap="sm" mt="md">
          {!data ? <Spinner className="py-4" /> : (
            <>
              <CopyLine label="Linux / Unix (POSIX sh + curl)" value={data.linux.replace("<gateway-url>", window.location.origin)} />
              <CopyLine label="Windows (elevated PowerShell)" value={data.windows.replace("<gateway-url>", window.location.origin)} />
              <Text size="11px" c="dimmed">{data.note} Agent scripts live in <Code style={{ fontSize: 11 }}>deploy/agent/</Code>. Schedule it (cron / Task Scheduler) to keep posture current.</Text>
            </>
          )}
        </Stack>
      </Collapse>
    </Card>
  );
}

function ComponentRow({ c }: { c: EndpointComponent }) {
  return (
    <Box px="sm" py="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderLeft: `3px solid var(--mantine-color-${PQC_COLOR[c.pqcStatus] ?? "gray"}-6)`, borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
      <Group justify="space-between" gap={8} wrap="nowrap">
        <Group gap={8} wrap="nowrap" style={{ minWidth: 0 }}>
          <Text fz={14} style={{ flexShrink: 0 }}>{CAT_ICON[c.category] ?? "🔒"}</Text>
          <Text size="13px" fw={600} c="gray.2" truncate>{c.name}</Text>
          {c.algorithm && <Text ff="monospace" size="11px" c="gray.5" truncate>{c.algorithm}</Text>}
        </Group>
        <Group gap={6} wrap="nowrap" style={{ flexShrink: 0 }}>
          {c.severity !== "info" && <Badge color={SEV_COLOR[c.severity] ?? "gray"} radius={2} size="xs" variant="light">{c.severity}</Badge>}
          <PqcBadge status={c.pqcStatus} size="xs" />
        </Group>
      </Group>
      <Text size="11px" c="dimmed" mt={4} style={{ lineHeight: 1.5 }}>{c.detail}</Text>
    </Box>
  );
}

function EndpointCard({ e, onDelete }: { e: Endpoint; onDelete: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderLeft: `3px solid var(--mantine-color-${PQC_COLOR[e.pqcStatus] ?? "gray"}-6)`, borderRadius: 2, background: "var(--mantine-color-dark-6)" }}>
      <Group justify="space-between" wrap="nowrap" px="md" py="sm" style={{ cursor: "pointer" }} onClick={() => setOpen((v) => !v)}>
        <Group gap={10} wrap="nowrap" style={{ minWidth: 0 }}>
          <Text fz={20} style={{ flexShrink: 0 }}>{OS_ICON(e.osKind)}</Text>
          <Box style={{ minWidth: 0 }}>
            <Text size="14px" fw={700} c="gray.1" truncate>{e.hostname}</Text>
            <Text size="11px" c="dimmed" truncate>{e.os}</Text>
          </Box>
        </Group>
        <Group gap={8} wrap="nowrap" style={{ flexShrink: 0 }}>
          {e.findingsCount > 0 && <Badge color="rose" radius={2} size="xs" variant="light">{e.findingsCount} findings</Badge>}
          <PqcBadge status={e.pqcStatus} />
          <ActionIcon size="sm" radius={2} variant="subtle" color="gray" onClick={(ev) => { ev.stopPropagation(); onDelete(); }}>
            <svg width={13} height={13} fill="none" viewBox="0 0 24 24" strokeWidth={1.8} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
          </ActionIcon>
          <Box style={{ transition: "transform .15s", transform: open ? "rotate(90deg)" : "none" }}>
            <svg width={14} height={14} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" style={{ color: "var(--mantine-color-dark-2)" }}><path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" /></svg>
          </Box>
        </Group>
      </Group>
      <Collapse in={open}>
        <Stack gap={6} px="md" pb="md">
          {e.components.length === 0 ? (
            <Text size="12px" c="dimmed">No crypto components reported.</Text>
          ) : (
            e.components.map((c, i) => <ComponentRow key={`${c.category}-${i}`} c={c} />)
          )}
          <Text ff="monospace" size="10px" c="dark.3" mt={2}>
            {e.agentVersion ?? "agent"} · last report {new Date(e.lastReport).toLocaleString()}
          </Text>
        </Stack>
      </Collapse>
    </Box>
  );
}

export default function EndpointsPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["endpoints"], queryFn: fetchEndpoints });
  const endpoints = data?.endpoints ?? [];
  const del = useMutation({ mutationFn: deleteEndpoint, onSuccess: () => qc.invalidateQueries({ queryKey: ["endpoints"] }) });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Endpoints"
        subtitle="Firmware & boot-chain crypto reported by host agents — the TPM, Secure Boot, measured boot and disk encryption that a network or SSH scan can't see"
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Stat label="Endpoints" value={data?.total ?? 0} accent="brand" />
        <Stat label="Quantum-vulnerable" value={data?.quantumVulnerable ?? 0} accent={(data?.quantumVulnerable ?? 0) > 0 ? "rose" : "emerald"} />
        <Stat label="Findings" value={endpoints.reduce((n, e) => n + e.findingsCount, 0)} accent="amber" />
      </div>

      <EnrollCard />

      {isLoading ? (
        <Spinner className="py-16" />
      ) : endpoints.length === 0 ? (
        <Card className="p-10">
          <EmptyState title="No endpoints reporting yet">Click “Show install command” above, run the agent on a host, and its firmware crypto posture will appear here.</EmptyState>
        </Card>
      ) : (
        <Stack gap={8}>
          {endpoints.map((e) => (
            <EndpointCard key={e.id} e={e} onDelete={() => del.mutate(e.id)} />
          ))}
        </Stack>
      )}
    </div>
  );
}
