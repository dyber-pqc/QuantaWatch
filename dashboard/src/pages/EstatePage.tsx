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
  PasswordInput,
  Textarea,
  SegmentedControl,
  NumberInput,
  Divider,
  Alert,
  Select,
  ScrollArea,
  ActionIcon,
  Tooltip,
} from "@mantine/core";
import { fetchTargets, registerTarget, scanTarget, deleteTarget, deepScanTarget, protectService, issueServiceCert } from "../api/client";
import type { Target, ExposedService } from "../api/types";
import { PageHeader, Stat, Spinner, EmptyState } from "../components/ui";
import { useContextMenu, type ContextMenuItem } from "../components/ContextMenu";
import { OverlayModal } from "../components/OverlayModal";
import { EstateMap } from "../components/EstateMap";

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
  const { openMenu, menu } = useContextMenu();
  const [selected, setSelected] = useState<string | null>(null);
  const [deepFor, setDeepFor] = useState<Target | null>(null);
  const [view, setView] = useState<string>("map");

  const { data: board, isLoading } = useQuery({ queryKey: ["targets"], queryFn: fetchTargets });
  const targets = board?.targets ?? [];
  const activeId = selected ?? targets[0]?.id ?? null;
  const active = targets.find((t) => t.id === activeId) ?? null;

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["targets"] });
    qc.invalidateQueries({ queryKey: ["attack-paths"] });
  };
  const scan = useMutation({ mutationFn: scanTarget, onSuccess: invalidate });
  const del = useMutation({ mutationFn: deleteTarget, onSuccess: invalidate });

  const containersTotal = targets.reduce((n, t) => n + (t.containers?.length ?? 0), 0);

  const menuItemsFor = (t: Target): ContextMenuItem[] => [
    { label: "Sweep (network)", onClick: () => scan.mutate(t.id) },
    { label: "Connect & inventory (SSH)", onClick: () => setDeepFor(t) },
    { label: "Copy host", onClick: () => navigator.clipboard?.writeText(t.host) },
    { label: "Delete target", color: "red", divider: true, onClick: () => del.mutate(t.id) },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Estate"
        subtitle="Register any connected system — a VM, a server over SSH/RDP, a network host — sweep it from the outside, then connect over SSH to inventory what runs inside"
      />

      {menu}
      <DeepScanModal target={deepFor} onClose={() => setDeepFor(null)} onDone={invalidate} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Targets" value={board?.total ?? 0} accent="brand" />
        <Stat label="Services found" value={board?.exposedServices ?? 0} accent="violet" />
        <Stat label="Quantum-vulnerable" value={board?.quantumVulnerable ?? 0} accent={(board?.quantumVulnerable ?? 0) > 0 ? "rose" : "emerald"} />
        <Stat label="Containers" value={containersTotal} accent="amber" />
      </div>

      <AddTarget onAdded={invalidate} />

      {targets.length > 0 && (
        <Group justify="space-between" align="center">
          <Text size="11px" fw={700} tt="uppercase" c="dimmed" style={{ letterSpacing: "0.08em" }}>
            {view === "map" ? "Estate map — hosts, services & containers" : "Targets"}
          </Text>
          <SegmentedControl
            size="xs"
            radius={2}
            value={view}
            onChange={setView}
            data={[
              { label: "Map", value: "map" },
              { label: "List", value: "list" },
            ]}
          />
        </Group>
      )}

      {isLoading ? (
        <Spinner className="py-16" />
      ) : targets.length === 0 ? (
        <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2 }} py="xl">
          <EmptyState title="No targets yet">Add a host above, then scan it to inventory what it exposes.</EmptyState>
        </Box>
      ) : view === "map" ? (
        <EstateMap targets={targets} onDeepScan={(t) => setDeepFor(t)} />
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
                onContextMenu={(e) => openMenu(e, menuItemsFor(t))}
              />
            ))}
          </Stack>
          <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-6)" }} p="md">
            {active ? <Detail t={active} scanning={scan.isPending} onScan={() => scan.mutate(active.id)} onDeepScan={() => setDeepFor(active)} openMenu={openMenu} /> : <Text c="dimmed" size="sm">Select a target.</Text>}
          </Box>
        </div>
      )}
    </div>
  );
}

function TargetRow({ t, active, scanning, onSelect, onScan, onDelete, onContextMenu }: {
  t: Target; active: boolean; scanning: boolean;
  onSelect: () => void; onScan: () => void; onDelete: () => void;
  onContextMenu: (e: React.MouseEvent) => void;
}) {
  return (
    <Box
      px="md"
      py="sm"
      onClick={onSelect}
      onContextMenu={onContextMenu}
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
        {t.exposedServices.length > 0 && <Badge color="violet" radius={2} size="xs" variant="light">{t.exposedServices.length} services</Badge>}
        {(t.containers?.length ?? 0) > 0 && <Badge color="cyan" radius={2} size="xs" variant="light">{t.containers!.length} containers</Badge>}
        {t.deepScanned && <Badge color="teal" radius={2} size="xs" variant="light">deep-scanned</Badge>}
        {!t.lastScanned && <Badge color="gray" radius={2} size="xs" variant="light">not scanned</Badge>}
      </Group>
    </Box>
  );
}

function ServiceCard({ s, onProtect, onIssueCert, onMenu, busy }: {
  s: ExposedService;
  onProtect: () => void;
  onIssueCert: () => void;
  onMenu: (e: React.MouseEvent) => void;
  busy: "protect" | "cert" | null;
}) {
  // Weak/secure/unknown services are candidates for a one-click fix.
  const fixable = s.pqcStatus === "classical_weak" || s.pqcStatus === "classical_secure" || s.pqcStatus === "unknown";
  return (
    <Box onContextMenu={onMenu} px="sm" py="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
      <Group justify="space-between" gap={8} wrap="nowrap">
        <Group gap={8} wrap="nowrap">
          <Text ff="monospace" size="13px" fw={600} c="gray.2">:{s.port}</Text>
          <Text ff="monospace" size="12px" c="gray.4">{s.service}</Text>
          {s.source === "host" && <Badge color="teal" radius={2} size="xs" variant="outline">host</Badge>}
        </Group>
        <PqcBadge status={s.pqcStatus} size="xs" />
      </Group>
      <Text size="11px" c="dimmed" mt={4} style={{ lineHeight: 1.5 }}>{s.detail}</Text>
      {s.protectedListen && (
        <Text ff="monospace" size="11px" c="signal.4" mt={4}>✓ protected via PQC overlay → {s.protectedListen}</Text>
      )}
      {s.certId && <Text size="11px" c="cyan.4" mt={2}>✓ hybrid ML-DSA certificate issued</Text>}
      {fixable && (
        <Group gap={6} mt={8}>
          <Button size="compact-xs" radius={2} color="brand" variant="light" loading={busy === "protect"} onClick={onProtect}>
            {s.protectedListen ? "Re-protect" : "Protect with overlay"}
          </Button>
          <Button size="compact-xs" radius={2} color="cyan" variant="light" loading={busy === "cert"} onClick={onIssueCert}>
            {s.certId ? "Re-issue cert" : "Issue PQC cert"}
          </Button>
        </Group>
      )}
    </Box>
  );
}

function Detail({ t, scanning, onScan, onDeepScan, openMenu }: { t: Target; scanning: boolean; onScan: () => void; onDeepScan: () => void; openMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void }) {
  const qc = useQueryClient();
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["targets"] });
    qc.invalidateQueries({ queryKey: ["attack-paths"] });
    qc.invalidateQueries({ queryKey: ["overlay"] });
    qc.invalidateQueries({ queryKey: ["pki"] });
  };
  const protectM = useMutation({ mutationFn: (port: number) => protectService(t.id, port), onSuccess: invalidate });
  const certM = useMutation({ mutationFn: (port: number) => issueServiceCert(t.id, port), onSuccess: invalidate });
  const busyFor = (port: number): "protect" | "cert" | null =>
    protectM.isPending && protectM.variables === port ? "protect" : certM.isPending && certM.variables === port ? "cert" : null;
  const serviceMenu = (s: ExposedService): ContextMenuItem[] => [
    { label: s.protectedListen ? "Re-protect with PQC overlay" : "Protect with PQC overlay", onClick: () => protectM.mutate(s.port) },
    { label: s.certId ? "Re-issue PQC certificate" : "Issue PQC certificate", onClick: () => certM.mutate(s.port) },
    { label: "Copy address", divider: true, onClick: () => navigator.clipboard?.writeText(`${t.host}:${s.port}`) },
  ];
  const renderService = (s: ExposedService, k: string) => (
    <ServiceCard key={k} s={s} busy={busyFor(s.port)} onProtect={() => protectM.mutate(s.port)} onIssueCert={() => certM.mutate(s.port)} onMenu={(e) => openMenu(e, serviceMenu(s))} />
  );

  const exposed = t.exposedServices.filter((s) => s.exposed !== false);
  const internal = t.exposedServices.filter((s) => s.exposed === false);
  const containers = t.containers ?? [];

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
          {t.hostInfo && <Text ff="monospace" size="11px" c="teal.4" mt={4}>{t.hostInfo}</Text>}
        </Box>
        <Group gap={6}>
          <Tooltip label="External network sweep (no credentials)" withArrow>
            <Button size="xs" radius={2} variant="default" loading={scanning} onClick={onScan}>Sweep</Button>
          </Tooltip>
          <Tooltip label="Connect over SSH and inventory from the inside" withArrow>
            <Button size="xs" radius={2} color="teal" onClick={onDeepScan}>Connect & inventory</Button>
          </Tooltip>
        </Group>
      </Group>

      {t.exposedServices.length === 0 && containers.length === 0 ? (
        <Box py="lg"><EmptyState title={t.lastScanned ? "Nothing found" : "Not scanned yet"}>{t.lastScanned ? "The sweep found no open crypto ports. Connect over SSH to inventory internal services." : "Sweep from the outside, or connect over SSH to inventory from the inside."}</EmptyState></Box>
      ) : (
        <ScrollArea.Autosize mah="calc(100vh - 360px)">
          <Stack gap={10}>
            {exposed.length > 0 && (
              <Stack gap={6}>
                <Text size="11px" fw={700} tt="uppercase" c="dark.2" style={{ letterSpacing: "0.08em" }}>Exposed to the network ({exposed.length})</Text>
                {exposed.map((s) => renderService(s, `e-${s.port}`))}
              </Stack>
            )}
            {internal.length > 0 && (
              <Stack gap={6}>
                <Text size="11px" fw={700} tt="uppercase" c="dark.2" style={{ letterSpacing: "0.08em" }}>Internal — loopback only ({internal.length})</Text>
                {internal.map((s) => renderService(s, `i-${s.port}`))}
              </Stack>
            )}
            {containers.length > 0 && (
              <Stack gap={6}>
                <Text size="11px" fw={700} tt="uppercase" c="dark.2" style={{ letterSpacing: "0.08em" }}>Containers ({containers.length})</Text>
                {containers.map((c) => (
                  <Box key={c.name} px="sm" py="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
                    <Group justify="space-between" gap={8} wrap="nowrap">
                      <Text size="12px" fw={600} c="gray.2" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</Text>
                      <Text ff="monospace" size="11px" c="cyan.4" style={{ flexShrink: 0 }}>{c.image}</Text>
                    </Group>
                    {c.ports && <Text ff="monospace" size="10px" c="dimmed" mt={2}>{c.ports}</Text>}
                  </Box>
                ))}
              </Stack>
            )}
          </Stack>
        </ScrollArea.Autosize>
      )}
      {t.lastScanned && <Text ff="monospace" size="10px" c="dark.3">last scanned {new Date(t.lastScanned).toLocaleString()}</Text>}
    </Stack>
  );
}

function DeepScanModal({ target, onClose, onDone }: { target: Target | null; onClose: () => void; onDone: () => void }) {
  const [authMode, setAuthMode] = useState<string>("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [port, setPort] = useState<number>(22);

  const run = useMutation({
    mutationFn: () =>
      deepScanTarget(target!.id, {
        port,
        username,
        ...(authMode === "password" ? { password } : { privateKey, passphrase: passphrase || undefined }),
      }),
    onSuccess: () => {
      onDone();
      onClose();
      setPassword(""); setPrivateKey(""); setPassphrase("");
    },
  });

  const canRun = !!username.trim() && (authMode === "password" ? !!password : !!privateKey.trim());

  return (
    <OverlayModal opened={!!target} onClose={onClose} title={`Connect & inventory — ${target?.name ?? ""}`} width={620}>
      <Stack gap="sm">
        <Alert color="teal" radius={2} variant="light" p="xs">
          <Text size="11px">QuantaWatch logs in over SSH to <b>{target?.host}</b> and reads listening sockets, Docker containers, and host facts. Credentials are used for this one connection and are <b>never stored</b>.</Text>
        </Alert>
        <Group gap="sm" grow>
          <TextInput size="xs" radius={2} label="Username" placeholder="root" value={username} onChange={(e) => setUsername(e.currentTarget.value)} />
          <NumberInput size="xs" radius={2} label="SSH port" value={port} onChange={(v) => setPort(typeof v === "number" ? v : 22)} min={1} max={65535} />
        </Group>
        <SegmentedControl size="xs" radius={2} value={authMode} onChange={setAuthMode} data={[{ label: "Password", value: "password" }, { label: "Private key", value: "key" }]} />
        {authMode === "password" ? (
          <PasswordInput size="xs" radius={2} label="Password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
        ) : (
          <Stack gap="xs">
            <Textarea size="xs" radius={2} label="OpenSSH private key (PEM)" autosize minRows={4} maxRows={8} styles={{ input: { fontFamily: "monospace", fontSize: 11 } }} placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----"} value={privateKey} onChange={(e) => setPrivateKey(e.currentTarget.value)} />
            <PasswordInput size="xs" radius={2} label="Key passphrase (optional)" value={passphrase} onChange={(e) => setPassphrase(e.currentTarget.value)} />
          </Stack>
        )}
        {run.isError && <Alert color="red" radius={2} variant="light" p="xs"><Text size="11px">{(run.error as Error)?.message ?? "Inventory failed."}</Text></Alert>}
        <Divider my={2} />
        <Group justify="flex-end" gap="sm">
          <Button size="xs" radius={2} variant="default" onClick={onClose}>Cancel</Button>
          <Button size="xs" radius={2} color="teal" loading={run.isPending} disabled={!canRun} onClick={() => run.mutate()}>Connect & inventory</Button>
        </Group>
      </Stack>
    </OverlayModal>
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
