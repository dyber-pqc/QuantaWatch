import { useQuery } from "@tanstack/react-query";
import { Badge, Box, Group, Stack, Text, Tooltip } from "@mantine/core";
import { fetchOverlay } from "../api/client";
import type { OverlayRouteStatus } from "../api/types";
import { PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
};

export default function OverlayPage() {
  const { data, isLoading, isFetching } = useQuery({
    queryKey: ["overlay"],
    queryFn: fetchOverlay,
    refetchInterval: 5000,
  });

  const routes = data?.routes ?? [];

  return (
    <div className="space-y-5">
      <PageHeader
        title="PQC Overlay"
        subtitle="Front legacy upstreams with a hybrid post-quantum TLS listener — protect the client leg without changing the upstream"
        actions={
          <Group gap={8}>
            <Tooltip label="The hybrid key-exchange group offered on every route's client-facing TLS listener." withArrow>
              <Badge variant="light" color="signal" radius={2} style={{ cursor: "help", fontFamily: "var(--font-mono)", textTransform: "none" }}>
                {data?.hybridGroup || "X25519MLKEM768"}
              </Badge>
            </Tooltip>
            <Box component="span" style={{ width: 7, height: 7, borderRadius: 7, background: isFetching ? "var(--mantine-color-brand-4)" : "var(--mantine-color-dark-3)", transition: "background 200ms" }} />
          </Group>
        }
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Protected routes" value={data?.total ?? 0} accent="brand" />
        <Stat label="PQC-proven" value={data?.pqcProtectedRoutes ?? 0} accent={(data?.pqcProtectedRoutes ?? 0) > 0 ? "emerald" : "amber"} sub="a hybrid handshake landed" />
        <Stat label="Active connections" value={routes.reduce((a, r) => a + r.active, 0)} accent="violet" />
        <Stat label="Cert" value={data?.certSource || "—"} accent="brand" />
      </div>

      {isLoading ? (
        <Spinner className="py-16" />
      ) : !data?.enabled || routes.length === 0 ? (
        <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2 }} py="xl">
          <EmptyState title="Overlay not configured">
            Declare <code>overlay.routes</code> in config (a listen address + upstream) and QuantaWatch fronts each
            with a hybrid-PQC TLS listener. The client leg becomes quantum-safe with no change to the upstream.
          </EmptyState>
        </Box>
      ) : (
        <Stack gap={10}>
          {routes.map((r) => (
            <RouteCard key={r.id} r={r} />
          ))}
        </Stack>
      )}
    </div>
  );
}

function RouteCard({ r }: { r: OverlayRouteStatus }) {
  return (
    <Box
      px="md"
      py="sm"
      style={{
        border: "1px solid var(--mantine-color-dark-4)",
        borderLeft: `3px solid var(--mantine-color-${r.pqcProtected ? "signal" : "yellow"}-6)`,
        borderRadius: 2,
        background: "var(--mantine-color-dark-6)",
      }}
    >
      <Group justify="space-between" align="flex-start" wrap="wrap" gap="sm">
        <Box style={{ minWidth: 0 }}>
          <Group gap={8} wrap="wrap">
            <Text ff="monospace" size="13px" fw={600} c="gray.2">{r.id}</Text>
            {r.pqcProtected ? (
              <Badge color="signal" radius={2} size="sm" variant="filled">PQC-protected</Badge>
            ) : (
              <Badge color="yellow" radius={2} size="sm" variant="light">awaiting PQC handshake</Badge>
            )}
            <Badge color="gray" radius={2} size="sm" variant="outline">{r.mode}</Badge>
          </Group>
          <Group gap={8} mt={8} wrap="wrap">
            <Text ff="monospace" size="12px" c="brand.4">{r.listen}</Text>
            <Text size="12px" c="dimmed">→</Text>
            <Text ff="monospace" size="12px" c="gray.4">{r.upstream}</Text>
            <Badge color="gray" radius={2} size="xs" variant="outline">
              upstream {r.upstreamTls ? "TLS" : "plaintext"}
            </Badge>
          </Group>
          {r.lastGroup && (
            <Text ff="monospace" size="11px" c="dark.2" mt={6}>
              last group: {r.lastGroup}
            </Text>
          )}
        </Box>
        <Group gap="lg" wrap="wrap">
          <MiniStat label="active" value={String(r.active)} />
          <MiniStat label="total" value={String(r.total)} />
          <MiniStat label="pqc conns" value={String(r.pqcConnections)} accent="var(--mantine-color-signal-4)" />
          {r.rejectedClassical > 0 && <MiniStat label="rejected" value={String(r.rejectedClassical)} accent="var(--mantine-color-red-4)" />}
          <MiniStat label="bytes" value={fmtBytes(r.bytes)} />
          {r.errors > 0 && <MiniStat label="errors" value={String(r.errors)} accent="var(--mantine-color-orange-4)" />}
        </Group>
      </Group>
    </Box>
  );
}

function MiniStat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <Box>
      <Text ff="monospace" size="9px" fw={600} c="dimmed" tt="uppercase" style={{ letterSpacing: "0.06em" }}>{label}</Text>
      <Text size="14px" fw={700} style={{ color: accent ?? "var(--mantine-color-gray-2)", fontVariantNumeric: "tabular-nums" }}>{value}</Text>
    </Box>
  );
}
