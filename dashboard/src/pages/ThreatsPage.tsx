import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Badge,
  Box,
  Group,
  Stack,
  Text,
  TextInput,
  Select,
  SegmentedControl,
  Checkbox,
  Tooltip,
  ScrollArea,
} from "@mantine/core";
import { fetchThreats } from "../api/client";
import type { Threat } from "../api/types";
import { PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const SEV: Record<Threat["severity"], { color: string; label: string; order: number }> = {
  critical: { color: "red", label: "Critical", order: 0 },
  high: { color: "orange", label: "High", order: 1 },
  medium: { color: "yellow", label: "Medium", order: 2 },
  low: { color: "gray", label: "Low", order: 3 },
};

// Turn "quantum_unsafe_channel" -> "Quantum Unsafe Channel". Split on
// underscore / space / hyphen only (no backslash escapes).
const prettyType = (s: string) =>
  s
    .split(/[_ -]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");

const timeAgo = (iso: string) => {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
};

type SevFilter = "all" | Threat["severity"];

export default function ThreatsPage() {
  const { data, isLoading, isFetching, dataUpdatedAt } = useQuery({
    queryKey: ["threats"],
    queryFn: fetchThreats,
    refetchInterval: 10_000, // live feed
  });

  const threats = data ?? [];

  const [sev, setSev] = useState<SevFilter>("all");
  const [type, setType] = useState<string | null>(null);
  const [blockedOnly, setBlockedOnly] = useState(false);
  const [q, setQ] = useState("");

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, blocked: 0 };
    for (const t of threats) {
      c[t.severity] += 1;
      if (t.blocked) c.blocked += 1;
    }
    return c;
  }, [threats]);

  const typeOptions = useMemo(() => {
    const set = new Map<string, number>();
    for (const t of threats) set.set(t.threat_type, (set.get(t.threat_type) ?? 0) + 1);
    return [...set.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, n]) => ({ value, label: `${prettyType(value)} (${n})` }));
  }, [threats]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return threats
      .filter((t) => (sev === "all" ? true : t.severity === sev))
      .filter((t) => (type ? t.threat_type === type : true))
      .filter((t) => (blockedOnly ? t.blocked : true))
      .filter((t) =>
        needle
          ? t.description.toLowerCase().includes(needle) ||
            t.threat_type.toLowerCase().includes(needle) ||
            t.session_id.toLowerCase().includes(needle)
          : true,
      );
  }, [threats, sev, type, blockedOnly, q]);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Threats"
        subtitle="Security detections, derived live from the tamper-evident audit log"
        actions={
          <Group gap={8}>
            <Tooltip
              label="Every threat is the security-relevant subset of the ML-DSA-signed audit chain — nothing here is fabricated or editable."
              multiline
              w={260}
              withArrow
            >
              <Badge
                variant="light"
                color="signal"
                radius={2}
                leftSection={
                  <Box
                    component="span"
                    style={{ width: 6, height: 6, borderRadius: 6, background: "var(--mantine-color-signal-4)", display: "inline-block" }}
                  />
                }
                style={{ cursor: "help", fontFamily: "var(--font-mono)", textTransform: "none" }}
              >
                ML-DSA attested
              </Badge>
            </Tooltip>
            <Group gap={6}>
              <Box
                component="span"
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: 7,
                  background: isFetching ? "var(--mantine-color-brand-4)" : "var(--mantine-color-dark-3)",
                  boxShadow: isFetching ? "0 0 0 3px color-mix(in srgb, var(--mantine-color-brand-6) 25%, transparent)" : "none",
                  transition: "background 200ms",
                }}
              />
              <Text ff="monospace" size="10px" c="dimmed" tt="uppercase" style={{ letterSpacing: "0.06em" }}>
                {dataUpdatedAt ? `live · ${timeAgo(new Date(dataUpdatedAt).toISOString())}` : "live"}
              </Text>
            </Group>
          </Group>
        }
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        <Stat label="Critical" value={counts.critical} accent={counts.critical > 0 ? "rose" : "emerald"} />
        <Stat label="High" value={counts.high} accent={counts.high > 0 ? "amber" : "emerald"} />
        <Stat label="Medium" value={counts.medium} accent="amber" />
        <Stat label="Blocked in-path" value={counts.blocked} accent="emerald" sub={`of ${threats.length} events`} />
        <Stat label="Total" value={threats.length} accent="brand" />
      </div>

      <Box
        style={{
          border: "1px solid var(--mantine-color-dark-4)",
          borderRadius: 2,
          background: "var(--mantine-color-dark-7)",
        }}
        px="sm"
        py="xs"
      >
        <Group justify="space-between" gap="sm" wrap="wrap">
          <Group gap="sm" wrap="wrap">
            <SegmentedControl
              size="xs"
              radius={2}
              value={sev}
              onChange={(v) => setSev(v as SevFilter)}
              data={[
                { value: "all", label: "All" },
                { value: "critical", label: `Critical` },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
              ]}
            />
            <Select
              size="xs"
              radius={2}
              clearable
              placeholder="All types"
              value={type}
              onChange={setType}
              data={typeOptions}
              w={220}
              comboboxProps={{ radius: 2 }}
            />
            <Checkbox
              size="xs"
              radius={2}
              label="Blocked only"
              checked={blockedOnly}
              onChange={(e) => setBlockedOnly(e.currentTarget.checked)}
            />
          </Group>
          <TextInput
            size="xs"
            radius={2}
            placeholder="Search description, type, session…"
            value={q}
            onChange={(e) => setQ(e.currentTarget.value)}
            w={280}
          />
        </Group>
      </Box>

      {isLoading ? (
        <Spinner className="py-16" />
      ) : threats.length === 0 ? (
        <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2 }} py="xl">
          <EmptyState title="No threats detected">
            The gateway hasn't flagged any security events yet. Detections appear here the moment the in-path
            monitor, PQC enforcer, or auth layer writes a signed event.
          </EmptyState>
        </Box>
      ) : filtered.length === 0 ? (
        <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2 }} py="xl">
          <EmptyState title="No threats match these filters">
            {threats.length} event{threats.length === 1 ? "" : "s"} are hidden by the current filters.
          </EmptyState>
        </Box>
      ) : (
        <ScrollArea.Autosize mah="calc(100vh - 320px)" type="hover">
          <Stack gap={8} pr={6}>
            {filtered.map((t) => {
              const meta = SEV[t.severity] ?? SEV.low;
              const stripe = `var(--mantine-color-${meta.color}-6)`;
              return (
                <Box
                  key={t.id}
                  px="md"
                  py="sm"
                  style={{
                    border: "1px solid var(--mantine-color-dark-4)",
                    borderLeft: `3px solid ${stripe}`,
                    borderRadius: 2,
                    background: "var(--mantine-color-dark-6)",
                  }}
                >
                  <Group justify="space-between" align="flex-start" gap="sm" wrap="nowrap">
                    <Box style={{ minWidth: 0, flex: 1 }}>
                      <Group gap={8} mb={6} wrap="wrap">
                        <Badge color={meta.color} radius={2} size="sm" variant="light">
                          {meta.label}
                        </Badge>
                        <Text ff="monospace" size="12px" c="gray.3" fw={600}>
                          {prettyType(t.threat_type)}
                        </Text>
                        {t.blocked ? (
                          <Badge color="signal" radius={2} size="sm" variant="filled">
                            Blocked in-path
                          </Badge>
                        ) : (
                          <Badge color="gray" radius={2} size="sm" variant="outline">
                            Observed
                          </Badge>
                        )}
                      </Group>
                      <Text size="13px" c="gray.4" style={{ lineHeight: 1.5 }}>
                        {t.description}
                      </Text>
                      <Group gap={14} mt={8}>
                        <Tooltip label={new Date(t.timestamp).toLocaleString()} withArrow>
                          <Text ff="monospace" size="11px" c="dimmed" style={{ cursor: "default" }}>
                            {timeAgo(t.timestamp)}
                          </Text>
                        </Tooltip>
                        <Text ff="monospace" size="11px" c="dark.2">
                          session {t.session_id.length > 18 ? `${t.session_id.slice(0, 18)}…` : t.session_id}
                        </Text>
                        <Text ff="monospace" size="11px" c="dark.3">
                          #{t.id}
                        </Text>
                      </Group>
                    </Box>
                  </Group>
                </Box>
              );
            })}
          </Stack>
        </ScrollArea.Autosize>
      )}

      <Text size="11px" c="dimmed" ta="center">
        Threats are read from the signed audit chain — verify integrity on the{" "}
        <Text component={Link} to="/audit" inherit c="brand.4" style={{ textDecoration: "none" }}>
          Audit
        </Text>{" "}
        view.
      </Text>
    </div>
  );
}
