import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Badge,
  Box,
  Group,
  Stack,
  Text,
  Button,
  Menu,
  ScrollArea,
  Tooltip,
  Alert,
} from "@mantine/core";
import {
  fetchCryptoPolicies,
  fetchCryptoPolicy,
  evaluateCryptoPolicies,
  enforceCryptoPolicy,
  fetchIntegrations,
} from "../api/client";
import type { CryptoPolicyResult } from "../api/types";
import { PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const SEV_COLOR: Record<string, string> = {
  critical: "red",
  high: "orange",
  medium: "yellow",
  low: "gray",
  info: "gray",
};

const prettyCat = (s: string) =>
  s.split(/[_ -]+/).filter(Boolean).map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");

function StatusBadge({ status }: { status: string }) {
  return status === "violated" ? (
    <Badge color="red" radius={2} variant="filled" size="sm">Violated</Badge>
  ) : (
    <Badge color="signal" radius={2} variant="light" size="sm">Compliant</Badge>
  );
}

export default function CryptoPoliciesPage() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const [enforceResult, setEnforceResult] = useState<string | null>(null);

  const { data: board, isLoading } = useQuery({
    queryKey: ["crypto-policies"],
    queryFn: fetchCryptoPolicies,
  });

  const policies = board?.policies ?? [];
  const activeId = selected ?? policies[0]?.id ?? null;

  const { data: detail } = useQuery({
    queryKey: ["crypto-policy", activeId],
    queryFn: () => fetchCryptoPolicy(activeId as string),
    enabled: !!activeId,
  });

  const { data: integrations } = useQuery({
    queryKey: ["integrations"],
    queryFn: fetchIntegrations,
  });
  const remediators = useMemo(() => {
    const list = Array.isArray(integrations) ? integrations : integrations?.integrations ?? [];
    return list.filter((i) => (i.capabilities ?? []).includes("create_remediation"));
  }, [integrations]);

  const reevaluate = useMutation({
    mutationFn: evaluateCryptoPolicies,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["crypto-policies"] });
      qc.invalidateQueries({ queryKey: ["crypto-policy"] });
    },
  });

  const enforce = useMutation({
    mutationFn: (integrationId: string) =>
      enforceCryptoPolicy(activeId as string, { integrationId }),
    onSuccess: (r) => {
      setEnforceResult(
        r.enforced > 0
          ? `Opened ${r.enforced} ${r.action === "create_ticket" ? "ticket(s)" : "PR(s)"} for ${r.policyId}.`
          : r.message ?? "Nothing enforced.",
      );
      qc.invalidateQueries({ queryKey: ["remediations"] });
    },
    onError: (e: unknown) => setEnforceResult(`Enforcement failed: ${String(e)}`),
  });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Crypto-Agility Policies"
        subtitle="Declarative crypto policy over the whole estate — evaluate, detect drift, and enforce via connectors"
        actions={
          <Button
            size="xs"
            radius={2}
            variant="light"
            color="brand"
            loading={reevaluate.isPending}
            onClick={() => reevaluate.mutate()}
          >
            Re-evaluate (acknowledge drift)
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Policies" value={board?.total ?? 0} accent="brand" />
        <Stat label="Violated" value={board?.violated ?? 0} accent={(board?.violated ?? 0) > 0 ? "rose" : "emerald"} />
        <Stat label="Critical violations" value={board?.criticalViolations ?? 0} accent={(board?.criticalViolations ?? 0) > 0 ? "rose" : "emerald"} />
        <Stat label="Compliant" value={board?.compliant ?? 0} accent="emerald" />
      </div>

      {isLoading ? (
        <Spinner className="py-16" />
      ) : policies.length === 0 ? (
        <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2 }} py="xl">
          <EmptyState title="No policies">Declare crypto_policies in config, or the built-in CNSA-2.0 defaults will appear after a scan.</EmptyState>
        </Box>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,360px)_1fr]">
          {/* Master: policy list */}
          <Stack gap={8}>
            {policies.map((p) => (
              <PolicyRow
                key={p.id}
                p={p}
                active={p.id === activeId}
                onClick={() => { setSelected(p.id); setEnforceResult(null); }}
              />
            ))}
          </Stack>

          {/* Detail */}
          <Box style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-6)" }} p="md">
            {detail ? (
              <Detail
                d={detail}
                remediators={remediators.map((r) => ({ id: r.id, name: r.displayName ?? r.id }))}
                enforcing={enforce.isPending}
                onEnforce={(iid) => { setEnforceResult(null); enforce.mutate(iid); }}
                result={enforceResult}
              />
            ) : (
              <Text c="dimmed" size="sm">Select a policy.</Text>
            )}
          </Box>
        </div>
      )}
    </div>
  );
}

function PolicyRow({ p, active, onClick }: { p: CryptoPolicyResult; active: boolean; onClick: () => void }) {
  const newCount = p.drift?.new?.length ?? 0;
  return (
    <Box
      onClick={onClick}
      px="md"
      py="sm"
      style={{
        cursor: "pointer",
        border: "1px solid var(--mantine-color-dark-4)",
        borderLeft: `3px solid var(--mantine-color-${SEV_COLOR[p.severity] ?? "gray"}-6)`,
        borderRadius: 2,
        background: active ? "var(--mantine-color-dark-5)" : "var(--mantine-color-dark-6)",
      }}
    >
      <Group justify="space-between" gap={6} wrap="nowrap">
        <Text size="13px" fw={600} c="gray.2" style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {p.name}
        </Text>
        <StatusBadge status={p.status} />
      </Group>
      <Group gap={6} mt={8} wrap="wrap">
        <Badge color={SEV_COLOR[p.severity] ?? "gray"} radius={2} size="xs" variant="light">{p.severity}</Badge>
        {p.status === "violated" && (
          <Badge color="gray" radius={2} size="xs" variant="outline">{p.violationCount} violations</Badge>
        )}
        {p.drift?.regressed && <Badge color="red" radius={2} size="xs" variant="filled">regressed</Badge>}
        {newCount > 0 && <Badge color="orange" radius={2} size="xs" variant="light">+{newCount} new</Badge>}
        {typeof p.daysToDeadline === "number" && (
          <Badge color={p.deadlinePassed ? "red" : "gray"} radius={2} size="xs" variant="outline">
            {p.deadlinePassed ? "deadline passed" : `${p.daysToDeadline}d to deadline`}
          </Badge>
        )}
      </Group>
    </Box>
  );
}

function Detail({
  d,
  remediators,
  enforcing,
  onEnforce,
  result,
}: {
  d: CryptoPolicyResult;
  remediators: { id: string; name: string }[];
  enforcing: boolean;
  onEnforce: (integrationId: string) => void;
  result: string | null;
}) {
  const isPr = d.action === "open_pr";
  const isTicket = d.action === "create_ticket";
  const needsConnector = isPr || isTicket;
  return (
    <Stack gap="sm">
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Box style={{ minWidth: 0 }}>
          <Group gap={8}>
            <Text size="15px" fw={700} c="gray.1">{d.name}</Text>
            <StatusBadge status={d.status} />
          </Group>
          <Text size="12.5px" c="dimmed" mt={4} style={{ lineHeight: 1.5 }}>{d.description}</Text>
        </Box>
        {d.status === "violated" && needsConnector && (
          <Menu radius={2} position="bottom-end">
            <Menu.Target>
              <Button size="xs" radius={2} color="brand" loading={enforcing} disabled={remediators.length === 0}>
                Enforce · {isPr ? "open PRs" : "open tickets"}
              </Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Label>Via connector</Menu.Label>
              {remediators.length === 0 ? (
                <Menu.Item disabled>No create-remediation integration</Menu.Item>
              ) : (
                remediators.map((r) => (
                  <Menu.Item key={r.id} onClick={() => onEnforce(r.id)}>{r.name}</Menu.Item>
                ))
              )}
            </Menu.Dropdown>
          </Menu>
        )}
        {d.status === "violated" && d.action === "alert" && (
          <Button size="xs" radius={2} color="brand" loading={enforcing} onClick={() => onEnforce("")}>
            Enforce · raise alerts
          </Button>
        )}
      </Group>

      {result && (
        <Alert color="signal" radius={2} variant="light" p="xs">
          <Text size="12px">{result}</Text>
        </Alert>
      )}

      {d.status === "compliant" ? (
        <Box py="lg">
          <EmptyState title="Compliant">No assets violate this policy.</EmptyState>
        </Box>
      ) : (
        <ScrollArea.Autosize mah="calc(100vh - 360px)">
          <Stack gap={6}>
            {d.violations.map((v) => (
              <Box
                key={v.fingerprint}
                px="sm"
                py="xs"
                style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}
              >
                <Group justify="space-between" gap={8} wrap="nowrap">
                  <Text ff="monospace" size="12px" c="gray.3" style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {v.location}
                  </Text>
                  <Group gap={6} wrap="nowrap">
                    <Badge color={SEV_COLOR[v.severity] ?? "gray"} radius={2} size="xs" variant="light">{v.severity}</Badge>
                    <Badge color="gray" radius={2} size="xs" variant="outline">{prettyCat(v.category)}</Badge>
                  </Group>
                </Group>
                <Group gap={12} mt={6}>
                  {v.algorithm && <Text ff="monospace" size="11px" c="dark.2">{v.algorithm}</Text>}
                  {v.plan && (
                    <Tooltip label={v.plan.rationale} multiline w={280} withArrow>
                      <Text size="11px" c="brand.4" style={{ cursor: "help" }}>
                        → {v.plan.targetAlgorithm} ({v.plan.strategy.replace(/-/g, " ")})
                      </Text>
                    </Tooltip>
                  )}
                </Group>
              </Box>
            ))}
          </Stack>
        </ScrollArea.Autosize>
      )}
    </Stack>
  );
}
