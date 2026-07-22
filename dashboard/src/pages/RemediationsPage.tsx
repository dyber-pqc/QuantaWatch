import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Group, Box, Text, Progress, Button, Menu, ActionIcon, CopyButton, Checkbox, ScrollArea, Stack, Tooltip } from "@mantine/core";
import { fetchMigrationPlans, fetchIntegrations, syncRemediations, remediateFinding, verifyFinding, setFindingStatus } from "../api/client";
import type { VerifyResult } from "../api/client";
import type { MigrationPlan, MigrationPriority, RemediationTicket } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const PRIO: Record<MigrationPriority, { label: string; short: string; color: string; order: number }> = {
  p0: { label: "P0 · Immediate", short: "P0", color: "red", order: 0 },
  p1: { label: "P1 · Before 2030 (CNSA 2.0)", short: "P1", color: "orange", order: 1 },
  p2: { label: "P2 · Advisory", short: "P2", color: "yellow", order: 2 },
  p3: { label: "P3", short: "P3", color: "gray", order: 3 },
};
const prettyStrategy = (s: string) => s.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
const CONF: Record<string, { label: string; color: string }> = {
  high: { label: "high confidence", color: "signal" },
  medium: { label: "medium confidence", color: "yellow" },
  low: { label: "low confidence · characterize", color: "orange" },
};
const rbKey = (id: string) => `qw-runbook-${id}`;

function CopyIcon({ copied }: { copied: boolean }) {
  return copied ? (
    <svg width={14} height={14} fill="none" viewBox="0 0 24 24" strokeWidth={2.4} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="m4.5 12.75 6 6 9-13.5" /></svg>
  ) : (
    <svg width={14} height={14} fill="none" viewBox="0 0 24 24" strokeWidth={1.7} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 0 1-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 0 1 1.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 0 0-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 0 1-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 0 0-3.375-3.375h-1.5a1.125 1.125 0 0 1-1.125-1.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H9.75" /></svg>
  );
}

function PatchDiff({ patch }: { patch: NonNullable<MigrationPlan["patch"]> }) {
  return (
    <Box mt="md" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2 }}>
      <Group justify="space-between" px="sm" py={6} style={{ borderBottom: "1px solid var(--mantine-color-dark-4)", background: "var(--mantine-color-dark-7)" }}>
        <Group gap={8}>
          <Text ff="monospace" size="11px" c="dimmed" tt="uppercase">{patch.kind}</Text>
          <Text ff="monospace" size="12px" c="gray.3">{patch.path}</Text>
        </Group>
        <CopyButton value={patch.after}>
          {({ copied, copy }) => (
            <Button size="compact-xs" variant="light" color={copied ? "signal" : "brand"} radius={2} leftSection={<CopyIcon copied={copied} />} onClick={copy}>
              {copied ? "Copied" : "Copy new config"}
            </Button>
          )}
        </CopyButton>
      </Group>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, lineHeight: 1.55 }}>
        {patch.before.split("\n").map((l, i) => (
          <div key={`b${i}`} style={{ padding: "1px 12px", background: "color-mix(in srgb, var(--mantine-color-red-6) 12%, transparent)", color: "var(--mantine-color-red-2)" }}>
            <span style={{ opacity: 0.5, marginRight: 8 }}>-</span>{l}
          </div>
        ))}
        {patch.after.split("\n").map((l, i) => (
          <div key={`a${i}`} style={{ padding: "1px 12px", background: "color-mix(in srgb, var(--mantine-color-signal-6) 12%, transparent)", color: "var(--mantine-color-signal-2)" }}>
            <span style={{ opacity: 0.5, marginRight: 8 }}>+</span>{l}
          </div>
        ))}
      </div>
      {patch.note && <Text size="11.5px" c="dimmed" px="sm" py={6} style={{ borderTop: "1px solid var(--mantine-color-dark-4)" }}>{patch.note}</Text>}
    </Box>
  );
}

function Runbook({ plan, doneArr, toggle, markAll, remediable }: {
  plan: MigrationPlan; doneArr: number[]; toggle: (i: number) => void; markAll: (v: boolean) => void;
  remediable: { id: string; displayName: string }[];
}) {
  const done = new Set(doneArr);
  const total = plan.steps.length;
  const pct = total ? Math.round((done.size / total) * 100) : 0;
  const complete = total > 0 && done.size === total;
  const prio = PRIO[plan.priority] ?? PRIO.p3;
  const qc = useQueryClient();
  const [ticket, setTicket] = useState<RemediationTicket | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const mut = useMutation({
    mutationFn: (integrationId: string) => remediateFinding(plan.findingId, { integrationId }),
    onSuccess: (t) => setTicket(t),
  });
  const verifyMut = useMutation({
    mutationFn: () => verifyFinding(plan.findingId),
    onSuccess: (r) => {
      setVerify(r);
      // A resolved/improved finding changes the work list and the graph.
      if (r.resolved || r.improved) qc.invalidateQueries({ queryKey: ["migration-plans"] });
      qc.invalidateQueries({ queryKey: ["attack-paths"] });
    },
  });
  const [showEvidence, setShowEvidence] = useState(false);
  const triageMut = useMutation({
    mutationFn: (s: "open" | "acknowledged" | "suppressed") => setFindingStatus(plan.findingId, s),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["migration-plans"] });
      qc.invalidateQueries({ queryKey: ["attack-paths"] });
    },
  });

  const runbookMd = `# ${plan.title}\n\nPriority: ${prio.label}\nStrategy: ${prettyStrategy(plan.strategy)}\nCurrent: ${plan.currentAlgorithm} → Target: ${plan.targetAlgorithm}\n\n${plan.steps.map((s, i) => `${i + 1}. [${done.has(i) ? "x" : " "}] ${s}`).join("\n")}`;

  return (
    <Card className="p-4">
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <div style={{ minWidth: 0 }}>
          <Group gap={8} mb={6}>
            <Badge variant="light" color={prio.color} radius={2} size="sm" tt="none" fw={700}>{prio.label}</Badge>
            <Badge variant="light" color="brand" radius={2} size="sm" tt="none" fw={600}>{prettyStrategy(plan.strategy)}</Badge>
            <Badge variant="light" color="gray" radius={2} size="sm" tt="none" fw={600}>effort: {plan.effort}</Badge>
            <Badge variant="light" color={CONF[plan.confidence]?.color ?? "gray"} radius={2} size="sm" tt="none" fw={600}>
              {CONF[plan.confidence]?.label ?? "confidence"}
            </Badge>
            {plan.status !== "open" && (
              <Badge variant="light" color={plan.status === "suppressed" ? "gray" : "orange"} radius={2} size="sm" tt="none" fw={700}>{plan.status}</Badge>
            )}
            {complete && <Badge variant="light" color="signal" radius={2} size="sm" tt="none" fw={700}>✓ complete</Badge>}
          </Group>
          <Text fw={700} ff="heading" fz="1.05rem" c="white">{plan.title}</Text>
          <Group gap={6} mt={4}>
            <Text ff="monospace" size="12px" c="red.3">{plan.currentAlgorithm || "classical"}</Text>
            <Text c="dimmed">→</Text>
            <Text ff="monospace" size="12px" c="signal.3">{plan.targetAlgorithm}</Text>
          </Group>
        </div>
        <CopyButton value={runbookMd}>
          {({ copied, copy }) => (
            <Button size="compact-sm" variant="default" radius={2} leftSection={<CopyIcon copied={copied} />} onClick={copy}>{copied ? "Copied" : "Copy runbook"}</Button>
          )}
        </CopyButton>
      </Group>

      <Text size="12.5px" c="dimmed" mt="sm" style={{ lineHeight: 1.5 }}>{plan.rationale}</Text>

      {/* Evidence trail — what the probe actually observed */}
      {plan.evidence?.length > 0 && (
        <Box mt="sm">
          <Button size="compact-xs" variant="subtle" color="gray" radius={2} onClick={() => setShowEvidence((v) => !v)}
            leftSection={<span style={{ fontFamily: "monospace" }}>{showEvidence ? "▾" : "▸"}</span>}>
            Evidence ({plan.evidence.length})
          </Button>
          {showEvidence && (
            <Box mt={4} px="sm" py="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
              {plan.evidence.map((e, i) => (
                <Text key={i} ff="monospace" size="11px" c="dark.1" style={{ lineHeight: 1.6 }}>{e}</Text>
              ))}
            </Box>
          )}
        </Box>
      )}

      {/* Triage — acknowledge (accepted risk) or suppress (false positive) */}
      <Group gap={6} mt="sm">
        <Text size="10px" fw={700} tt="uppercase" c="dimmed" style={{ letterSpacing: "0.06em" }}>Triage</Text>
        {(["open", "acknowledged", "suppressed"] as const).map((s) => (
          <Button key={s} size="compact-xs" radius={2} loading={triageMut.isPending && triageMut.variables === s}
            variant={plan.status === s ? "filled" : "default"}
            color={s === "suppressed" ? "gray" : s === "acknowledged" ? "orange" : "brand"}
            onClick={() => triageMut.mutate(s)} disabled={plan.status === s}>
            {s === "open" ? "Reopen" : s === "acknowledged" ? "Acknowledge" : "Suppress"}
          </Button>
        ))}
      </Group>

      {/* Progress */}
      <Group justify="space-between" mt="md" mb={4}>
        <Text ff="monospace" size="11px" tt="uppercase" c="dimmed" style={{ letterSpacing: "0.06em" }}>Runbook · {done.size}/{total} steps</Text>
        <Group gap={4}>
          <Button size="compact-xs" variant="subtle" color="gray" radius={2} onClick={() => markAll(true)}>Mark all</Button>
          <Button size="compact-xs" variant="subtle" color="gray" radius={2} onClick={() => markAll(false)}>Reset</Button>
        </Group>
      </Group>
      <Progress value={pct} color={complete ? "signal" : "brand"} size="sm" radius={0} />

      {/* Steps */}
      <Stack gap={2} mt="sm">
        {plan.steps.map((step, i) => {
          const isDone = done.has(i);
          return (
            <Group key={i} gap={10} align="flex-start" wrap="nowrap" onClick={() => toggle(i)}
              style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 2, borderLeft: `2px solid ${isDone ? "var(--mantine-color-signal-6)" : "var(--mantine-color-dark-4)"}`, background: isDone ? "color-mix(in srgb, var(--mantine-color-signal-6) 7%, transparent)" : "transparent" }}>
              <Checkbox checked={isDone} onChange={() => {}} size="xs" color="signal" radius={2} styles={{ input: { cursor: "pointer" } }} mt={1} />
              <Text ff="monospace" size="11px" c="dimmed" mt={2} style={{ width: 16, flexShrink: 0 }}>{i + 1}</Text>
              <Text size="13px" style={{ flex: 1, color: isDone ? "var(--mantine-color-dark-3)" : "var(--mantine-color-dark-0)", textDecoration: isDone ? "line-through" : "none" }}>{step}</Text>
              <CopyButton value={step}>
                {({ copied, copy }) => (
                  <Tooltip label={copied ? "Copied" : "Copy step"} withArrow>
                    <ActionIcon size="sm" variant="subtle" color={copied ? "signal" : "gray"} radius={2} onClick={(e) => { e.stopPropagation(); copy(); }}><CopyIcon copied={copied} /></ActionIcon>
                  </Tooltip>
                )}
              </CopyButton>
            </Group>
          );
        })}
      </Stack>

      {plan.patch && <PatchDiff patch={plan.patch} />}

      {/* Verify — actively re-check whether the fix is live */}
      <Group mt="md" gap={8} align="center">
        <Button
          variant="light"
          color="signal"
          radius={2}
          size="compact-sm"
          loading={verifyMut.isPending}
          onClick={() => verifyMut.mutate()}
          leftSection={<svg width={14} height={14} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" /></svg>}
        >
          Verify fix
        </Button>
        {verifyMut.isError && <Text size="xs" c="red.4">re-check failed</Text>}
        {verify && (
          verify.verifiable ? (
            <Group gap={8} align="center" wrap="nowrap">
              <Badge radius={2} variant="light" tt="none" fw={700}
                color={verify.resolved ? "signal" : verify.improved ? "orange" : "red"}>
                {verify.resolved ? "✓ resolved" : verify.improved ? "improved" : "not fixed yet"}
              </Badge>
              <Text size="11.5px" c="dimmed" style={{ lineHeight: 1.4 }}>{verify.detail}</Text>
            </Group>
          ) : (
            <Group gap={6} align="center" wrap="nowrap">
              <Badge radius={2} variant="light" color="gray" tt="none">manual re-check</Badge>
              <Text size="11.5px" c="dimmed" style={{ lineHeight: 1.4 }}>{verify.guidance}</Text>
            </Group>
          )
        )}
      </Group>

      {/* Actions */}
      <Group mt="sm" gap={8}>
        {ticket ? (
          <Button component="a" href={ticket.externalUrl} target="_blank" rel="noreferrer" variant="light" color="signal" radius={2} size="compact-sm">{ticket.externalId} ↗ opened</Button>
        ) : remediable.length > 0 ? (
          <Menu shadow="md" radius={2} position="bottom-start">
            <Menu.Target><Button variant="filled" color="brand" radius={2} size="compact-sm" loading={mut.isPending}>Create Ticket / PR</Button></Menu.Target>
            <Menu.Dropdown>
              {remediable.map((it) => <Menu.Item key={it.id} onClick={() => mut.mutate(it.id)}>{it.displayName}</Menu.Item>)}
            </Menu.Dropdown>
          </Menu>
        ) : (
          <Tooltip label="Configure a Jira or Linear integration to file tickets" withArrow>
            <Button variant="default" radius={2} size="compact-sm" disabled>Create Ticket / PR</Button>
          </Tooltip>
        )}
        {mut.isError && <Text size="xs" c="red.4">failed to create ticket</Text>}
      </Group>
    </Card>
  );
}

export default function RemediationsPage() {
  const { data, isLoading } = useQuery({ queryKey: ["migration-plans"], queryFn: fetchMigrationPlans });
  const { data: integrationsData } = useQuery({ queryKey: ["integrations"], queryFn: fetchIntegrations });
  const syncMut = useMutation({ mutationFn: syncRemediations });

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [done, setDone] = useState<Record<string, number[]>>({});

  const plans = [...(data?.plans ?? [])].sort((a, b) => (PRIO[a.priority]?.order ?? 9) - (PRIO[b.priority]?.order ?? 9));

  useEffect(() => {
    const init: Record<string, number[]> = {};
    plans.forEach((p) => {
      try { init[p.findingId] = JSON.parse(localStorage.getItem(rbKey(p.findingId)) || "[]"); } catch { init[p.findingId] = []; }
    });
    setDone(init);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  if (isLoading) return <Spinner className="h-64" />;

  const selected = plans.find((p) => p.findingId === selectedId) ?? plans[0];
  const remediable = (integrationsData?.integrations ?? [])
    .filter((i) => i.capabilities.includes("create_remediation"))
    .map((i) => ({ id: i.id, displayName: i.displayName }));

  const persist = (id: string, arr: number[]) => { localStorage.setItem(rbKey(id), JSON.stringify(arr)); setDone((prev) => ({ ...prev, [id]: arr })); };
  const toggle = (id: string, i: number) => { const s = new Set(done[id] ?? []); s.has(i) ? s.delete(i) : s.add(i); persist(id, [...s]); };
  const markAll = (id: string, n: number, v: boolean) => persist(id, v ? Array.from({ length: n }, (_, i) => i) : []);

  const count = (p: MigrationPriority) => plans.filter((x) => x.priority === p).length;
  const totalSteps = plans.reduce((s, p) => s + p.steps.length, 0);
  const doneSteps = plans.reduce((s, p) => s + (done[p.findingId]?.length ?? 0), 0);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Remediation Runbooks"
        subtitle="Every migration turned into a guided, checkable workflow — copy the exact change, track progress, and file the ticket. Progress is saved per finding."
        actions={<Button variant="default" radius={2} size="compact-sm" loading={syncMut.isPending} onClick={() => syncMut.mutate()}>Sync ticket status</Button>}
      />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="P0 · Immediate" value={count("p0")} accent={count("p0") > 0 ? "rose" : "emerald"} />
        <Stat label="P1 · By 2030" value={count("p1")} accent="amber" />
        <Stat label="P2 · Advisory" value={count("p2")} accent="brand" />
        <Stat label="Steps done" value={`${doneSteps}/${totalSteps}`} accent="violet" sub="across all runbooks" />
      </div>

      {plans.length === 0 ? (
        <Card><EmptyState title="Nothing to remediate">No findings currently need migration — every discovered asset is PQC-ready or hybrid.</EmptyState></Card>
      ) : (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          {/* Plan index */}
          <Card>
            <div style={{ borderBottom: "1px solid var(--mantine-color-dark-4)", padding: "10px 14px" }}>
              <Text ff="monospace" size="11px" tt="uppercase" c="dimmed" style={{ letterSpacing: "0.08em" }}>Findings · {plans.length}</Text>
            </div>
            <ScrollArea.Autosize mah={620}>
              {plans.map((p) => {
                const prio = PRIO[p.priority] ?? PRIO.p3;
                const d = done[p.findingId]?.length ?? 0;
                const pct = p.steps.length ? Math.round((d / p.steps.length) * 100) : 0;
                const active = selected?.findingId === p.findingId;
                return (
                  <button key={p.findingId} onClick={() => setSelectedId(p.findingId)}
                    style={{ display: "block", width: "100%", textAlign: "left", cursor: "pointer", border: "none", padding: "10px 14px", background: active ? "color-mix(in srgb, var(--mantine-color-brand-6) 14%, transparent)" : "transparent", borderLeft: active ? "2px solid var(--mantine-color-brand-5)" : "2px solid transparent", borderBottom: "1px solid var(--mantine-color-dark-6)" }}>
                    <Group gap={6} mb={4} wrap="nowrap">
                      <Badge variant="light" color={prio.color} radius={2} size="xs" tt="none" fw={700}>{prio.short}</Badge>
                      <Text size="12.5px" fw={active ? 700 : 500} c={active ? "white" : "gray.3"} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.title}</Text>
                    </Group>
                    <Group gap={8} wrap="nowrap">
                      <Progress value={pct} color={pct === 100 ? "signal" : "brand"} size="xs" radius={0} style={{ flex: 1 }} />
                      <Text ff="monospace" size="9.5px" c="dimmed" style={{ flexShrink: 0 }}>{d}/{p.steps.length}</Text>
                    </Group>
                  </button>
                );
              })}
            </ScrollArea.Autosize>
          </Card>

          {/* Runbook */}
          <div className="xl:col-span-2">
            {selected && (
              <Runbook
                key={selected.findingId}
                plan={selected}
                doneArr={done[selected.findingId] ?? []}
                toggle={(i) => toggle(selected.findingId, i)}
                markAll={(v) => markAll(selected.findingId, selected.steps.length, v)}
                remediable={remediable}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
