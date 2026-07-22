import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Box, Group, Stack, Text, Button, Divider } from "@mantine/core";
import { fetchAlerts, sendTestAlert, fetchAttestation } from "../api/client";
import type { AlertEvent, AlertSeverity } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";
import { OverlayModal } from "../components/OverlayModal";

// Which page a given alert kind links to, for "View related".
const KIND_LINK: Record<string, { to: string; label: string }> = {
  new_attack_path: { to: "/attack-paths", label: "Open attack paths" },
  new_critical: { to: "/scans", label: "Open findings" },
  posture_drop: { to: "/posture", label: "Open PQC posture" },
  cert_expiring: { to: "/certificates", label: "Open certificates" },
  slo_breach: { to: "/frameworks", label: "Open frameworks" },
  remediation_resolved: { to: "/remediations", label: "Open remediation" },
};
const SEV_COLOR: Record<string, string> = { critical: "red", warning: "orange", info: "brand" };

function AlertDetail({ alert, onClose }: { alert: AlertEvent | null; onClose: () => void }) {
  const navigate = useNavigate();
  if (!alert) return null;
  const link = KIND_LINK[alert.kind];
  const meta = Object.entries(alert.metadata ?? {});
  return (
    <OverlayModal opened={!!alert} onClose={onClose} width={560} title={alert.title}>
      <Stack gap="sm">
        <Group gap={8} wrap="wrap">
          <Badge color={SEV_COLOR[alert.severity] ?? "gray"} radius={2} variant="light">{alert.severity}</Badge>
          <Badge color="gray" radius={2} variant="outline" tt="none">{alert.kind}</Badge>
          <Text size="11px" c="dimmed">{new Date(alert.timestamp).toLocaleString()}</Text>
          <Text size="11px" c="dimmed">· delivered to {alert.delivered} channel(s)</Text>
        </Group>
        <Box>
          <Text size="10px" fw={700} tt="uppercase" c="dimmed" mb={3} style={{ letterSpacing: "0.06em" }}>Details</Text>
          <Text size="13px" c="gray.3" style={{ lineHeight: 1.6 }}>{alert.message}</Text>
        </Box>
        {meta.length > 0 && (
          <Box>
            <Text size="10px" fw={700} tt="uppercase" c="dimmed" mb={4} style={{ letterSpacing: "0.06em" }}>Metadata</Text>
            <Box px="sm" py="xs" style={{ border: "1px solid var(--mantine-color-dark-4)", borderRadius: 2, background: "var(--mantine-color-dark-7)" }}>
              {meta.map(([k, v]) => (
                <Group key={k} justify="space-between" gap={12} wrap="nowrap">
                  <Text ff="monospace" size="11px" c="dark.2">{k}</Text>
                  <Text ff="monospace" size="11px" c="gray.3" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{v}</Text>
                </Group>
              ))}
            </Box>
          </Box>
        )}
        <Divider my={2} />
        <Group justify="flex-end" gap="sm">
          <Button size="xs" radius={2} variant="default" onClick={onClose}>Close</Button>
          {link && <Button size="xs" radius={2} color="brand" onClick={() => { onClose(); navigate(link.to); }}>{link.label}</Button>}
        </Group>
      </Stack>
    </OverlayModal>
  );
}

const severityStyle: Record<AlertSeverity, { chip: string; dot: string }> = {
  critical: { chip: "bg-rose-500/15 text-rose-300", dot: "bg-rose-400" },
  warning: { chip: "bg-amber-500/15 text-amber-300", dot: "bg-amber-400" },
  info: { chip: "bg-brand-500/15 text-brand-200", dot: "bg-brand-400" },
};

const kindLabel: Record<string, string> = {
  posture_drop: "Posture Drop",
  new_critical: "Critical Finding",
  cert_expiring: "Cert Expiry",
  test: "Test",
};

function AlertRow({ alert, onClick }: { alert: AlertEvent; onClick: () => void }) {
  const s = severityStyle[alert.severity] ?? severityStyle.info;
  return (
    <div className="flex items-start gap-3 px-4 py-3 cursor-pointer transition-colors hover:bg-white/[0.04]" onClick={onClick}>
      <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${s.dot}`} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-white">{alert.title}</span>
          <span className={`qw-chip ${s.chip}`}>{kindLabel[alert.kind] ?? alert.kind}</span>
        </div>
        <p className="mt-0.5 text-xs text-gray-400">{alert.message}</p>
      </div>
      <div className="shrink-0 text-right">
        <div className="text-[11px] text-gray-500">{new Date(alert.timestamp).toLocaleString()}</div>
        <div className="text-[10px] text-gray-600">{alert.delivered} delivered</div>
      </div>
    </div>
  );
}

function AttestationCard() {
  const { data: att, isLoading } = useQuery({ queryKey: ["attestation"], queryFn: fetchAttestation });

  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="qw-eyebrow">CBOM Attestation</div>
        {att && (
          <span className="qw-chip bg-emerald-500/15 text-emerald-300">
            <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="m4.5 12.75 6 6 9-13.5" />
            </svg>
            Signed
          </span>
        )}
      </div>
      {isLoading || !att ? (
        <Spinner className="py-6" />
      ) : (
        <div className="space-y-2 text-xs">
          <Field label="Algorithm" value={att.algorithm} />
          <Field label="Type" value={att.attestationType} mono />
          <Field label="Signer" value={`${att.signerFingerprint.slice(0, 24)}…`} mono />
          <Field label="BOM digest" value={`${att.bomDigest.slice(0, 28)}…`} mono />
          <Field label="Signature" value={`${att.signature.length / 2} bytes`} />
          <Field label="Public key" value={`${att.publicKey.length / 2} bytes`} />
          <div className="border-t border-white/[0.06] pt-2 text-[11px] leading-relaxed text-gray-500">{att.note}</div>
        </div>
      )}
    </Card>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-gray-500">{label}</span>
      <span className={`text-gray-200 ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

export default function AlertsPage() {
  const queryClient = useQueryClient();
  const [sel, setSel] = useState<AlertEvent | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ["alerts"], queryFn: () => fetchAlerts(100) });

  const testMutation = useMutation({
    mutationFn: sendTestAlert,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });

  if (isLoading) return <Spinner className="h-64" />;

  const alerts = data?.alerts ?? [];
  const critical = alerts.filter((a) => a.severity === "critical").length;

  return (
    <div className="space-y-5">
      <AlertDetail alert={sel} onClose={() => setSel(null)} />
      <PageHeader
        title="Alerts"
        subtitle="Continuous-attestation notifications on posture drops, critical findings, and cert expiry — click an alert for detail"
        actions={
          <button onClick={() => testMutation.mutate()} disabled={testMutation.isPending} className="qw-btn-ghost">
            {testMutation.isPending ? "Sending…" : "Send Test Alert"}
          </button>
        }
      />

      {testMutation.isSuccess && (
        <div className="qw-fade-up rounded border border-brand-500/30 bg-brand-500/10 px-4 py-2.5 text-sm text-brand-200">
          Test alert fired — delivered to {testMutation.data.delivered} channel(s).
          {!testMutation.data.enabled && " (Alerting is disabled in config; recorded but not delivered.)"}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Stat label="Status" value={data?.enabled ? "On" : "Off"} accent={data?.enabled ? "emerald" : "rose"} />
        <Stat label="Channels" value={data?.channels.length ?? 0} accent="brand" />
        <Stat label="Total Alerts" value={data?.total ?? 0} accent="violet" />
        <Stat label="Critical" value={critical} accent={critical > 0 ? "rose" : "emerald"} />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card>
            <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
              <div className="qw-eyebrow">Recent Alerts</div>
              <div className="flex gap-1.5">
                {(data?.channels ?? []).map((c) => (
                  <span key={c.id} className="qw-chip bg-white/5 text-gray-400">{c.type}:{c.id}</span>
                ))}
              </div>
            </div>
            {alerts.length === 0 ? (
              <EmptyState title="No alerts yet">
                Alerts fire when posture drops by ≥{data?.rules.postureDropThreshold ?? 5} points, a critical finding appears, or a certificate is expiring.
              </EmptyState>
            ) : (
              <div className="divide-y divide-white/5">
                {alerts.map((a) => (
                  <AlertRow key={a.id} alert={a} onClick={() => setSel(a)} />
                ))}
              </div>
            )}
          </Card>
        </div>

        <div className="space-y-5">
          <AttestationCard />
          <Card className="p-4">
            <div className="qw-eyebrow mb-3">Alert Rules</div>
            <div className="space-y-2 text-xs">
              <Field label="Posture drop ≥" value={`${data?.rules.postureDropThreshold ?? 5} pts`} />
              <Field label="On critical finding" value={data?.rules.alertOnCritical ? "Yes" : "No"} />
              <Field label="Cert expiry window" value={`${data?.rules.certExpiryDays ?? 30} days`} />
            </div>
            <p className="mt-3 border-t border-white/[0.06] pt-2 text-[11px] leading-relaxed text-gray-500">
              Configure channels (webhook / Slack) and thresholds in the <span className="font-mono">alerts</span> section of quantawatch.yaml.
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
}
