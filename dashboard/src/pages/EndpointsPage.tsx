import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Box, Group, Stack, Text, Button, ActionIcon, Collapse, CopyButton, Code, Divider } from "@mantine/core";
import { fetchEndpoints, fetchEnrollInfo, deleteEndpoint } from "../api/client";
import type { Endpoint, EndpointComponent } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";
import { OverlayModal } from "../components/OverlayModal";

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

// Per-component-type knowledge: what it is, why it's quantum-exposed, and the
// concrete path to post-quantum. `effort` sets expectations honestly — some of
// these are a config toggle, others need new silicon.
type Effort = "config" | "software" | "hardware";
const EFFORT_META: Record<Effort, { label: string; color: string; note: string }> = {
  config: { label: "Config change", color: "teal", note: "A setting or policy change — doable now, no new hardware." },
  software: { label: "Software / re-key", color: "orange", note: "Reissue, re-encrypt or upgrade software — feasible now with planning." },
  hardware: { label: "Hardware / firmware", color: "red", note: "Bound to firmware or silicon — waits on an OEM/standards update." },
};

interface ComponentKb {
  what: string;
  quantumRisk: string;
  steps: string[];
  effort: Effort;
}
const COMPONENT_KB: Record<string, ComponentKb> = {
  secure_boot: {
    what: "UEFI Secure Boot verifies each stage of the boot chain (firmware → bootloader → kernel) against digital signatures held in firmware (PK / KEK / db). It's what stops an attacker booting tampered code.",
    quantumRisk: "Boot images are signed with RSA or ECDSA. Shor's algorithm breaks both, so a quantum-capable attacker could forge a signature and boot malicious code that Secure Boot would accept as genuine.",
    steps: [
      "Confirm signatures are at least RSA-3072 / ECDSA-P384 (CNSA-2.0 classical floor) via a firmware update.",
      "Track your OEM's roadmap for PQC boot signatures (stateful hash-based LMS/XMSS, or ML-DSA) — this ships in firmware, not the OS.",
      "Keep the machine on a supported firmware branch so PQC db updates can be applied when available.",
    ],
    effort: "hardware",
  },
  tpm: {
    what: "The TPM 2.0 is the hardware root of trust: it seals disk-encryption keys, stores boot measurements, and signs attestations proving the machine's state.",
    quantumRisk: "TPM 2.0 implements only RSA-2048, ECC-P256 and SHA-256. RSA/ECC are broken by Shor, and keys sealed to the TPM cannot be re-keyed to a PQC algorithm the chip doesn't have — so migration needs new silicon.",
    steps: [
      "Inventory what depends on TPM keys (BitLocker, attestation, credential guard) so you know the blast radius.",
      "Follow the TCG's PQC work; plan a hardware refresh cycle for TPMs that add PQC once standardized.",
      "In the interim, ensure sealed secrets are also protected by a quantum-safe layer (e.g. AES-256 at rest).",
    ],
    effort: "hardware",
  },
  measured_boot: {
    what: "Measured boot hashes each boot component and extends those hashes into TPM PCR banks, producing a tamper-evident log used for remote attestation.",
    quantumRisk: "If the PCR bank uses SHA-1, it is already collision-broken (classically). Grover's algorithm also halves hash pre-image strength, so SHA-1/224 must move to SHA-256+.",
    steps: [
      "Enable the SHA-256 PCR bank in firmware (BIOS/UEFI setup → TPM/PCR settings) and disable the SHA-1 bank.",
      "Re-seal any PCR-bound secrets (e.g. BitLocker) against the SHA-256 bank after switching.",
      "Re-run the endpoint agent to confirm the measured-boot component now reports SHA-256.",
    ],
    effort: "config",
  },
  disk_encryption: {
    what: "Full-disk encryption (BitLocker / LUKS / FileVault) protects data at rest so a stolen disk is unreadable.",
    quantumRisk: "AES itself is quantum-resistant, but Grover's algorithm halves its effective strength: AES-128 drops to ~64-bit security. AES-256 (which drops to ~128-bit) is the quantum-safe target. CBC mode is also weaker than XTS for disk.",
    steps: [
      "Re-encrypt the volume with AES-256 (BitLocker: 'XtsAes256'; LUKS: aes-xts-plain64 512-bit key).",
      "Rotate the key after upgrading so no data remains under the old 128-bit key.",
      "Re-run the agent to confirm the disk-encryption component reports AES-256.",
    ],
    effort: "software",
  },
  ssh_host_key: {
    what: "The SSH host key is the server's cryptographic identity — clients pin it to detect man-in-the-middle. Separately, the SSH key exchange establishes the session key.",
    quantumRisk: "ssh-rsa (SHA-1 RSA) is deprecated and weak; Ed25519 is strong classically but broken by Shor. No standardized PQC host-key format ships broadly yet, but OpenSSH already offers a hybrid PQC key exchange that protects the session against harvest-now-decrypt-later.",
    steps: [
      "Remove deprecated ssh-rsa / DSA host keys; keep Ed25519 as the classical identity.",
      "Enable the hybrid PQC key exchange in sshd (KexAlgorithms sntrup761x25519-sha512@openssh.com, or mlkem768x25519-sha256 on newer OpenSSH).",
      "Front the service with the QuantaWatch PQC overlay to guarantee an X25519MLKEM768 channel regardless of client.",
    ],
    effort: "software",
  },
  certificate: {
    what: "This is the machine's X.509 identity certificate, used for TLS, device authentication or code signing.",
    quantumRisk: "It's signed with sha256WithRSAEncryption. RSA signatures are forgeable by Shor's algorithm, so the identity can be impersonated by a quantum attacker.",
    steps: [
      "Reissue as a hybrid certificate: a classical leaf plus an ML-DSA-65 binding — the QuantaWatch internal CA (Certificates page) issues these in one click.",
      "Shorten the validity period so the crypto is rotated more often during the transition.",
      "Move to a native ML-DSA certificate once your relying parties support it.",
    ],
    effort: "software",
  },
  crypto_library: {
    what: "A cryptographic library or dependency used by software on this host.",
    quantumRisk: "If it implements RSA/ECC/DH for key exchange or signatures, those primitives are broken by Shor's algorithm and must move to ML-KEM / ML-DSA.",
    steps: [
      "Upgrade to a version that offers PQC (ML-KEM / ML-DSA) or a hybrid mode.",
      "Prefer hybrid key exchange so you keep classical security during migration.",
      "Re-scan to confirm the dependency reports a PQC-capable posture.",
    ],
    effort: "software",
  },
};

function kbFor(category: string): ComponentKb {
  return (
    COMPONENT_KB[category] ?? {
      what: "A cryptographic component reported by the host agent.",
      quantumRisk: "Classical public-key cryptography (RSA/ECC/DH) is broken by a large quantum computer; symmetric strength is halved by Grover's algorithm.",
      steps: ["Move to NIST PQC standards (ML-KEM for key exchange, ML-DSA for signatures) or AES-256 for symmetric."],
      effort: "software",
    }
  );
}

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

function ComponentRow({ c, onClick }: { c: EndpointComponent; onClick: () => void }) {
  return (
    <Box
      px="sm"
      py="xs"
      onClick={onClick}
      style={{ cursor: "pointer", border: "1px solid var(--mantine-color-dark-4)", borderLeft: `3px solid var(--mantine-color-${PQC_COLOR[c.pqcStatus] ?? "gray"}-6)`, borderRadius: 2, background: "var(--mantine-color-dark-7)" }}
      className="qw-hoverable"
    >
      <Group justify="space-between" gap={8} wrap="nowrap">
        <Group gap={8} wrap="nowrap" style={{ minWidth: 0 }}>
          <Text fz={14} style={{ flexShrink: 0 }}>{CAT_ICON[c.category] ?? "🔒"}</Text>
          <Text size="13px" fw={600} c="gray.2" truncate>{c.name}</Text>
          {c.algorithm && <Text ff="monospace" size="11px" c="gray.5" truncate>{c.algorithm}</Text>}
        </Group>
        <Group gap={6} wrap="nowrap" style={{ flexShrink: 0 }}>
          {c.severity !== "info" && <Badge color={SEV_COLOR[c.severity] ?? "gray"} radius={2} size="xs" variant="light">{c.severity}</Badge>}
          <PqcBadge status={c.pqcStatus} size="xs" />
          <svg width={13} height={13} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" style={{ color: "var(--mantine-color-dark-2)", flexShrink: 0 }}><path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" /></svg>
        </Group>
      </Group>
      <Text size="11px" c="dimmed" mt={4} style={{ lineHeight: 1.5 }}>{c.detail}</Text>
    </Box>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Box>
      <Text size="10px" fw={700} tt="uppercase" c="dimmed" mb={4} style={{ letterSpacing: "0.08em" }}>{label}</Text>
      {children}
    </Box>
  );
}

function ComponentDetail({ host, component, onClose }: { host: string; component: EndpointComponent | null; onClose: () => void }) {
  if (!component) return null;
  const kb = kbFor(component.category);
  const effort = EFFORT_META[kb.effort];
  const isSafe = component.pqcStatus === "pqc_ready" || component.pqcStatus === "hybrid";
  return (
    <OverlayModal
      opened={!!component}
      onClose={onClose}
      width={640}
      title={`${CAT_ICON[component.category] ?? "🔒"}  ${component.name}`}
    >
      <Stack gap="md">
        <Group gap={8} wrap="wrap">
          {component.algorithm && <Badge color="gray" radius={2} variant="light" tt="none" style={{ fontFamily: "monospace" }}>{component.algorithm}</Badge>}
          <PqcBadge status={component.pqcStatus} />
          {component.severity !== "info" && <Badge color={SEV_COLOR[component.severity] ?? "gray"} radius={2} variant="light">{component.severity}</Badge>}
          <Text size="11px" c="dimmed">on {host}</Text>
        </Group>

        <Section label="What it is">
          <Text size="13px" c="gray.3" style={{ lineHeight: 1.6 }}>{kb.what}</Text>
        </Section>

        <Section label="Current cryptography">
          <Text size="13px" c="gray.3" style={{ lineHeight: 1.6 }}>{component.detail}</Text>
        </Section>

        <Section label="Why it's quantum-exposed">
          <Text size="13px" c="gray.3" style={{ lineHeight: 1.6 }}>{kb.quantumRisk}</Text>
        </Section>

        <Divider />

        <Section label="Path to post-quantum">
          <Group gap={8} mb={8}>
            <Badge color={effort.color} radius={2} variant="light">{effort.label}</Badge>
            <Text size="11px" c="dimmed">{effort.note}</Text>
          </Group>
          {isSafe ? (
            <Text size="13px" c="signal.4">This component already reports a quantum-safe posture — keep it current.</Text>
          ) : (
            <Stack gap={8}>
              {kb.steps.map((s, i) => (
                <Group key={i} gap={8} wrap="nowrap" align="flex-start">
                  <Box style={{ flexShrink: 0, width: 18, height: 18, borderRadius: 3, background: "var(--mantine-color-dark-5)", display: "grid", placeItems: "center" }}>
                    <Text size="10px" fw={700} c="gray.3">{i + 1}</Text>
                  </Box>
                  <Text size="13px" c="gray.3" style={{ lineHeight: 1.55 }}>{s}</Text>
                </Group>
              ))}
            </Stack>
          )}
        </Section>
      </Stack>
    </OverlayModal>
  );
}

function EndpointCard({ e, onDelete }: { e: Endpoint; onDelete: () => void }) {
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState<EndpointComponent | null>(null);
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
            e.components.map((c, i) => <ComponentRow key={`${c.category}-${i}`} c={c} onClick={() => setSel(c)} />)
          )}
          <Text ff="monospace" size="10px" c="dark.3" mt={2}>
            {e.agentVersion ?? "agent"} · last report {new Date(e.lastReport).toLocaleString()}
          </Text>
        </Stack>
      </Collapse>
      <ComponentDetail host={e.hostname} component={sel} onClose={() => setSel(null)} />
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
