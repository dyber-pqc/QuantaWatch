import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Badge, Box, Group, Stack, Text, Button, TextInput, NumberInput, SegmentedControl,
  Alert, Tooltip, Code, Divider,
} from "@mantine/core";
import {
  fetchCertificates, fetchCa, issueCertificate, verifyCertBinding, renewCertificate, revokeCertificate,
} from "../api/client";
import type { Certificate, IssueResult } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState } from "../components/ui";

const PQC_COLOR: Record<string, string> = {
  classical_weak: "red", classical_secure: "orange", unknown: "gray", hybrid: "cyan", pqc_ready: "signal",
};

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function daysUntil(iso: string) {
  return Math.round((new Date(iso).getTime() - Date.now()) / 86400000);
}

function VerifyResult({ ok }: { ok: boolean }) {
  return (
    <Badge color={ok ? "signal" : "red"} radius={2} size="xs" variant="light"
      leftSection={<Box w={6} h={6} style={{ borderRadius: "50%", background: `var(--mantine-color-${ok ? "signal" : "red"}-5)` }} />}>
      {ok ? "ML-DSA binding valid" : "binding INVALID"}
    </Badge>
  );
}

function CertRow({ c, onChange }: { c: Certificate; onChange: () => void }) {
  const isHybrid = c.keyType === "hybrid" && !!c.mldsaSignature;
  const revoked = c.status === "revoked";
  const dleft = daysUntil(c.notAfter);
  const expiring = dleft <= 30 && dleft >= 0;
  const expired = dleft < 0;

  const verify = useMutation({
    mutationFn: () => verifyCertBinding({ certPem: c.certPem, mldsaPublicKey: c.mldsaPublicKey ?? "", mldsaSignature: c.mldsaSignature ?? "" }),
  });
  const renew = useMutation({ mutationFn: () => renewCertificate(c.id), onSuccess: onChange });
  const revoke = useMutation({ mutationFn: () => revokeCertificate(c.id), onSuccess: onChange });

  return (
    <Box px="md" py="sm" style={{ border: "1px solid var(--mantine-color-dark-4)", borderLeft: `3px solid var(--mantine-color-${revoked ? "gray" : PQC_COLOR[c.pqcStatus] ?? "gray"}-6)`, borderRadius: 2, background: "var(--mantine-color-dark-6)", opacity: revoked ? 0.6 : 1 }}>
      <Group justify="space-between" wrap="nowrap" align="flex-start">
        <Box style={{ minWidth: 0 }}>
          <Group gap={8} wrap="wrap">
            <Text size="14px" fw={700} c="gray.1" truncate>{c.subject}</Text>
            {isHybrid ? (
              <Tooltip withArrow multiline w={300}
                label="Hybrid = a classical Ed25519 X.509 leaf PLUS a detached ML-DSA-65 signature over the cert, made by the CA's quantum-safe key. The leaf is Ed25519 because standards-track ML-DSA-in-X.509 isn't available yet; the post-quantum protection is the binding, which 'Verify ML-DSA binding' checks.">
                <Group gap={4} wrap="nowrap" style={{ cursor: "help" }}>
                  <Badge color="gray" radius={2} size="xs" variant="light">Ed25519 X.509</Badge>
                  <Text size="11px" c="dark.2" fw={700}>+</Text>
                  <Badge color="cyan" radius={2} size="xs" variant="light">ML-DSA-65 binding</Badge>
                </Group>
              </Tooltip>
            ) : (
              <Badge color="gray" radius={2} size="xs" variant="light">Ed25519 X.509 (classical)</Badge>
            )}
            {revoked ? (
              <Badge color="red" radius={2} size="xs" variant="filled">revoked</Badge>
            ) : expired ? (
              <Badge color="red" radius={2} size="xs" variant="filled">expired</Badge>
            ) : expiring ? (
              <Badge color="orange" radius={2} size="xs" variant="light">expires in {dleft}d</Badge>
            ) : (
              <Badge color="signal" radius={2} size="xs" variant="light">active</Badge>
            )}
          </Group>
          <Group gap={12} mt={4} wrap="wrap">
            <Text ff="monospace" size="10.5px" c="dimmed">serial {c.serial.slice(0, 20)}</Text>
            <Text size="10.5px" c="dimmed">not after {new Date(c.notAfter).toLocaleDateString()}</Text>
            {c.sans.length > 1 && <Text size="10.5px" c="dark.2">SAN: {c.sans.slice(0, 3).join(", ")}</Text>}
          </Group>
          {c.mldsaSignature && (
            <Text ff="monospace" size="9.5px" c="dark.3" mt={3}>ML-DSA sig {c.mldsaSignature.length} B (b64) · CA fp {c.caFingerprint.slice(0, 16)}…</Text>
          )}
        </Box>
      </Group>

      <Group gap="xs" mt={10} wrap="wrap">
        {isHybrid && (
          <Button size="compact-xs" radius={2} color="cyan" variant="light" loading={verify.isPending} onClick={() => verify.mutate()}>
            Verify ML-DSA binding
          </Button>
        )}
        {verify.isSuccess && <VerifyResult ok={verify.data.valid} />}
        {verify.isError && <Text size="11px" c="red.4">verify failed</Text>}
        <Button size="compact-xs" radius={2} variant="default" onClick={() => downloadText(`${c.subject.replace(/[^a-z0-9.-]/gi, "_")}.pem`, c.certPem)}>Download PEM</Button>
        {!revoked && <Button size="compact-xs" radius={2} variant="default" loading={renew.isPending} onClick={() => renew.mutate()}>Renew</Button>}
        {!revoked && (
          <Tooltip label="Mark this certificate revoked" withArrow>
            <Button size="compact-xs" radius={2} color="red" variant="subtle" loading={revoke.isPending} onClick={() => revoke.mutate()}>Revoke</Button>
          </Tooltip>
        )}
      </Group>
    </Box>
  );
}

function IssueCard({ onIssued }: { onIssued: () => void }) {
  const [subject, setSubject] = useState("");
  const [sans, setSans] = useState("");
  const [days, setDays] = useState<number>(90);
  const [keyType, setKeyType] = useState("hybrid");
  const [issued, setIssued] = useState<IssueResult | null>(null);

  const issue = useMutation({
    mutationFn: () => issueCertificate({
      subject,
      sans: sans.split(",").map((s) => s.trim()).filter(Boolean),
      validityDays: days,
      keyType,
    }),
    onSuccess: (r) => { setIssued(r); setSubject(""); setSans(""); onIssued(); },
  });

  return (
    <Card className="p-4">
      <Text fw={700} c="gray.1" mb={2}>Issue a certificate</Text>
      <Text size="12px" c="dimmed" mb="sm">A hybrid cert is a CA-signed X.509 leaf plus a detached ML-DSA-65 signature (the quantum-safe binding you can verify below).</Text>
      <Group gap="sm" align="flex-end" wrap="wrap">
        <TextInput size="xs" radius={2} label="Subject (CN)" placeholder="orders-db.internal" value={subject} onChange={(e) => setSubject(e.currentTarget.value)} w={200} />
        <TextInput size="xs" radius={2} label="Extra SANs (comma-sep)" placeholder="db.internal, 10.0.0.5" value={sans} onChange={(e) => setSans(e.currentTarget.value)} w={200} />
        <NumberInput size="xs" radius={2} label="Validity (days)" value={days} onChange={(v) => setDays(typeof v === "number" ? v : 90)} min={1} max={3650} w={120} />
        <Box>
          <Text size="10px" fw={700} tt="uppercase" c="dimmed" mb={3} style={{ letterSpacing: "0.06em" }}>Type</Text>
          <SegmentedControl size="xs" radius={2} value={keyType} onChange={setKeyType} data={[{ label: "Hybrid", value: "hybrid" }, { label: "Classical", value: "classical" }]} />
        </Box>
        <Button size="xs" radius={2} color="brand" loading={issue.isPending} disabled={!subject.trim()} onClick={() => issue.mutate()}>Issue</Button>
      </Group>
      {issue.isError && <Alert color="red" radius={2} variant="light" p="xs" mt="sm"><Text size="11px">{(issue.error as Error)?.message ?? "Issue failed."}</Text></Alert>}
      {issued && (
        <Alert color="teal" radius={2} variant="light" mt="sm" withCloseButton onClose={() => setIssued(null)} title={`Issued ${issued.subject}`}>
          <Text size="11px" mb={6}>The private key is shown <b>once</b> and is never stored. Download it now.</Text>
          <Group gap="xs">
            <Button size="compact-xs" radius={2} color="teal" onClick={() => downloadText(`${issued.subject.replace(/[^a-z0-9.-]/gi, "_")}.key`, issued.keyPem)}>Download private key</Button>
            <Button size="compact-xs" radius={2} variant="default" onClick={() => downloadText(`${issued.subject.replace(/[^a-z0-9.-]/gi, "_")}.pem`, issued.certPem)}>Download cert</Button>
          </Group>
        </Alert>
      )}
    </Card>
  );
}

function CaCard() {
  const { data: ca } = useQuery({ queryKey: ["pki-ca"], queryFn: fetchCa });
  if (!ca) return null;
  return (
    <Card className="p-4">
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <Box style={{ minWidth: 0 }}>
          <Group gap={8}>
            <Text fw={700} c="gray.1">{ca.commonName}</Text>
            {ca.hybrid && <Badge color="cyan" radius={2} size="xs" variant="light">hybrid CA</Badge>}
          </Group>
          <Text size="12px" c="dimmed">Internal certificate authority. Its ML-DSA-65 key makes the quantum-safe binding on every hybrid cert.</Text>
          <Text ff="monospace" size="10.5px" c="teal.4" mt={4}>ML-DSA fingerprint: {ca.mldsaFingerprint}</Text>
        </Box>
        <Button size="xs" radius={2} variant="default" onClick={() => downloadText("quantawatch-ca.pem", ca.caCertPem)}>Download CA cert</Button>
      </Group>
    </Card>
  );
}

export default function CertificatesPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["certificates"], queryFn: fetchCertificates });
  const certs = data?.certificates ?? [];
  const refresh = () => qc.invalidateQueries({ queryKey: ["certificates"] });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Certificates"
        subtitle="The internal PQC certificate authority — issue hybrid ML-DSA certificates, verify their post-quantum binding, download, renew and revoke"
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Certificates" value={data?.total ?? 0} accent="brand" />
        <Stat label="Active" value={data?.active ?? 0} accent="emerald" />
        <Stat label="Hybrid (PQC-bound)" value={data?.hybrid ?? 0} accent="violet" />
        <Stat label="Revoked" value={data?.revoked ?? 0} accent={(data?.revoked ?? 0) > 0 ? "amber" : "emerald"} />
      </div>

      <CaCard />
      <IssueCard onIssued={refresh} />

      {isLoading ? (
        <Spinner className="py-16" />
      ) : certs.length === 0 ? (
        <Card className="p-10">
          <EmptyState title="No certificates issued yet">Issue one above, or use “Issue PQC cert” on a service in the Estate.</EmptyState>
        </Card>
      ) : (
        <>
          <Divider label={`Issued certificates (${certs.length})`} labelPosition="left" styles={{ label: { fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--mantine-color-dark-2)" } }} />
          <Stack gap={8}>
            {certs.map((c) => <CertRow key={c.id} c={c} onChange={refresh} />)}
          </Stack>
        </>
      )}

      <Card className="p-4">
        <Text size="11px" c="dimmed">
          <b>Note:</b> the X.509 leaf is Ed25519 (classical) because standards-track ML-DSA-in-X.509 isn’t available yet; the “hybrid / PQC” property is the detached <Code style={{ fontSize: 11 }}>ML-DSA-65</Code> signature over the certificate, made by the CA’s quantum-safe key. “Verify ML-DSA binding” checks exactly that signature.
        </Text>
      </Card>
    </div>
  );
}
