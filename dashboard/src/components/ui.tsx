import type { ReactNode } from "react";
import { Paper, Title, Text, Badge, Loader, Group, Box, Stack } from "@mantine/core";
import type { PqcStatus, FindingSeverity } from "../api/types";

/* ============================================================
   Shared UI primitives — rebuilt on Mantine. Same exported API,
   so every page reskins without edits.
   ============================================================ */

// PQC status / severity → Mantine color + label.
const PQC_COLOR: Record<PqcStatus, { label: string; color: string; dot: string }> = {
  pqc_ready: { label: "PQC Ready", color: "signal", dot: "var(--mantine-color-signal-5)" },
  hybrid: { label: "Hybrid", color: "brand", dot: "var(--mantine-color-brand-4)" },
  classical_secure: { label: "Classical", color: "yellow", dot: "var(--mantine-color-yellow-5)" },
  classical_weak: { label: "Weak", color: "red", dot: "var(--mantine-color-red-5)" },
  unknown: { label: "Unknown", color: "gray", dot: "var(--mantine-color-gray-5)" },
};

const SEVERITY_COLOR: Record<FindingSeverity, { label: string; color: string }> = {
  critical: { label: "Critical", color: "red" },
  high: { label: "High", color: "orange" },
  medium: { label: "Medium", color: "yellow" },
  low: { label: "Low", color: "signal" },
  info: { label: "Info", color: "gray" },
};

// Kept for pages that still reference these Tailwind maps directly.
export const PQC_META: Record<PqcStatus, { label: string; text: string; bg: string; ring: string; dot: string }> = {
  pqc_ready: { label: "PQC Ready", text: "text-emerald-300", bg: "bg-emerald-400/10", ring: "ring-emerald-400/30", dot: "bg-emerald-400" },
  hybrid: { label: "Hybrid", text: "text-brand-300", bg: "bg-brand-400/10", ring: "ring-brand-400/30", dot: "bg-brand-400" },
  classical_secure: { label: "Classical", text: "text-amber-300", bg: "bg-amber-400/10", ring: "ring-amber-400/30", dot: "bg-amber-400" },
  classical_weak: { label: "Weak", text: "text-rose-300", bg: "bg-rose-400/10", ring: "ring-rose-400/30", dot: "bg-rose-400" },
  unknown: { label: "Unknown", text: "text-slate-300", bg: "bg-slate-400/10", ring: "ring-slate-400/30", dot: "bg-slate-400" },
};

export const SEVERITY_META: Record<FindingSeverity, { label: string; text: string; bg: string }> = {
  critical: { label: "Critical", text: "text-rose-300", bg: "bg-rose-500/15" },
  high: { label: "High", text: "text-orange-300", bg: "bg-orange-500/15" },
  medium: { label: "Medium", text: "text-amber-300", bg: "bg-amber-500/15" },
  low: { label: "Low", text: "text-emerald-300", bg: "bg-emerald-500/15" },
  info: { label: "Info", text: "text-slate-300", bg: "bg-slate-500/15" },
};

export function scoreColor(score: number): string {
  if (score >= 80) return "var(--mantine-color-signal-5)";
  if (score >= 60) return "var(--mantine-color-yellow-5)";
  if (score >= 40) return "var(--mantine-color-orange-5)";
  return "var(--mantine-color-red-5)";
}
export function scoreText(score: number): string {
  if (score >= 80) return "text-emerald-300";
  if (score >= 60) return "text-amber-300";
  if (score >= 40) return "text-orange-300";
  return "text-rose-300";
}

// ---- Card ----
export function Card({ children, className = "", hover = false }: { children: ReactNode; className?: string; hover?: boolean }) {
  return (
    <Paper withBorder radius="md" bg="dark.6" className={`${hover ? "qw-hover" : ""} ${className}`} style={{ borderColor: "var(--mantine-color-dark-4)" }}>
      {children}
    </Paper>
  );
}

// ---- Page header ----
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <Group justify="space-between" align="flex-end" wrap="wrap" pb="sm" gap="sm" style={{ borderBottom: "1px solid var(--mantine-color-dark-4)" }}>
      <div>
        <Title order={2} c="white">{title}</Title>
        {subtitle && <Text size="xs" c="dimmed" mt={2} maw="70ch">{subtitle}</Text>}
      </div>
      {actions && <Group gap="xs">{actions}</Group>}
    </Group>
  );
}

// ---- Stat tile ----
const ACCENT: Record<string, string> = {
  brand: "var(--mantine-color-brand-4)",
  violet: "var(--mantine-color-grape-4)",
  emerald: "var(--mantine-color-signal-4)",
  rose: "var(--mantine-color-red-4)",
  amber: "var(--mantine-color-yellow-4)",
};
export function Stat({ label, value, accent = "brand", sub }: { label: string; value: ReactNode; accent?: "brand" | "violet" | "emerald" | "rose" | "amber"; sub?: ReactNode }) {
  return (
    <Paper withBorder radius="md" bg="dark.6" px="md" py="sm" style={{ borderColor: "var(--mantine-color-dark-4)" }}>
      <Text ff="monospace" size="10px" fw={600} c="dimmed" tt="uppercase" style={{ letterSpacing: "0.08em" }}>{label}</Text>
      <Text fz="1.6rem" fw={700} ff="heading" style={{ color: ACCENT[accent], fontVariantNumeric: "tabular-nums", lineHeight: 1.1 }} mt={4}>{value}</Text>
      {sub && <Text size="11px" c="dimmed" mt={2}>{sub}</Text>}
    </Paper>
  );
}

// ---- Badges ----
export function PqcBadge({ status }: { status: PqcStatus }) {
  const m = PQC_COLOR[status] ?? PQC_COLOR.unknown;
  return (
    <Badge variant="light" color={m.color} radius="sm" size="sm" tt="none" fw={600}
      leftSection={<Box w={6} h={6} style={{ borderRadius: "50%", background: m.dot }} />}>
      {m.label}
    </Badge>
  );
}
export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  const m = SEVERITY_COLOR[severity] ?? SEVERITY_COLOR.info;
  return <Badge variant="light" color={m.color} radius="sm" size="sm" tt="none" fw={600}>{m.label}</Badge>;
}

// ---- Score ring ----
export function ScoreRing({ score, size = 132, stroke = 9 }: { score: number; size?: number; stroke?: number }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (score / 100) * c;
  const color = scoreColor(score);
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--mantine-color-dark-5)" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="butt"
          style={{ transition: "stroke-dashoffset 0.7s ease" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <Text fz="2rem" fw={700} ff="heading" style={{ color, fontVariantNumeric: "tabular-nums" }}>{Math.round(score)}</Text>
        <Text size="10px" c="dimmed" tt="uppercase" style={{ letterSpacing: "0.1em" }}>/ 100</Text>
      </div>
    </div>
  );
}

// ---- Spinner ----
export function Spinner({ className = "" }: { className?: string }) {
  return (
    <Group justify="center" align="center" className={className}>
      <Loader color="brand" size="sm" type="bars" />
    </Group>
  );
}

// ---- Empty state ----
export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <Stack align="center" justify="center" gap={6} py="xl" ta="center">
      {icon && <Box c="dimmed">{icon}</Box>}
      <Text fw={600} c="gray.3" ff="heading">{title}</Text>
      {children && <Text size="xs" c="dimmed" maw={420}>{children}</Text>}
    </Stack>
  );
}
