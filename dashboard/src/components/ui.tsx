import type { ReactNode } from "react";
import type { PqcStatus, FindingSeverity } from "../api/types";

/* ============================================================
   Shared bold-branded UI primitives.
   Use these everywhere so pages stay visually consistent.
   ============================================================ */

// ---- PQC status styling ----
export const PQC_META: Record<PqcStatus, { label: string; text: string; bg: string; ring: string; dot: string }> = {
  pqc_ready:        { label: "PQC Ready",        text: "text-emerald-300", bg: "bg-emerald-400/10", ring: "ring-emerald-400/30", dot: "bg-emerald-400" },
  hybrid:           { label: "Hybrid",           text: "text-brand-300",   bg: "bg-brand-400/10",   ring: "ring-brand-400/30",   dot: "bg-brand-400" },
  classical_secure: { label: "Classical",        text: "text-amber-300",   bg: "bg-amber-400/10",   ring: "ring-amber-400/30",   dot: "bg-amber-400" },
  classical_weak:   { label: "Weak",             text: "text-rose-300",    bg: "bg-rose-400/10",    ring: "ring-rose-400/30",    dot: "bg-rose-400" },
  unknown:          { label: "Unknown",          text: "text-slate-300",   bg: "bg-slate-400/10",   ring: "ring-slate-400/30",   dot: "bg-slate-400" },
};

export const SEVERITY_META: Record<FindingSeverity, { label: string; text: string; bg: string }> = {
  critical: { label: "Critical", text: "text-rose-300",    bg: "bg-rose-500/15" },
  high:     { label: "High",     text: "text-orange-300",  bg: "bg-orange-500/15" },
  medium:   { label: "Medium",   text: "text-amber-300",   bg: "bg-amber-500/15" },
  low:      { label: "Low",      text: "text-emerald-300", bg: "bg-emerald-500/15" },
  info:     { label: "Info",     text: "text-slate-300",   bg: "bg-slate-500/15" },
};

export function scoreColor(score: number): string {
  if (score >= 80) return "#34d399";
  if (score >= 60) return "#fbbf24";
  if (score >= 40) return "#fb923c";
  return "#f87171";
}

export function scoreText(score: number): string {
  if (score >= 80) return "text-emerald-300";
  if (score >= 60) return "text-amber-300";
  if (score >= 40) return "text-orange-300";
  return "text-rose-300";
}

// ---- Card ----
export function Card({ children, className = "", hover = false }: { children: ReactNode; className?: string; hover?: boolean }) {
  return <div className={`qw-card ${hover ? "qw-card-hover" : ""} ${className}`}>{children}</div>;
}

// ---- Page header ----
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-0.5 text-xs text-gray-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

// ---- Stat tile ----
export function Stat({ label, value, accent = "brand", sub }: { label: string; value: ReactNode; accent?: "brand" | "violet" | "emerald" | "rose" | "amber"; sub?: ReactNode }) {
  const accents: Record<string, string> = {
    brand: "text-brand-300",
    violet: "text-quantum-300",
    emerald: "text-emerald-300",
    rose: "text-rose-300",
    amber: "text-amber-300",
  };
  return (
    <Card className="px-4 py-3">
      <div className="qw-eyebrow">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${accents[accent]}`}>{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-gray-500">{sub}</div>}
    </Card>
  );
}

// ---- Badges ----
export function PqcBadge({ status }: { status: PqcStatus }) {
  const m = PQC_META[status] ?? PQC_META.unknown;
  return (
    <span className={`qw-chip ${m.bg} ${m.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  const m = SEVERITY_META[severity] ?? SEVERITY_META.info;
  return <span className={`qw-chip ${m.bg} ${m.text}`}>{m.label}</span>;
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
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#28282c" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="butt"
          style={{ transition: "stroke-dashoffset 0.7s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-semibold tabular-nums ${scoreText(score)}`}>{Math.round(score)}</span>
        <span className="mt-0.5 text-[10px] uppercase tracking-wider text-gray-500">/ 100</span>
      </div>
    </div>
  );
}

// ---- Spinner ----
export function Spinner({ className = "" }: { className?: string }) {
  return (
    <div className={`flex items-center justify-center ${className}`}>
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-brand-400/20 border-t-brand-400" />
    </div>
  );
}

// ---- Empty state ----
export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center py-10 text-center">
      {icon && <div className="mb-3 text-gray-600">{icon}</div>}
      <h3 className="text-sm font-medium text-gray-300">{title}</h3>
      {children && <div className="mt-1.5 max-w-md text-xs text-gray-500">{children}</div>}
    </div>
  );
}
