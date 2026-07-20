import { Component, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ScrollArea, Tooltip } from "@mantine/core";
import { navSections } from "./Sidebar";
import { fetchAuditEntries, fetchMe, fetchPosture, fetchTenants, getTenant, setTenant, logout } from "../api/client";

/* ============================================================
   VS Code–style IDE shell: activity bar · explorer · editor
   tabs · output panel (live audit/enforcement feed) · status
   bar · Ctrl+P command palette.
   ============================================================ */

interface FlatItem { to: string; label: string; icon: ReactNode; section: string }
const FLAT: FlatItem[] = navSections.flatMap((s) =>
  s.items.map((i) => ({ ...i, section: s.label ?? "" })),
);
const labelFor = (path: string) => FLAT.find((i) => i.to === path)?.label ?? (path.replace(/^\//, "") || "Dashboard");
const iconFor = (path: string) => FLAT.find((i) => i.to === path)?.icon;

// ---- tiny icon set (activity bar / chrome) ----
const I = {
  explorer: <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12.75V12A2.25 2.25 0 0 1 4.5 9.75h15A2.25 2.25 0 0 1 21.75 12v.75m-8.69-6.44-2.12-2.12a1.5 1.5 0 0 0-1.061-.44H4.5A2.25 2.25 0 0 0 2.25 6v12a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9a2.25 2.25 0 0 0-2.25-2.25h-5.379a1.5 1.5 0 0 1-1.06-.44Z" />,
  search: <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />,
  shield: <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />,
  bug: <path strokeLinecap="round" strokeLinejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.047.83-1.867 1.866-2.013A24.204 24.204 0 0 1 12 12.75Zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 0 1-1.152 6.06M12 12.75c-2.883 0-5.647.508-8.208 1.44.125 2.104.52 4.136 1.153 6.06M12 12.75a2.25 2.25 0 0 0 2.248-2.354M12 12.75a2.25 2.25 0 0 1-2.248-2.354M12 8.25c.995 0 1.971-.08 2.922-.236.403-.066.74-.358.795-.762a3.778 3.778 0 0 0-.399-2.25M12 8.25c-.995 0-1.97-.08-2.922-.236-.402-.066-.74-.358-.795-.762a3.734 3.734 0 0 1 .4-2.253M12 8.25a2.25 2.25 0 0 0-2.248 2.146M12 8.25a2.25 2.25 0 0 1 2.248 2.146" />,
  gear: <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a6.759 6.759 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.241.437-.613.43-.992a6.932 6.932 0 0 1 0-.255c.007-.378-.138-.75-.43-.991l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.281Z" />,
  terminal: <path strokeLinecap="round" strokeLinejoin="round" d="m6.75 7.5 3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0 0 21 18V6a2.25 2.25 0 0 0-2.25-2.25H5.25A2.25 2.25 0 0 0 3 6v12a2.25 2.25 0 0 0 2.25 2.25Z" />,
  chevron: <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />,
  close: <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />,
  signout: <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15M12 9l-3 3m0 0 3 3m-3-3h12.75" />,
};
function Ic({ d, size = 22, w = 1.6 }: { d: ReactNode; size?: number; w?: number }) {
  return <svg width={size} height={size} fill="none" viewBox="0 0 24 24" strokeWidth={w} stroke="currentColor">{d}</svg>;
}

const C = {
  activity: "#111318",
  side: "var(--mantine-color-dark-8)",
  editor: "var(--mantine-color-dark-8)",
  chrome: "#15181e",
  border: "var(--mantine-color-dark-5)",
  accent: "var(--mantine-color-brand-6)",
  textDim: "var(--mantine-color-dark-2)",
};

// One failing widget/page must not blank the whole IDE.
class Boundary extends Component<{ children: ReactNode; label: string }, { err: string | null }> {
  state = { err: null as string | null };
  static getDerivedStateFromError(e: unknown) { return { err: e instanceof Error ? e.message : String(e) }; }
  render() {
    if (this.state.err) {
      return (
        <div style={{ padding: 16, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--mantine-color-red-4)" }}>
          {this.props.label} failed to render: {this.state.err}
        </div>
      );
    }
    return this.props.children;
  }
}

export default function IdeShell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [openPaths, setOpenPaths] = useState<string[]>([pathname]);
  const [palette, setPalette] = useState(false);
  const [panelOpen, setPanelOpen] = useState(true);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  useEffect(() => {
    setOpenPaths((prev) => (prev.includes(pathname) ? prev : [...prev, pathname]));
  }, [pathname]);

  // Ctrl/Cmd+P → command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === "p" || e.key === "k")) {
        e.preventDefault();
        setPalette((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const closeTab = (p: string) => {
    setOpenPaths((prev) => {
      const idx = prev.indexOf(p);
      const next = prev.filter((x) => x !== p);
      if (p === pathname) navigate(next[idx] ?? next[idx - 1] ?? next[0] ?? "/");
      return next.length ? next : ["/"];
    });
  };

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", background: C.editor, color: "var(--mantine-color-dark-0)" }}>
      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        {/* Activity bar */}
        <div style={{ width: 48, background: C.activity, display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 8, borderRight: `1px solid ${C.border}` }}>
          <ActIcon d={I.explorer} active title="Explorer" onClick={() => {}} />
          <ActIcon d={I.search} title="Command palette (Ctrl+P)" onClick={() => setPalette(true)} />
          <ActIcon d={I.bug} title="Findings" onClick={() => navigate("/scans")} />
          <ActIcon d={I.shield} title="Governance" onClick={() => navigate("/frameworks")} />
          <ActIcon d={I.terminal} title="Toggle output panel" onClick={() => setPanelOpen((v) => !v)} />
          <div style={{ flex: 1 }} />
          <ActIcon d={I.signout} title="Sign out" onClick={async () => { await logout(); qc.clear(); window.dispatchEvent(new Event("qw-unauthorized")); }} />
          <ActIcon d={I.gear} title="Settings" onClick={() => navigate("/")} />
        </div>

        {/* Explorer sidebar */}
        <div style={{ width: 250, background: C.side, borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", minHeight: 0 }}>
          <div style={{ padding: "10px 14px 8px", fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.1em", color: C.textDim, textTransform: "uppercase" }}>Explorer</div>
          <ScrollArea style={{ flex: 1 }} scrollbarSize={8}>
            <div style={{ paddingBottom: 8 }}>
              {navSections.map((s, si) => {
                const key = s.label ?? `s${si}`;
                const isCol = collapsed[key];
                return (
                  <div key={key}>
                    {s.label && (
                      <button
                        onClick={() => setCollapsed((c) => ({ ...c, [key]: !c[key] }))}
                        style={treeGroupStyle}
                      >
                        <span style={{ display: "inline-flex", transition: "transform .12s", transform: isCol ? "rotate(0deg)" : "rotate(90deg)" }}>
                          <Ic d={I.chevron} size={11} w={2.4} />
                        </span>
                        {s.label}
                      </button>
                    )}
                    {!isCol && s.items.map((item) => {
                      const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
                      return (
                        <button key={item.to} onClick={() => navigate(item.to)} style={treeRow(active)}>
                          <span style={{ width: 16, height: 16, display: "grid", placeItems: "center", opacity: 0.85 }}>{item.icon}</span>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
                        </button>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </ScrollArea>
        </div>

        {/* Editor column */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          {/* Tab strip */}
          <div style={{ display: "flex", background: C.chrome, borderBottom: `1px solid ${C.border}`, overflowX: "auto", flexShrink: 0 }}>
            {openPaths.map((p) => {
              const active = p === pathname;
              return (
                <div key={p} onClick={() => navigate(p)} title={p}
                  style={{
                    display: "flex", alignItems: "center", gap: 7, padding: "0 10px", height: 35, cursor: "pointer",
                    fontSize: 12.5, whiteSpace: "nowrap", userSelect: "none",
                    color: active ? "#fff" : C.textDim,
                    background: active ? C.editor : "transparent",
                    borderRight: `1px solid ${C.border}`,
                    borderTop: active ? `1.5px solid ${C.accent}` : "1.5px solid transparent",
                  }}>
                  <span style={{ width: 14, height: 14, display: "grid", placeItems: "center", opacity: 0.9 }}>{iconFor(p)}</span>
                  {labelFor(p)}
                  <span onClick={(e) => { e.stopPropagation(); closeTab(p); }} style={{ display: "grid", placeItems: "center", width: 16, height: 16, borderRadius: 2, opacity: 0.6 }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,.12)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                    <Ic d={I.close} size={12} w={2} />
                  </span>
                </div>
              );
            })}
          </div>

          {/* Editor content + output panel */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
            <ScrollArea style={{ flex: 1, background: C.editor }} scrollbarSize={10}>
              <div style={{ padding: "20px 22px 40px", maxWidth: 1180, margin: "0 auto" }}>
                <Boundary label={labelFor(pathname)}>{children}</Boundary>
              </div>
            </ScrollArea>
            <Boundary label="Output"><OutputPanel open={panelOpen} onToggle={() => setPanelOpen((v) => !v)} /></Boundary>
          </div>
        </div>
      </div>

      <Boundary label="Status bar"><StatusBar openCount={openPaths.length} onOutput={() => setPanelOpen((v) => !v)} onPalette={() => setPalette(true)} /></Boundary>

      <CommandPalette opened={palette} onClose={() => setPalette(false)} onPick={(to) => { setPalette(false); navigate(to); }} />
    </div>
  );
}

const treeGroupStyle: React.CSSProperties = {
  display: "flex", alignItems: "center", gap: 4, width: "100%", cursor: "pointer",
  padding: "6px 10px 2px", fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em",
  color: "var(--mantine-color-dark-3)", textTransform: "uppercase", background: "transparent", border: "none",
};
function treeRow(active: boolean): React.CSSProperties {
  return {
    display: "flex", alignItems: "center", gap: 8, width: "100%", cursor: "pointer",
    padding: "5px 10px 5px 20px", fontSize: 13, textAlign: "left", border: "none",
    color: active ? "#fff" : "var(--mantine-color-dark-1)",
    background: active ? "color-mix(in srgb, var(--mantine-color-brand-6) 22%, transparent)" : "transparent",
    borderLeft: active ? `2px solid var(--mantine-color-brand-5)` : "2px solid transparent",
  };
}

function ActIcon({ d, active, title, onClick }: { d: ReactNode; active?: boolean; title: string; onClick: () => void }) {
  return (
    <Tooltip label={title} position="right" openDelay={300} withArrow>
      <button onClick={onClick} aria-label={title}
        style={{
          width: 48, height: 44, display: "grid", placeItems: "center", cursor: "pointer", background: "transparent", border: "none",
          color: active ? "#fff" : "#8a8f99", borderLeft: active ? `2px solid ${C.accent}` : "2px solid transparent",
        }}
        onMouseEnter={(e) => { if (!active) e.currentTarget.style.color = "#fff"; }}
        onMouseLeave={(e) => { if (!active) e.currentTarget.style.color = "#8a8f99"; }}>
        <Ic d={d} size={23} />
      </button>
    </Tooltip>
  );
}

// ---- Output panel: live audit + enforcement feed ----
function OutputPanel({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  const { data } = useQuery({ queryKey: ["audit-feed"], queryFn: () => fetchAuditEntries(40), refetchInterval: 5000 });
  const bodyRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => { if (bodyRef.current) bodyRef.current.scrollTop = 0; }, [data]);
  // /api/audit returns { entries, total }; fetchAuditEntries is typed as an
  // array but passes the object through — handle both shapes.
  const list = Array.isArray(data) ? data : ((data as unknown as { entries?: typeof data })?.entries ?? []);
  const rows = (Array.isArray(list) ? list : []).slice(0, 40);

  const color = (t: string) =>
    /threat|denied|failed|blocked/.test(t) ? "var(--mantine-color-red-4)"
      : /enforced|policy|violation/.test(t) ? "var(--mantine-color-orange-4)"
        : /login|admin|logout|scan/.test(t) ? "var(--mantine-color-brand-3)"
          : "var(--mantine-color-dark-2)";

  return (
    <div style={{ borderTop: `1px solid ${C.border}`, background: C.editor, flexShrink: 0, display: "flex", flexDirection: "column", height: open ? 190 : 30 }}>
      <div style={{ display: "flex", alignItems: "center", height: 30, padding: "0 10px", gap: 14, borderBottom: open ? `1px solid ${C.border}` : "none", flexShrink: 0 }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.08em", textTransform: "uppercase", color: "#fff", borderBottom: `1.5px solid ${C.accent}`, paddingBottom: 6, marginTop: 8 }}>Output — Audit &amp; Enforcement</span>
        <div style={{ flex: 1 }} />
        <button onClick={onToggle} title={open ? "Collapse" : "Expand"} style={{ background: "transparent", border: "none", color: C.textDim, cursor: "pointer", display: "grid", placeItems: "center" }}>
          <span style={{ display: "inline-flex", transform: open ? "rotate(90deg)" : "rotate(-90deg)" }}><Ic d={I.chevron} size={12} w={2.2} /></span>
        </button>
      </div>
      {open && (
        <div ref={bodyRef} style={{ flex: 1, overflow: "auto", padding: "6px 12px", fontFamily: "var(--font-mono)", fontSize: 11.5, lineHeight: 1.7 }}>
          {rows.length === 0 && <div style={{ color: C.textDim }}>waiting for events…</div>}
          {rows.map((e) => (
            <div key={e.id} style={{ whiteSpace: "nowrap" }}>
              <span style={{ color: "#5a6070" }}>{new Date(e.timestamp).toLocaleTimeString()}</span>{"  "}
              <span style={{ color: color(e.event_type) }}>{e.event_type}</span>{"  "}
              <span style={{ color: "#7a8091" }}>{e.session_id?.slice(0, 12)}</span>{"  "}
              <span style={{ color: "var(--mantine-color-dark-1)" }}>{(e.details || "").slice(0, 120)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---- Status bar (Azure blue, VS Code style) ----
function StatusBar({ openCount, onOutput, onPalette }: { openCount: number; onOutput: () => void; onPalette: () => void }) {
  const qc = useQueryClient();
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: fetchMe });
  const { data: posture } = useQuery({ queryKey: ["posture"], queryFn: fetchPosture });
  const { data: tenants } = useQuery({ queryKey: ["tenants"], queryFn: fetchTenants });
  const current = getTenant() ?? "default";

  const item: React.CSSProperties = { display: "inline-flex", alignItems: "center", gap: 5, padding: "0 8px", height: "100%", cursor: "pointer" };
  const switchOrg = () => {
    const list = tenants?.tenants ?? [];
    if (list.length < 2) return;
    const next = list[(list.indexOf(current) + 1) % list.length];
    setTenant(next === "default" ? null : next);
    qc.clear();
    window.location.reload();
  };

  return (
    <div style={{ height: 24, background: C.accent, color: "#fff", display: "flex", alignItems: "center", fontFamily: "var(--font-mono)", fontSize: 11, flexShrink: 0 }}>
      <span style={item}><span style={{ width: 7, height: 7, borderRadius: "50%", background: "#9ff0c8", boxShadow: "0 0 6px #9ff0c8" }} /> Gateway online</span>
      {typeof posture?.overallScore === "number" && <span style={item}>◆ Posture {Math.round(posture.overallScore)}/100</span>}
      <div style={{ flex: 1 }} />
      <span style={item} onClick={switchOrg} title="Switch tenant">⛁ {current}</span>
      {me?.username && <span style={item} title={me.role}>{me.username.replace(/^apikey:/, "")} · {me.role}</span>}
      <span style={item} onClick={onOutput} title="Toggle output">≣ {openCount} open</span>
      <span style={item} onClick={onPalette} title="Command palette">⌘ Ctrl+P</span>
    </div>
  );
}

// ---- Command palette (Ctrl+P) ----
function CommandPalette({ opened, onClose, onPick }: { opened: boolean; onClose: () => void; onPick: (to: string) => void }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  useEffect(() => { if (opened) { setQ(""); setSel(0); } }, [opened]);
  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    return FLAT.filter((i) => !t || i.label.toLowerCase().includes(t) || i.section.toLowerCase().includes(t)).slice(0, 12);
  }, [q]);

  if (!opened) return null;
  return (
    <div onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)", zIndex: 1000, display: "flex", justifyContent: "center", paddingTop: "13vh" }}>
      <div onClick={(e) => e.stopPropagation()}
        style={{ width: 560, maxHeight: "72vh", background: "var(--mantine-color-dark-7)", border: `1px solid ${C.border}`, borderRadius: 3, overflow: "hidden", display: "flex", flexDirection: "column", boxShadow: "0 12px 48px rgba(0,0,0,.5)" }}>
        <input
          autoFocus value={q}
          onChange={(e) => { setQ(e.currentTarget.value); setSel(0); }}
          placeholder="Go to view…  (Ctrl+P)"
          style={{ background: "transparent", border: "none", borderBottom: `1px solid ${C.border}`, outline: "none", color: "#fff", fontFamily: "var(--font-mono)", fontSize: 14, padding: "13px 16px" }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(results.length - 1, s + 1)); }
            if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
            if (e.key === "Enter" && results[sel]) onPick(results[sel].to);
            if (e.key === "Escape") onClose();
          }}
        />
        <div style={{ overflow: "auto", padding: 4 }}>
          {results.map((r, i) => (
            <div key={r.to} onClick={() => onPick(r.to)} onMouseEnter={() => setSel(i)}
              style={{ display: "flex", alignItems: "center", gap: 9, padding: "7px 12px", cursor: "pointer", borderRadius: 2, background: i === sel ? "color-mix(in srgb, var(--mantine-color-brand-6) 26%, transparent)" : "transparent" }}>
              <span style={{ width: 16, height: 16, display: "grid", placeItems: "center", opacity: 0.85 }}>{r.icon}</span>
              <span style={{ fontSize: 13.5, color: "#fff" }}>{r.label}</span>
              <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10, color: C.textDim, textTransform: "uppercase" }}>{r.section}</span>
            </div>
          ))}
          {results.length === 0 && <div style={{ padding: 14, color: C.textDim, fontSize: 13 }}>No matching views</div>}
        </div>
      </div>
    </div>
  );
}
