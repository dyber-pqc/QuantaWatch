import { Component, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Menu, ScrollArea, Tooltip } from "@mantine/core";
import { navSections } from "./Sidebar";
import { useContextMenu, type ContextMenuItem } from "./ContextMenu";
import {
  fetchAuditEntries, fetchThreats, fetchMe, fetchPosture, fetchTenants, getTenant, setTenant, logout,
  syncRemediations, verifyAuditChain, triggerScan, fetchFrameworks, fetchFramework, openAuthed,
  fetchAttackPaths, fetchMigrationPlans, fetchEndpoints, fetchAlerts,
  fetchTargets, fetchCertificates, ctScan, seedDemo, fetchSettings, saveSettings, fetchAssets,
  BOARD_REPORT_URL, CBOM_DOWNLOAD_URL,
} from "../api/client";

/* ============================================================
   VS Code–style IDE shell: menu bar · activity bar · explorer ·
   editor tabs · bottom panel (Problems / Output / Terminal) ·
   status bar · Ctrl+P command palette.
   ============================================================ */

interface FlatItem { to: string; label: string; icon: ReactNode; section: string }
const FLAT: FlatItem[] = navSections.flatMap((s) => s.items.map((i) => ({ ...i, section: s.label ?? "" })));
const labelFor = (path: string) => FLAT.find((i) => i.to === path)?.label ?? (path.replace(/^\//, "") || "Dashboard");
const iconFor = (path: string) => FLAT.find((i) => i.to === path)?.icon;

const I = {
  explorer: <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12.75V12A2.25 2.25 0 0 1 4.5 9.75h15A2.25 2.25 0 0 1 21.75 12v.75m-8.69-6.44-2.12-2.12a1.5 1.5 0 0 0-1.061-.44H4.5A2.25 2.25 0 0 0 2.25 6v12a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9a2.25 2.25 0 0 0-2.25-2.25h-5.379a1.5 1.5 0 0 1-1.06-.44Z" />,
  search: <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />,
  shield: <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />,
  bug: <path strokeLinecap="round" strokeLinejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.047.83-1.867 1.866-2.013A24.204 24.204 0 0 1 12 12.75Zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 0 1-1.152 6.06M12 12.75c-2.883 0-5.647.508-8.208 1.44.125 2.104.52 4.136 1.153 6.06M12 12.75a2.25 2.25 0 0 0 2.248-2.354M12 12.75a2.25 2.25 0 0 1-2.248-2.354M15 6.75a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />,
  terminal: <path strokeLinecap="round" strokeLinejoin="round" d="m6.75 7.5 3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0 0 21 18V6a2.25 2.25 0 0 0-2.25-2.25H5.25A2.25 2.25 0 0 0 3 6v12a2.25 2.25 0 0 0 2.25 2.25Z" />,
  chevron: <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />,
  plus: <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />,
  close: <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />,
  signout: <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15M12 9l-3 3m0 0 3 3m-3-3h12.75" />,
  gear: <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.24-.438.613-.43.992a6.759 6.759 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 0 1 0-.255c.007-.378-.138-.75-.43-.991l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.281Z" />,
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

class Boundary extends Component<{ children: ReactNode; label: string }, { err: string | null }> {
  state = { err: null as string | null };
  static getDerivedStateFromError(e: unknown) { return { err: e instanceof Error ? e.message : String(e) }; }
  render() {
    if (this.state.err) return <div style={{ padding: 16, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--mantine-color-red-4)" }}>{this.props.label} failed: {this.state.err}</div>;
    return this.props.children;
  }
}

type PanelTab = "problems" | "output" | "terminal";

// Console command reference — drives `help`, `help <cmd>`, and `<cmd> --help`.
const CMD_HELP: Record<string, { usage: string; desc: string }> = {
  help: { usage: "help [command]", desc: "list commands, or show usage for one" },
  clear: { usage: "clear", desc: "clear the terminal" },
  whoami: { usage: "whoami", desc: "current user, role and auth status" },
  posture: { usage: "posture", desc: "overall PQC posture score" },
  scan: { usage: "scan", desc: "run a full scan now" },
  sync: { usage: "sync", desc: "reconcile remediation ticket status" },
  verify: { usage: "verify", desc: "verify the audit hash chain" },
  targets: { usage: "targets", desc: "list Estate targets (alias: estate)" },
  estate: { usage: "estate", desc: "alias for targets" },
  assets: { usage: "assets", desc: "asset inventory summary" },
  endpoints: { usage: "endpoints", desc: "host-agent endpoints summary" },
  certs: { usage: "certs", desc: "issued certificate summary" },
  paths: { usage: "paths", desc: "top attack paths" },
  plans: { usage: "plans", desc: "open migration plans (alias: remediate)" },
  remediate: { usage: "remediate", desc: "alias for plans" },
  alerts: { usage: "alerts", desc: "recent alerts" },
  threats: { usage: "threats", desc: "recent threats" },
  frameworks: { usage: "frameworks", desc: "compliance framework verdicts" },
  gate: { usage: "gate <id>", desc: "one framework (cnsa-2.0|nist-800-53|pci-dss|fedramp)" },
  evidence: { usage: "evidence", desc: "download the signed evidence pack" },
  cbom: { usage: "cbom", desc: "download the CBOM" },
  ct: { usage: "ct <domain>", desc: "certificate-transparency lookup" },
  seed: { usage: "seed", desc: "load the demo estate" },
  pause: { usage: "pause", desc: "pause automated scanning" },
  resume: { usage: "resume", desc: "resume automated scanning" },
  settings: { usage: "settings", desc: "show runtime settings" },
  open: { usage: "open <view>", desc: "navigate to a page, e.g. open estate" },
};

export default function IdeShell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [openPaths, setOpenPaths] = useState<string[]>([pathname]);
  const [palette, setPalette] = useState(false);
  const [panelOpen, setPanelOpen] = useState(true);
  const [panelTab, setPanelTab] = useState<PanelTab>("terminal");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // Live counts for the nav badges (reuse the pages' query keys so nothing is
  // fetched twice). Only kept if > 0.
  const { data: apData } = useQuery({ queryKey: ["attack-paths"], queryFn: fetchAttackPaths, staleTime: 15000 });
  const { data: planData } = useQuery({ queryKey: ["migration-plans"], queryFn: fetchMigrationPlans, staleTime: 15000 });
  const { data: epData } = useQuery({ queryKey: ["endpoints"], queryFn: fetchEndpoints, staleTime: 15000 });
  const { data: alertData } = useQuery({ queryKey: ["alerts-nav"], queryFn: () => fetchAlerts(100), staleTime: 15000 });
  const navBadges: Record<string, { count: number; color: string }> = {
    criticalPaths: { count: apData?.summary?.critical ?? 0, color: "#f04438" },
    openPlans: { count: planData?.total ?? 0, color: "#f79009" },
    vulnerableEndpoints: { count: epData?.quantumVulnerable ?? 0, color: "#f04438" },
    alerts: { count: alertData?.alerts?.length ?? 0, color: "#f79009" },
  };
  const [term, setTerm] = useState<string[]>(["QuantaWatch console ready — type 'help' for commands."]);

  useEffect(() => { setOpenPaths((prev) => (prev.includes(pathname) ? prev : [...prev, pathname])); }, [pathname]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === "p" || e.key === "k")) { e.preventDefault(); setPalette((v) => !v); }
      if ((e.ctrlKey || e.metaKey) && e.key === "`") { e.preventDefault(); setPanelOpen((v) => !v); setPanelTab("terminal"); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const { openMenu: openTabMenu, menu: tabMenu } = useContextMenu();

  const closeTab = (p: string) => setOpenPaths((prev) => {
    const idx = prev.indexOf(p);
    const next = prev.filter((x) => x !== p);
    if (p === pathname) navigate(next[idx] ?? next[idx - 1] ?? next[0] ?? "/");
    return next.length ? next : ["/"];
  });
  const closeOthers = (p: string) => { setOpenPaths([p]); if (pathname !== p) navigate(p); };
  const closeToRight = (p: string) => setOpenPaths((prev) => {
    const i = prev.indexOf(p);
    if (i < 0) return prev;
    const next = prev.slice(0, i + 1);
    if (!next.includes(pathname)) navigate(p);
    return next;
  });
  const closeAll = () => { setOpenPaths(["/"]); navigate("/"); };

  const tabMenuItems = (p: string): ContextMenuItem[] => {
    const i = openPaths.indexOf(p);
    return [
      { label: "Close", onClick: () => closeTab(p) },
      { label: "Close Others", disabled: openPaths.length <= 1, onClick: () => closeOthers(p) },
      { label: "Close to the Right", disabled: i < 0 || i >= openPaths.length - 1, onClick: () => closeToRight(p) },
      { label: "Close All", onClick: closeAll },
      { label: "Copy Path", divider: true, onClick: () => navigator.clipboard?.writeText(p) },
    ];
  };

  const dragPath = useRef<string | null>(null);
  const reorderTabs = (from: string, to: string) => {
    if (from === to) return;
    setOpenPaths((prev) => {
      const arr = prev.filter((x) => x !== from);
      const ti = arr.indexOf(to);
      if (ti < 0) return prev;
      arr.splice(ti, 0, from);
      return arr;
    });
  };

  const push = (...lines: string[]) => setTerm((l) => [...l.slice(-300), ...lines]);
  const signOut = async () => { await logout(); qc.clear(); window.dispatchEvent(new Event("qw-unauthorized")); };

  const runCommand = async (raw: string) => {
    const cmd = raw.trim();
    if (!cmd) return;
    setPanelOpen(true); setPanelTab("terminal");
    push(`qw> ${cmd}`);
    let name = (cmd.split(/\s+/)[0] || "").toLowerCase();
    const args = cmd.split(/\s+/).slice(1);
    // Normalize help aliases so `--help`, `-h`, `?` all work.
    if (["--help", "-h", "-help", "?", "commands"].includes(name)) name = "help";
    const wantsHelp = args.some((a) => a === "--help" || a === "-h");

    // Per-command usage: `<cmd> --help`, or `help <cmd>`.
    if (name === "help") {
      const target = (args[0] || "").toLowerCase().replace(/^-+/, "");
      if (target && CMD_HELP[target]) {
        push(`usage: ${CMD_HELP[target].usage}  —  ${CMD_HELP[target].desc}`);
      } else if (target) {
        push(`no such command '${target}'. type 'help' for the list.`);
      } else {
        push("commands (run '<command> --help' for usage):");
        Object.entries(CMD_HELP).forEach(([n, h]) => push(`  ${n.padEnd(11)} ${h.desc}`));
      }
      return;
    }
    if (wantsHelp) {
      if (CMD_HELP[name]) push(`usage: ${CMD_HELP[name].usage}  —  ${CMD_HELP[name].desc}`);
      else push(`no such command '${name}'. type 'help' for the list.`);
      return;
    }

    try {
      switch (name) {
        case "clear": setTerm([]); break;
        case "whoami": { const m = await fetchMe(); push(`${m.username ?? "anonymous"} · role ${m.role ?? "—"} · auth ${m.authEnabled ? "on" : "off"}`); break; }
        case "posture": { const p = await fetchPosture(); push(`posture ${Math.round(p.overallScore)}/100 · ${p.totalAssets} assets`); break; }
        case "verify": { const v = await verifyAuditChain(); push(v.valid ? `audit chain VALID · ${v.checked} entries` : `audit chain INVALID: ${v.errors.join("; ")}`); break; }
        case "sync": { const r = await syncRemediations(); push(`remediation sync · ${r.changed} updated`); break; }
        case "scan": { push("running full scan…"); const r = await triggerScan([]); push(`scan complete · ${r.scans_completed} scans · ${r.total_findings} findings`); break; }
        case "targets": case "estate": { const t = await fetchTargets(); push(`${t.total} target(s) · ${t.exposedServices} services · ${t.quantumVulnerable} vulnerable`); t.targets.slice(0, 8).forEach((x) => push(`  ${x.name.padEnd(22)} ${x.host.padEnd(24)} ${x.pqcStatus}`)); break; }
        case "assets": { const a = await fetchAssets(); push(`${a.total} asset(s) · ${a.vulnerable} vulnerable · ${a.connectors.length} connector(s)`); break; }
        case "endpoints": { const e = await fetchEndpoints(); push(`${e.total} endpoint(s) · ${e.quantumVulnerable} quantum-vulnerable`); break; }
        case "certs": { const c = await fetchCertificates(); push(`${c.total} cert(s) · ${c.active} active · ${c.hybrid} hybrid · ${c.revoked} revoked`); break; }
        case "paths": { const g = await fetchAttackPaths(); push(`${g.summary.total} path(s) · ${g.summary.critical} critical · ${g.summary.hndl} HNDL`); g.paths.slice(0, 6).forEach((p) => push(`  [${p.severity}] ${p.title.slice(0, 62)}`)); break; }
        case "plans": case "remediate": { const r = await fetchMigrationPlans(); push(`${r.total} migration plan(s) open`); break; }
        case "alerts": { const a = await fetchAlerts(20); push(`${a.alerts.length} alert(s)`); a.alerts.slice(0, 6).forEach((x) => push(`  [${x.severity}] ${x.title}`)); break; }
        case "frameworks": { const f = await fetchFrameworks(); f.frameworks.forEach((fr) => push(`  ${fr.name.padEnd(22)} ${fr.verdict}  ${fr.summary.enforced}/${fr.summary.total}`)); break; }
        case "gate": { if (!args[0]) { push("usage: gate <id>  (cnsa-2.0 | nist-800-53 | pci-dss | fedramp)"); break; } const d = await fetchFramework(args[0]); push(`${d.name} · ${d.verdict} · ${d.summary.gaps} gap(s)`); break; }
        case "threats": { const t = await fetchThreats(); push(`${t.length} threat(s)`); t.slice(0, 6).forEach((x) => push(`  [${x.severity}] ${x.threat_type}${x.blocked ? " (blocked)" : ""}`)); break; }
        case "ct": { if (!args[0]) { push("usage: ct <domain>"); break; } push(`querying CT logs for ${args[0]}…`); const r = await ctScan(args[0], 25); push(`  ${r.certificatesFound} cert(s) · ${r.weak} weak · issuers: ${r.issuers.slice(0, 3).join(", ") || "—"}`); break; }
        case "seed": { const r = await seedDemo(false); push(`demo estate seeded · ${r.targets} targets · ${r.findings} findings`); qc.invalidateQueries(); break; }
        case "settings": { const s = await fetchSettings(); const st = s.settings; push(`scanning ${st.scanningPaused ? "PAUSED" : "active"} · disabled: [${st.disabledScanners.join(", ") || "none"}] · external-lookups ${st.externalLookupsEnabled ? "on" : "off"}`); break; }
        case "pause": case "resume": { const cur = await fetchSettings(); const paused = name.toLowerCase() === "pause"; await saveSettings({ ...cur.settings, scanningPaused: paused }); qc.invalidateQueries({ queryKey: ["settings"] }); push(`scanning ${paused ? "PAUSED" : "resumed"}`); break; }
        case "evidence": { push("downloading signed evidence pack…"); openAuthed("/api/evidence", "quantawatch-evidence.json"); break; }
        case "cbom": { push("downloading CBOM…"); openAuthed(CBOM_DOWNLOAD_URL, "quantawatch-cbom.json"); break; }
        case "open": { if (args[0]) { const to = args[0].startsWith("/") ? args[0] : "/" + args[0]; navigate(to); push(`opened ${to}`); } else push("usage: open <view>"); break; }
        default: push(`unknown command: ${name} — try 'help'`);
      }
    } catch (e) { push(`error: ${e instanceof Error ? e.message : String(e)}`); }
  };

  const openPanel = (tab: PanelTab) => { setPanelOpen(true); setPanelTab(tab); };

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", background: C.editor, color: "var(--mantine-color-dark-0)" }}>
      <MenuBar
        run={runCommand} nav={navigate} palette={() => setPalette(true)}
        toggleSidebar={() => setSidebarOpen((v) => !v)} togglePanel={() => setPanelOpen((v) => !v)}
        openPanel={openPanel} clearTerm={() => setTerm([])} signOut={signOut}
        download={(u, f) => openAuthed(u, f)}
      />

      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        {/* Activity bar */}
        <div style={{ width: 48, background: C.activity, display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 8, borderRight: `1px solid ${C.border}` }}>
          <ActIcon d={I.explorer} active={sidebarOpen} title="Explorer" onClick={() => setSidebarOpen((v) => !v)} />
          <ActIcon d={I.search} title="Command palette (Ctrl+P)" onClick={() => setPalette(true)} />
          <ActIcon d={I.bug} title="Findings" onClick={() => navigate("/scans")} />
          <ActIcon d={I.shield} title="Governance" onClick={() => navigate("/frameworks")} />
          <ActIcon d={I.terminal} title="Terminal (Ctrl+`)" onClick={() => openPanel("terminal")} />
          <div style={{ flex: 1 }} />
          <ActIcon d={I.signout} title="Sign out" onClick={signOut} />
          <ActIcon d={I.gear} active={pathname.startsWith("/settings")} title="Settings" onClick={() => navigate("/settings")} />
        </div>

        {/* Explorer */}
        {sidebarOpen && (
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
                        <button onClick={() => setCollapsed((c) => ({ ...c, [key]: !c[key] }))} style={treeGroupStyle}>
                          <span style={{ display: "inline-flex", transition: "transform .12s", transform: isCol ? "rotate(0deg)" : "rotate(90deg)" }}><Ic d={I.chevron} size={11} w={2.4} /></span>
                          {s.label}
                        </button>
                      )}
                      {!isCol && s.items.map((item) => {
                        const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
                        const badge = item.badge ? navBadges[item.badge] : undefined;
                        const qa = item.quickAction;
                        return (
                          <button key={item.to} onClick={() => navigate(item.to)} style={treeRow(active)} className="qw-navrow" title={item.label}>
                            <span style={{ width: 16, height: 16, display: "grid", placeItems: "center", opacity: 0.85, flexShrink: 0 }}>{item.icon}</span>
                            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
                            {qa && (
                              <span
                                className="qw-navaction"
                                title={qa.label}
                                onClick={(e) => { e.stopPropagation(); navigate(qa.to); }}
                                style={{ display: "none", flexShrink: 0, width: 16, height: 16, placeItems: "center", opacity: 0.7 }}
                              >
                                <Ic d={I.plus} size={13} w={2} />
                              </span>
                            )}
                            {badge && badge.count > 0 && (
                              <span style={{ flexShrink: 0, minWidth: 16, height: 15, padding: "0 5px", display: "grid", placeItems: "center", borderRadius: 8, fontSize: 9.5, fontWeight: 700, fontFamily: "var(--font-mono)", color: "#fff", background: badge.color }}>
                                {badge.count > 99 ? "99+" : badge.count}
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          </div>
        )}

        {/* Editor column */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          {tabMenu}
          <div style={{ display: "flex", background: C.chrome, borderBottom: `1px solid ${C.border}`, overflowX: "auto", flexShrink: 0 }}>
            {openPaths.map((p) => {
              const active = p === pathname;
              return (
                <div key={p} onClick={() => navigate(p)} title={p}
                  onContextMenu={(e) => openTabMenu(e, tabMenuItems(p))}
                  draggable
                  onDragStart={(e) => { dragPath.current = p; e.dataTransfer.effectAllowed = "move"; }}
                  onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; }}
                  onDrop={(e) => { e.preventDefault(); if (dragPath.current) reorderTabs(dragPath.current, p); dragPath.current = null; }}
                  onDragEnd={() => { dragPath.current = null; }}
                  style={{ display: "flex", alignItems: "center", gap: 7, padding: "0 10px", height: 35, cursor: "pointer", fontSize: 12.5, whiteSpace: "nowrap", userSelect: "none", color: active ? "#fff" : C.textDim, background: active ? C.editor : "transparent", borderRight: `1px solid ${C.border}`, borderTop: active ? `1.5px solid ${C.accent}` : "1.5px solid transparent" }}>
                  <span style={{ width: 14, height: 14, display: "grid", placeItems: "center", opacity: 0.9 }}>{iconFor(p)}</span>
                  {labelFor(p)}
                  <span onClick={(e) => { e.stopPropagation(); closeTab(p); }} style={{ display: "grid", placeItems: "center", width: 16, height: 16, borderRadius: 2, opacity: 0.6 }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,.12)")} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                    <Ic d={I.close} size={12} w={2} />
                  </span>
                </div>
              );
            })}
          </div>

          <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
            <ScrollArea style={{ flex: 1, background: C.editor }} scrollbarSize={10}>
              <div style={{ padding: "20px 22px 40px", maxWidth: 1180, margin: "0 auto" }}>
                {/* key on pathname so a crash on one view doesn't stick to the next */}
                <Boundary key={pathname} label={labelFor(pathname)}>{children}</Boundary>
              </div>
            </ScrollArea>
            <Boundary label="Panel">
              <BottomPanel open={panelOpen} tab={panelTab} onTab={setPanelTab} onToggle={() => setPanelOpen((v) => !v)} term={term} run={runCommand} onProblem={() => navigate("/threats")} />
            </Boundary>
          </div>
        </div>
      </div>

      <Boundary label="Status bar"><StatusBar openCount={openPaths.length} onOutput={() => openPanel("output")} onPalette={() => setPalette(true)} /></Boundary>
      <CommandPalette opened={palette} onClose={() => setPalette(false)} onPick={(to) => { setPalette(false); navigate(to); }} />
    </div>
  );
}

// ---- Menu bar ----
const menuBtnStyle: React.CSSProperties = { background: "transparent", border: "none", color: "#c9cdd6", cursor: "pointer", fontSize: 12.5, padding: "0 10px", height: "100%", fontFamily: "var(--font-sans)" };
function MenuBar(p: {
  run: (c: string) => void; nav: (to: string) => void; palette: () => void; toggleSidebar: () => void;
  togglePanel: () => void; openPanel: (t: PanelTab) => void; clearTerm: () => void; signOut: () => void;
  download: (u: string, f?: string) => void;
}) {
  const M = ({ label, children }: { label: string; children: ReactNode }) => (
    <Menu shadow="md" width={230} position="bottom-start" trigger="click" offset={2} radius={2}>
      <Menu.Target><button style={menuBtnStyle} onMouseEnter={(e) => (e.currentTarget.style.color = "#fff")} onMouseLeave={(e) => (e.currentTarget.style.color = "#c9cdd6")}>{label}</button></Menu.Target>
      <Menu.Dropdown style={{ background: "var(--mantine-color-dark-7)", borderColor: C.border }}>{children}</Menu.Dropdown>
    </Menu>
  );
  return (
    <div style={{ display: "flex", alignItems: "center", height: 30, background: C.activity, borderBottom: `1px solid ${C.border}`, flexShrink: 0, paddingLeft: 6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 12px 0 8px" }}>
        <div style={{ width: 16, height: 16, borderRadius: 3, background: "linear-gradient(135deg, var(--mantine-color-brand-5), var(--mantine-color-brand-7))", display: "grid", placeItems: "center" }}>
          <Ic d={<path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75" />} size={11} w={2.6} />
        </div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#e8eaed", letterSpacing: "0.02em" }}>QuantaWatch</span>
      </div>
      <M label="File">
        <Menu.Item onClick={() => p.run("scan")}>New Scan</Menu.Item>
        <Menu.Item onClick={() => p.download(CBOM_DOWNLOAD_URL, "quantawatch-cbom.json")}>Export CBOM…</Menu.Item>
        <Menu.Item onClick={() => p.download(BOARD_REPORT_URL)}>Board Report (PDF)</Menu.Item>
        <Menu.Divider />
        <Menu.Item color="red" onClick={p.signOut}>Sign Out</Menu.Item>
      </M>
      <M label="Edit">
        <Menu.Item onClick={p.palette}>Command Palette… <span style={{ float: "right", opacity: 0.5, fontFamily: "var(--font-mono)" }}>Ctrl+P</span></Menu.Item>
        <Menu.Item onClick={p.palette}>Go to View…</Menu.Item>
      </M>
      <M label="View">
        <Menu.Item onClick={p.toggleSidebar}>Toggle Explorer</Menu.Item>
        <Menu.Item onClick={p.togglePanel}>Toggle Panel <span style={{ float: "right", opacity: 0.5, fontFamily: "var(--font-mono)" }}>Ctrl+`</span></Menu.Item>
        <Menu.Divider />
        <Menu.Item onClick={() => p.nav("/")}>Dashboard</Menu.Item>
        <Menu.Item onClick={() => p.nav("/posture")}>PQC Posture</Menu.Item>
        <Menu.Item onClick={() => p.nav("/attack-paths")}>Attack Paths</Menu.Item>
      </M>
      <M label="Tools">
        <Menu.Item onClick={() => p.run("scan")}>Run Full Scan</Menu.Item>
        <Menu.Item onClick={() => p.run("verify")}>Verify Audit Chain</Menu.Item>
        <Menu.Item onClick={() => p.run("sync")}>Sync Remediations</Menu.Item>
        <Menu.Item onClick={() => p.run("frameworks")}>Evaluate Frameworks</Menu.Item>
        <Menu.Divider />
        <Menu.Item onClick={() => p.nav("/frameworks")}>Compliance Frameworks</Menu.Item>
        <Menu.Item onClick={() => p.nav("/rbac")}>Access Control (RBAC)</Menu.Item>
      </M>
      <M label="Terminal">
        <Menu.Item onClick={() => p.openPanel("terminal")}>Open Terminal <span style={{ float: "right", opacity: 0.5, fontFamily: "var(--font-mono)" }}>Ctrl+`</span></Menu.Item>
        <Menu.Item onClick={() => p.run("help")}>List Commands</Menu.Item>
        <Menu.Item onClick={p.clearTerm}>Clear Terminal</Menu.Item>
        <Menu.Divider />
        <Menu.Item onClick={() => p.openPanel("problems")}>Show Problems</Menu.Item>
        <Menu.Item onClick={() => p.openPanel("output")}>Show Output</Menu.Item>
      </M>
      <M label="Help">
        <Menu.Item onClick={p.palette}>Command Palette</Menu.Item>
        <Menu.Item onClick={() => p.run("help")}>Console Commands</Menu.Item>
        <Menu.Divider />
        <Menu.Item onClick={() => p.run("posture")}>About / Status</Menu.Item>
      </M>
    </div>
  );
}

const treeGroupStyle: React.CSSProperties = { display: "flex", alignItems: "center", gap: 4, width: "100%", cursor: "pointer", padding: "6px 10px 2px", fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em", color: "var(--mantine-color-dark-3)", textTransform: "uppercase", background: "transparent", border: "none" };
function treeRow(active: boolean): React.CSSProperties {
  return { display: "flex", alignItems: "center", gap: 8, width: "100%", cursor: "pointer", padding: "5px 10px 5px 20px", fontSize: 13, textAlign: "left", border: "none", color: active ? "#fff" : "var(--mantine-color-dark-1)", background: active ? "color-mix(in srgb, var(--mantine-color-brand-6) 22%, transparent)" : "transparent", borderLeft: active ? "2px solid var(--mantine-color-brand-5)" : "2px solid transparent" };
}

function ActIcon({ d, active, title, onClick }: { d: ReactNode; active?: boolean; title: string; onClick: () => void }) {
  return (
    <Tooltip label={title} position="right" openDelay={300} withArrow>
      <button onClick={onClick} aria-label={title} style={{ width: 48, height: 44, display: "grid", placeItems: "center", cursor: "pointer", background: "transparent", border: "none", color: active ? "#fff" : "#8a8f99", borderLeft: active ? `2px solid ${C.accent}` : "2px solid transparent" }}
        onMouseEnter={(e) => { if (!active) e.currentTarget.style.color = "#fff"; }} onMouseLeave={(e) => { if (!active) e.currentTarget.style.color = "#8a8f99"; }}>
        <Ic d={d} size={23} />
      </button>
    </Tooltip>
  );
}

// ---- Bottom panel: Problems / Output / Terminal ----
function BottomPanel({ open, tab, onTab, onToggle, term, run, onProblem }: { open: boolean; tab: PanelTab; onTab: (t: PanelTab) => void; onToggle: () => void; term: string[]; run: (c: string) => void; onProblem: () => void }) {
  const { data: auditData } = useQuery({ queryKey: ["audit-feed"], queryFn: () => fetchAuditEntries(60), refetchInterval: 5000 });
  const { data: threats } = useQuery({ queryKey: ["threats-panel"], queryFn: fetchThreats, refetchInterval: 8000 });
  const audit = Array.isArray(auditData) ? auditData : ((auditData as unknown as { entries?: unknown[] })?.entries ?? []);
  const termRef = useRef<HTMLDivElement | null>(null);
  const [input, setInput] = useState("");
  const inputRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight; }, [term, tab]);
  useEffect(() => { if (open && tab === "terminal") inputRef.current?.focus(); }, [open, tab]);

  const evColor = (t: string) => /threat|denied|failed|blocked/.test(t) ? "var(--mantine-color-red-4)" : /enforced|policy|violation/.test(t) ? "var(--mantine-color-orange-4)" : /login|admin|logout|scan/.test(t) ? "var(--mantine-color-brand-3)" : "var(--mantine-color-dark-2)";
  const sevColor = (s: string) => s === "critical" ? "var(--mantine-color-red-4)" : s === "high" ? "var(--mantine-color-orange-4)" : s === "medium" ? "var(--mantine-color-yellow-4)" : "var(--mantine-color-dark-2)";

  const Tab = ({ id, label, count }: { id: PanelTab; label: string; count?: number }) => (
    <button onClick={() => onTab(id)} style={{ background: "transparent", border: "none", cursor: "pointer", height: "100%", padding: "0 12px", fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em", textTransform: "uppercase", color: tab === id ? "#fff" : C.textDim, borderBottom: tab === id ? `1.5px solid ${C.accent}` : "1.5px solid transparent" }}>
      {label}{typeof count === "number" && count > 0 ? ` (${count})` : ""}
    </button>
  );

  return (
    <div style={{ borderTop: `1px solid ${C.border}`, background: C.editor, flexShrink: 0, display: "flex", flexDirection: "column", height: open ? 210 : 31 }}>
      <div style={{ display: "flex", alignItems: "center", height: 31, borderBottom: open ? `1px solid ${C.border}` : "none", flexShrink: 0, paddingRight: 8 }}>
        <Tab id="problems" label="Problems" count={(threats ?? []).length} />
        <Tab id="output" label="Output" />
        <Tab id="terminal" label="Terminal" />
        <div style={{ flex: 1 }} />
        <button onClick={onToggle} title={open ? "Collapse" : "Expand"} style={{ background: "transparent", border: "none", color: C.textDim, cursor: "pointer", display: "grid", placeItems: "center" }}>
          <span style={{ display: "inline-flex", transform: open ? "rotate(90deg)" : "rotate(-90deg)" }}><Ic d={I.chevron} size={12} w={2.2} /></span>
        </button>
      </div>
      {open && (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          {tab === "output" && (
            <div ref={termRef} style={{ flex: 1, overflow: "auto", padding: "6px 12px", fontFamily: "var(--font-mono)", fontSize: 11.5, lineHeight: 1.7 }}>
              {audit.length === 0 && <div style={{ color: C.textDim }}>waiting for events…</div>}
              {(audit as { id: number; timestamp: string; event_type: string; session_id: string; details: string }[]).slice(0, 60).map((e) => (
                <div key={e.id} style={{ whiteSpace: "nowrap" }}>
                  <span style={{ color: "#5a6070" }}>{new Date(e.timestamp).toLocaleTimeString()}</span>{"  "}
                  <span style={{ color: evColor(e.event_type) }}>{e.event_type}</span>{"  "}
                  <span style={{ color: "#7a8091" }}>{(e.session_id || "").slice(0, 12)}</span>{"  "}
                  <span style={{ color: "var(--mantine-color-dark-1)" }}>{(e.details || "").slice(0, 130)}</span>
                </div>
              ))}
            </div>
          )}
          {tab === "problems" && (
            <div style={{ flex: 1, overflow: "auto", padding: "4px 0", fontSize: 12.5 }}>
              {(threats ?? []).length === 0 && <div style={{ color: C.textDim, padding: "8px 14px" }}>No active problems — the monitor has flagged nothing.</div>}
              {(threats ?? []).map((t) => (
                <div key={t.id} onClick={onProblem} title="Open Threats"
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 14px", cursor: "pointer" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,.03)")} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                  <span style={{ width: 7, height: 7, borderRadius: "50%", background: sevColor(t.severity), flexShrink: 0 }} />
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, textTransform: "uppercase", color: sevColor(t.severity), width: 62 }}>{t.severity}</span>
                  <span style={{ color: "#e8eaed" }}>{t.threat_type}</span>
                  <span style={{ color: C.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.description}</span>
                  {t.blocked && <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--mantine-color-signal-4)" }}>BLOCKED</span>}
                </div>
              ))}
            </div>
          )}
          {tab === "terminal" && (
            <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}
              onClick={() => { if (!window.getSelection()?.toString()) inputRef.current?.focus(); }}>
              <div ref={termRef} style={{ flex: 1, overflow: "auto", padding: "6px 12px 2px", fontFamily: "var(--font-mono)", fontSize: 11.5, lineHeight: 1.6, userSelect: "text", cursor: "text" }}>
                {term.map((l, i) => (
                  <div key={i} style={{ whiteSpace: "pre-wrap", userSelect: "text", color: l.startsWith("qw>") ? "var(--mantine-color-brand-3)" : l.startsWith("error:") ? "var(--mantine-color-red-4)" : "var(--mantine-color-dark-1)" }}>{l}</div>
                ))}
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 12px 8px", borderTop: `1px solid ${C.border}` }}>
                <span style={{ color: "var(--mantine-color-brand-4)", fontFamily: "var(--font-mono)", fontSize: 12 }}>qw&gt;</span>
                <input ref={inputRef} value={input} onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") { run(input); setInput(""); } }}
                  placeholder="type a command… (help)"
                  style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "#fff", fontFamily: "var(--font-mono)", fontSize: 12 }} />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---- Status bar ----
function StatusBar({ openCount, onOutput, onPalette }: { openCount: number; onOutput: () => void; onPalette: () => void }) {
  const qc = useQueryClient();
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: fetchMe });
  const { data: posture } = useQuery({ queryKey: ["posture"], queryFn: fetchPosture });
  const { data: tenants } = useQuery({ queryKey: ["tenants"], queryFn: fetchTenants });
  const current = getTenant() ?? "default";
  const item: React.CSSProperties = { display: "inline-flex", alignItems: "center", gap: 5, padding: "0 8px", height: "100%", cursor: "pointer" };
  const cycleOrg = () => {
    const list = tenants?.tenants ?? [];
    if (list.length < 2) return;
    const next = list[(list.indexOf(current) + 1) % list.length];
    setTenant(next === "default" ? null : next); qc.clear(); window.location.reload();
  };
  return (
    <div style={{ height: 24, background: C.accent, color: "#fff", display: "flex", alignItems: "center", fontFamily: "var(--font-mono)", fontSize: 11, flexShrink: 0 }}>
      <span style={item}><span style={{ width: 7, height: 7, borderRadius: "50%", background: "#9ff0c8", boxShadow: "0 0 6px #9ff0c8" }} /> Gateway online</span>
      {typeof posture?.overallScore === "number" && <span style={item}>◆ Posture {Math.round(posture.overallScore)}/100</span>}
      <div style={{ flex: 1 }} />
      <span style={item} onClick={cycleOrg} title="Switch tenant">⛁ {current}</span>
      {me?.username && <span style={item} title={me.role}>{me.username.replace(/^apikey:/, "")} · {me.role}</span>}
      <span style={item} onClick={onOutput} title="Output">≣ {openCount} open</span>
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
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)", zIndex: 1000, display: "flex", justifyContent: "center", paddingTop: "13vh" }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 560, maxHeight: "72vh", background: "var(--mantine-color-dark-7)", border: `1px solid ${C.border}`, borderRadius: 3, overflow: "hidden", display: "flex", flexDirection: "column", boxShadow: "0 12px 48px rgba(0,0,0,.5)" }}>
        <input autoFocus value={q} onChange={(e) => { setQ(e.currentTarget.value); setSel(0); }} placeholder="Go to view…  (Ctrl+P)"
          style={{ background: "transparent", border: "none", borderBottom: `1px solid ${C.border}`, outline: "none", color: "#fff", fontFamily: "var(--font-mono)", fontSize: 14, padding: "13px 16px" }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(results.length - 1, s + 1)); }
            if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
            if (e.key === "Enter" && results[sel]) onPick(results[sel].to);
            if (e.key === "Escape") onClose();
          }} />
        <div style={{ overflow: "auto", padding: 4 }}>
          {results.map((r, i) => (
            <div key={r.to} onClick={() => onPick(r.to)} onMouseEnter={() => setSel(i)} style={{ display: "flex", alignItems: "center", gap: 9, padding: "7px 12px", cursor: "pointer", borderRadius: 2, background: i === sel ? "color-mix(in srgb, var(--mantine-color-brand-6) 26%, transparent)" : "transparent" }}>
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
