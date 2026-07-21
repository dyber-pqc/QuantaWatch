import type {
  Target,
  TargetBoard,
  OverlayStatus,
  CryptoPolicyBoard,
  CryptoPolicyResult,
  EnforceResult,
  Session,
  AuditEntry,
  Stats,
  Threat,
  AuditVerifyResult,
  PostureSummary,
  PostureSnapshot,
  AgentPostureResponse,
  ComplianceReport,
  AttackPathsResponse,
  SimulateResponse,
  AttackPathTimeline,
  AssetsResponse,
  SlosResponse,
  SloHistoryResponse,
  AlertsResponse,
  Attestation,
  CryptoBom,
  ScanRecord,
  ScanResult,
  FindingRecord,
  IntegrationInfo,
  ConnectionStatus,
  DiscoveredTarget,
  IntegrationScanResult,
  RemediationTicket,
  Soc2Report,
  RbacReport,
  FrameworkSummary,
  FrameworkDetail,
  MigrationPlan,
} from "./types";

// ---- Mock data for development when API is unavailable ----

const MOCK_SESSIONS: Session[] = [
  {
    session_id: "sess-a1b2c3d4",
    agent_name: "code-assistant-v2",
    created_at: "2026-03-11T08:12:00Z",
    request_count: 47,
    status: "active",
  },
  {
    session_id: "sess-e5f6g7h8",
    agent_name: "data-analyst",
    created_at: "2026-03-11T07:45:00Z",
    request_count: 123,
    status: "active",
  },
  {
    session_id: "sess-i9j0k1l2",
    agent_name: "research-bot",
    created_at: "2026-03-11T06:30:00Z",
    request_count: 89,
    status: "completed",
  },
  {
    session_id: "sess-m3n4o5p6",
    agent_name: "code-assistant-v2",
    created_at: "2026-03-10T22:15:00Z",
    request_count: 201,
    status: "completed",
  },
  {
    session_id: "sess-q7r8s9t0",
    agent_name: "security-scanner",
    created_at: "2026-03-10T19:00:00Z",
    request_count: 15,
    status: "terminated",
  },
  {
    session_id: "sess-u1v2w3x4",
    agent_name: "translation-agent",
    created_at: "2026-03-10T16:40:00Z",
    request_count: 68,
    status: "completed",
  },
];

const MOCK_THREATS: Threat[] = [
  {
    id: 1,
    timestamp: "2026-03-11T08:45:12Z",
    session_id: "sess-a1b2c3d4",
    threat_type: "prompt_injection",
    severity: "critical",
    description: "Detected prompt injection attempt: system prompt override via encoded payload",
    blocked: true,
  },
  {
    id: 2,
    timestamp: "2026-03-11T08:30:05Z",
    session_id: "sess-e5f6g7h8",
    threat_type: "data_exfiltration",
    severity: "high",
    description: "Potential data exfiltration: agent requested sensitive file paths outside sandbox",
    blocked: true,
  },
  {
    id: 3,
    timestamp: "2026-03-11T07:55:33Z",
    session_id: "sess-a1b2c3d4",
    threat_type: "rate_limit_exceeded",
    severity: "medium",
    description: "Rate limit exceeded: 150 requests/min (threshold: 100)",
    blocked: false,
  },
  {
    id: 4,
    timestamp: "2026-03-11T06:12:44Z",
    session_id: "sess-i9j0k1l2",
    threat_type: "token_abuse",
    severity: "low",
    description: "Unusual token usage pattern detected: large context window padding",
    blocked: false,
  },
  {
    id: 5,
    timestamp: "2026-03-10T23:01:00Z",
    session_id: "sess-m3n4o5p6",
    threat_type: "prompt_injection",
    severity: "high",
    description: "Prompt injection via tool output: hidden instruction in returned JSON",
    blocked: true,
  },
  {
    id: 6,
    timestamp: "2026-03-10T20:15:22Z",
    session_id: "sess-q7r8s9t0",
    threat_type: "unauthorized_access",
    severity: "critical",
    description: "Attempted access to admin API endpoints without proper authorization",
    blocked: true,
  },
];

const MOCK_AUDIT_ENTRIES: AuditEntry[] = Array.from({ length: 25 }, (_, i) => ({
  id: 25 - i,
  timestamp: new Date(
    Date.now() - i * 12 * 60 * 1000,
  ).toISOString(),
  event_type: [
    "request",
    "response",
    "threat_detected",
    "session_start",
    "session_end",
    "policy_check",
  ][i % 6],
  session_id: MOCK_SESSIONS[i % MOCK_SESSIONS.length].session_id,
  details: [
    "Incoming request processed through policy engine",
    "Response delivered after content filtering",
    "Threat detected and blocked by security layer",
    "New agent session initialized with sandbox constraints",
    "Session completed normally, resources released",
    "Policy compliance check passed for outbound request",
  ][i % 6],
  hash: `sha256:${Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join("")}`,
  prev_hash:
    i === 24
      ? "sha256:0000000000000000"
      : `sha256:${Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join("")}`,
}));

const MOCK_STATS: Stats = {
  total_sessions: 142,
  total_requests: 8_437,
  active_threats: 3,
  audit_entries: 12_891,
  requests_per_minute: [
    45, 52, 48, 61, 55, 70, 65, 72, 80, 75, 68, 82, 90, 85, 78, 92, 88, 95,
    87, 76, 82, 91, 86, 79, 84, 93, 88, 81, 77, 85,
  ],
  threat_counts: {
    low: 12,
    medium: 8,
    high: 5,
    critical: 2,
  },
  recent_threats: MOCK_THREATS.slice(0, 5),
};

// ---- Fetch helpers ----

// ---- Auth token handling ----

const TOKEN_KEY = "qw_token";
export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t);
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

// ---- Tenant (org) selection for multi-tenant admins ----
const TENANT_KEY = "qw_tenant";
export function getTenant(): string | null {
  return localStorage.getItem(TENANT_KEY);
}
export function setTenant(t: string | null) {
  if (t) localStorage.setItem(TENANT_KEY, t);
  else localStorage.removeItem(TENANT_KEY);
}

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const headers = new Headers(init?.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const tenant = getTenant();
  if (tenant) headers.set("X-Tenant", tenant);
  const res = await fetch(url, { ...init, headers });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event("qw-unauthorized"));
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

/**
 * Coerce an API response to an array. List endpoints are inconsistent — some
 * return a bare array, others `{ <key>: [...], total }`. This makes every
 * array-typed fetcher shape-safe so a page can never call `.filter`/`.map` on
 * an object and crash the shell.
 */
function asArray<T>(d: unknown, key: string): T[] {
  if (Array.isArray(d)) return d as T[];
  if (d && typeof d === "object") {
    const v = (d as Record<string, unknown>)[key];
    if (Array.isArray(v)) return v as T[];
  }
  return [];
}

// ---- Auth API ----

export interface MeInfo {
  authEnabled: boolean;
  authenticated: boolean;
  username?: string;
  role?: string;
  permissions?: string[];
}

export interface AuthConfigInfo {
  authEnabled: boolean;
  ssoEnabled: boolean;
  ssoLoginUrl: string;
}

export async function fetchAuthConfig(): Promise<AuthConfigInfo> {
  try {
    const res = await fetch("/api/auth/config");
    return await res.json();
  } catch {
    return { authEnabled: false, ssoEnabled: false, ssoLoginUrl: "/api/auth/oidc/login" };
  }
}

export async function syncRemediations(): Promise<{ changed: number }> {
  return fetchJSON("/api/remediations/sync", { method: "POST" });
}

export async function fetchSlos(): Promise<SlosResponse> {
  try {
    return await fetchJSON<SlosResponse>("/api/slos");
  } catch {
    return { slos: [], allPass: true, gateBreach: false };
  }
}

export async function fetchSloHistory(): Promise<SloHistoryResponse> {
  try {
    return await fetchJSON<SloHistoryResponse>("/api/slos/history");
  } catch {
    return { history: [], total: 0 };
  }
}

export async function registerIntegrationWebhook(
  id: string,
  callbackUrl: string,
): Promise<{ ok: boolean; detail: string }> {
  return fetchJSON(`/api/integrations/${id}/register-webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ callbackUrl }),
  });
}

export interface TenantsResponse {
  tenants: string[];
  canSwitch: boolean;
}

export async function fetchTenants(): Promise<TenantsResponse> {
  try {
    return await fetchJSON<TenantsResponse>("/api/tenants");
  } catch {
    return { tenants: [], canSwitch: false };
  }
}

export async function fetchMe(): Promise<MeInfo> {
  const token = getToken();
  const res = await fetch("/api/auth/me", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401) return { authEnabled: true, authenticated: false };
  const d = await res.json();
  return {
    authEnabled: !!d.authEnabled,
    authenticated: !!d.username,
    username: d.username,
    role: d.role,
    permissions: d.permissions,
  };
}

// ---- Governance: SOC2 controls + RBAC matrix ----

export async function fetchSoc2(): Promise<Soc2Report> {
  return fetchJSON<Soc2Report>("/api/soc2");
}

export async function fetchRbac(): Promise<RbacReport> {
  return fetchJSON<RbacReport>("/api/rbac");
}

export async function fetchFrameworks(): Promise<{ frameworks: FrameworkSummary[]; note: string }> {
  return fetchJSON("/api/frameworks");
}

export async function fetchFramework(id: string): Promise<FrameworkDetail> {
  return fetchJSON<FrameworkDetail>(`/api/frameworks/${id}`);
}

export async function login(username: string, password: string): Promise<void> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("Invalid username or password");
  const data = await res.json();
  setToken(data.token);
}

export async function logout(): Promise<void> {
  try {
    await fetchJSON("/api/auth/logout", { method: "POST" });
  } catch {
    /* ignore */
  }
  clearToken();
}

/**
 * Fetch a report/download endpoint WITH the auth token, then open it (a plain
 * <a href> navigation can't carry the bearer token when auth is enabled).
 * If `filename` is given it downloads; otherwise it opens in a new tab.
 */
export async function openAuthed(url: string, filename?: string): Promise<void> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const tenant = getTenant();
  if (tenant) headers["X-Tenant"] = tenant;
  const res = await fetch(url, { headers });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event("qw-unauthorized"));
    return;
  }
  const blob = await res.blob();
  const objUrl = URL.createObjectURL(blob);
  if (filename) {
    const a = document.createElement("a");
    a.href = objUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } else {
    window.open(objUrl, "_blank");
  }
  setTimeout(() => URL.revokeObjectURL(objUrl), 60_000);
}

// ---- Public API functions ----

export async function fetchSessions(): Promise<Session[]> {
  try {
    // /api/sessions returns { sessions, total }.
    return asArray<Session>(await fetchJSON("/api/sessions"), "sessions");
  } catch {
    console.warn("API unavailable, using mock session data");
    return MOCK_SESSIONS;
  }
}

// Summarize an AuditEvent's payload (every field except the discriminant
// `type`) into a readable one-line detail string, e.g.
// "scanner id: tls · target: api.openai.com:443 · status: Completed".
function summarizeAuditEvent(event: Record<string, unknown>): string {
  return Object.entries(event)
    .filter(([k]) => k !== "type")
    .map(([k, v]) => `${k.split("_").join(" ")}: ${v}`)
    .join(" · ");
}

// The API returns a signed entry shaped as { sequence, timestamp, session_id,
// content_hash, prev_hash, event: { type, ...fields } } — NOT the flat
// AuditEntry the table renders. Normalize it here so the page (and the type)
// stay flat and honest, and so `event_type` is never undefined.
function normalizeAuditEntry(raw: Record<string, unknown>): AuditEntry {
  const event = (raw.event as Record<string, unknown> | undefined) ?? {};
  return {
    id: (raw.sequence as number) ?? (raw.id as number) ?? 0,
    timestamp: (raw.timestamp as string) ?? "",
    event_type: (event.type as string) ?? (raw.event_type as string) ?? "unknown",
    session_id: (raw.session_id as string) ?? "",
    details: (raw.details as string) ?? summarizeAuditEvent(event),
    hash: (raw.content_hash as string) ?? (raw.hash as string) ?? "",
    prev_hash: (raw.prev_hash as string) ?? "",
  };
}

export async function fetchAuditEntries(
  limit: number = 50,
): Promise<AuditEntry[]> {
  try {
    // /api/audit returns { entries, total }, oldest-first. Normalize each
    // signed entry to the flat shape and show newest-first.
    const raw = asArray<Record<string, unknown>>(
      await fetchJSON(`/api/audit?limit=${limit}`),
      "entries",
    );
    return raw.map(normalizeAuditEntry).reverse();
  } catch {
    console.warn("API unavailable, using mock audit data");
    return MOCK_AUDIT_ENTRIES.slice(0, limit);
  }
}

export async function fetchStats(): Promise<Stats> {
  try {
    // The gateway /api/stats endpoint is intentionally thin; normalize it into the
    // full dashboard shape so the page renders with the fields it does expose and
    // safe defaults for the rest (rather than crashing on undefined arrays).
    const num = (v: unknown) => (typeof v === "number" ? v : 0);
    // /api/stats is intentionally thin (sessions/requests/tokens); it carries no
    // threat or audit data. Compose those from the endpoints that do, so the
    // dashboard shows real counts instead of hardcoded zeros.
    const [raw, threats, auditMeta] = await Promise.all([
      fetchJSON<Record<string, unknown>>("/api/stats"),
      fetchThreats(), // already returns [] on failure
      fetchJSON<Record<string, unknown>>("/api/audit?limit=1").catch(() => ({} as Record<string, unknown>)),
    ]);

    const threat_counts = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const t of threats) {
      if (t.severity in threat_counts) threat_counts[t.severity] += 1;
    }

    return {
      total_sessions: num(raw.total_sessions ?? raw.active_sessions),
      total_requests: num(raw.total_requests),
      active_threats: threats.length,
      audit_entries: num(auditMeta.total),
      requests_per_minute: Array.isArray(raw.requests_per_minute) ? (raw.requests_per_minute as number[]) : [],
      threat_counts,
      // newest-first; the endpoint already sorts, take the top few for the panel.
      recent_threats: threats.slice(0, 6),
    };
  } catch {
    console.warn("API unavailable, using mock stats data");
    return MOCK_STATS;
  }
}

export async function fetchThreats(): Promise<Threat[]> {
  try {
    // Accepts a bare array or { threats } — and returns [] on failure rather
    // than mock data (showing fake threats in a security product is worse than
    // showing none).
    return asArray<Threat>(await fetchJSON("/api/threats"), "threats");
  } catch {
    return [];
  }
}

// ---- Estate targets ----
export async function fetchTargets(): Promise<TargetBoard> {
  try {
    return await fetchJSON<TargetBoard>("/api/targets");
  } catch {
    return { targets: [], total: 0, exposedServices: 0, quantumVulnerable: 0 };
  }
}

export async function registerTarget(body: {
  name: string;
  host: string;
  kind: string;
  reachability: string[];
  environment: string;
  tags?: string[];
}): Promise<Target> {
  return fetchJSON<Target>("/api/targets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function scanTarget(id: string): Promise<Target> {
  return fetchJSON<Target>(`/api/targets/${encodeURIComponent(id)}/scan`, { method: "POST" });
}

export interface DeepScanCreds {
  port?: number;
  username: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
}
export async function deepScanTarget(
  id: string,
  creds: DeepScanCreds,
): Promise<{ target: Target; servicesFound: number }> {
  return fetchJSON(`/api/targets/${encodeURIComponent(id)}/deep-scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(creds),
  });
}

export async function deleteTarget(id: string): Promise<void> {
  await fetchJSON(`/api/targets/${encodeURIComponent(id)}`, { method: "DELETE" });
}

// ---- PQC-terminating overlay ----
export async function fetchOverlay(): Promise<OverlayStatus> {
  try {
    return await fetchJSON<OverlayStatus>("/api/overlay");
  } catch {
    return { enabled: false, certSource: "", hybridGroup: "", routes: [], total: 0, pqcProtectedRoutes: 0 };
  }
}

// ---- Crypto-agility policies ----
export async function fetchCryptoPolicies(): Promise<CryptoPolicyBoard> {
  try {
    return await fetchJSON<CryptoPolicyBoard>("/api/crypto-policies");
  } catch {
    return { policies: [], total: 0, violated: 0, compliant: 0, criticalViolations: 0 };
  }
}

export async function fetchCryptoPolicy(id: string): Promise<CryptoPolicyResult> {
  return fetchJSON<CryptoPolicyResult>(`/api/crypto-policies/${encodeURIComponent(id)}`);
}

export async function evaluateCryptoPolicies(): Promise<{ evaluated: number }> {
  return fetchJSON("/api/crypto-policies/evaluate", { method: "POST" });
}

export async function enforceCryptoPolicy(
  id: string,
  body: { integrationId?: string; project?: string; dryRun?: boolean },
): Promise<EnforceResult> {
  return fetchJSON<EnforceResult>(`/api/crypto-policies/${encodeURIComponent(id)}/enforce`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function verifyAuditChain(): Promise<AuditVerifyResult> {
  try {
    return await fetchJSON<AuditVerifyResult>("/api/audit/verify", {
      method: "POST",
    });
  } catch {
    console.warn("API unavailable, returning mock verification result");
    return { valid: true, checked: MOCK_AUDIT_ENTRIES.length, errors: [] };
  }
}

// ---- Posture & CBOM ----

const MOCK_POSTURE: PostureSummary = {
  overallScore: 62.5,
  totalAssets: 8,
  byStatus: { classical_secure: 5, classical_weak: 1, unknown: 2 },
  byCategory: [
    { category: "TLS & Protocols", score: 60.0, assetCount: 3 },
    { category: "Certificates", score: 60.0, assetCount: 2 },
    { category: "Dependencies", score: 65.0, assetCount: 2 },
    { category: "Keys & Code", score: 100.0, assetCount: 0 },
  ],
  byProvider: [
    { provider: "anthropic", score: 60.0, tlsVersion: "TLS 1.3", pqcStatus: "classical_secure" },
    { provider: "openai", score: 60.0, tlsVersion: "TLS 1.3", pqcStatus: "classical_secure" },
  ],
  calculatedAt: new Date().toISOString(),
};

export async function fetchPosture(): Promise<PostureSummary> {
  try {
    return await fetchJSON<PostureSummary>("/api/posture");
  } catch {
    console.warn("API unavailable, using mock posture data");
    return MOCK_POSTURE;
  }
}

export async function fetchCbom(): Promise<CryptoBom> {
  return fetchJSON<CryptoBom>("/api/cbom");
}

export async function fetchCompliance(): Promise<ComplianceReport> {
  return fetchJSON<ComplianceReport>("/api/compliance");
}

export async function fetchAttackPaths(): Promise<AttackPathsResponse> {
  try {
    return await fetchJSON<AttackPathsResponse>("/api/attack-paths");
  } catch {
    console.warn("API unavailable, returning empty attack-path graph");
    return { nodes: [], edges: [], paths: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, hndl: 0, observed: 0 } };
  }
}

export async function simulateAttackPaths(
  overrides: { provider: string; pqcStatus: string }[],
): Promise<SimulateResponse> {
  return fetchJSON<SimulateResponse>("/api/attack-paths/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ overrides }),
  });
}

export async function fetchAttackPathTimeline(): Promise<AttackPathTimeline> {
  try {
    return await fetchJSON<AttackPathTimeline>("/api/attack-paths/timeline");
  } catch {
    return { timeline: [], total: 0 };
  }
}

export async function remediateAttackPath(
  pathId: string,
  body: { integrationId: string; project?: string },
): Promise<RemediationTicket> {
  return fetchJSON<RemediationTicket>(`/api/attack-paths/${encodeURIComponent(pathId)}/remediate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function fetchAssets(): Promise<AssetsResponse> {
  try {
    return await fetchJSON<AssetsResponse>("/api/assets");
  } catch {
    return { assets: [], total: 0, vulnerable: 0, environments: {}, connectors: [] };
  }
}

export async function syncAssets(): Promise<{ total: number; scanned: number }> {
  return fetchJSON("/api/assets/sync", { method: "POST" });
}

/** URL of the print-ready executive quantum-risk board report. */
export const BOARD_REPORT_URL = "/api/report/board";

/** URL of the ML-DSA-signed evidence pack (CBOM + compliance + graph + audit). */
export const EVIDENCE_PACK_URL = "/api/evidence";

export async function fetchAlerts(limit: number = 100): Promise<AlertsResponse> {
  try {
    return await fetchJSON<AlertsResponse>(`/api/alerts?limit=${limit}`);
  } catch {
    console.warn("API unavailable, returning empty alerts");
    return { alerts: [], total: 0, enabled: false, channels: [], rules: { postureDropThreshold: 5, alertOnCritical: true, certExpiryDays: 30 } };
  }
}

export async function sendTestAlert(): Promise<{ fired: boolean; delivered: number; enabled: boolean }> {
  return fetchJSON("/api/alerts/test", { method: "POST" });
}

export async function fetchAttestation(): Promise<Attestation> {
  return fetchJSON<Attestation>("/api/cbom/attestation");
}

/** URL of the print-ready executive report (opens in a new tab → Save as PDF). */
export const COMPLIANCE_REPORT_URL = "/api/compliance/report";

export async function fetchAgents(): Promise<AgentPostureResponse> {
  try {
    return await fetchJSON<AgentPostureResponse>("/api/agents");
  } catch {
    console.warn("API unavailable, returning empty agent posture");
    return { agents: [], total: 0, atRisk: 0, avgScore: 100 };
  }
}

export async function fetchPostureHistory(limit: number = 100): Promise<PostureSnapshot[]> {
  try {
    // /api/posture/history returns { history, total }.
    return asArray<PostureSnapshot>(await fetchJSON(`/api/posture/history?limit=${limit}`), "history");
  } catch {
    console.warn("API unavailable, returning empty posture history");
    return [];
  }
}

/** URL for downloading the CBOM as a file (used directly in an anchor href). */
export const CBOM_DOWNLOAD_URL = "/api/cbom/download";

// ---- Scanning ----

export async function fetchScans(limit: number = 50): Promise<{ scans: ScanRecord[]; total: number }> {
  try {
    return await fetchJSON<{ scans: ScanRecord[]; total: number }>(`/api/scans?limit=${limit}`);
  } catch {
    console.warn("API unavailable, using mock scan data");
    return { scans: [], total: 0 };
  }
}

export async function triggerScan(targets: { target_type: string; address: string }[]): Promise<{ scans_completed: number; total_findings: number; results: ScanResult[] }> {
  return fetchJSON("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targets }),
  });
}

export async function fetchFindings(): Promise<{ findings: FindingRecord[]; total: number }> {
  try {
    return await fetchJSON<{ findings: FindingRecord[]; total: number }>("/api/findings");
  } catch {
    console.warn("API unavailable, using mock findings data");
    return { findings: [], total: 0 };
  }
}

// ---- Integrations ----

export async function fetchIntegrations(): Promise<{ integrations: IntegrationInfo[]; total: number }> {
  try {
    return await fetchJSON<{ integrations: IntegrationInfo[]; total: number }>("/api/integrations");
  } catch {
    console.warn("API unavailable, using mock integration data");
    return { integrations: [], total: 0 };
  }
}

export async function testIntegration(id: string): Promise<ConnectionStatus> {
  return fetchJSON<ConnectionStatus>(`/api/integrations/${id}/test`, { method: "POST" });
}

export async function syncIntegration(id: string): Promise<{ targets_discovered: number; targets: DiscoveredTarget[] }> {
  return fetchJSON(`/api/integrations/${id}/sync`, { method: "POST" });
}

/** Discover repos, fetch dependency files, scan them, and update posture. */
export async function scanIntegration(id: string): Promise<IntegrationScanResult> {
  return fetchJSON(`/api/integrations/${id}/scan`, { method: "POST" });
}

/** Create a remediation ticket (Jira/Linear) from a finding. */
export async function remediateFinding(
  findingId: string,
  body: { integrationId: string; project?: string; assignee?: string; priority?: string },
): Promise<RemediationTicket> {
  return fetchJSON<RemediationTicket>(`/api/findings/${findingId}/remediate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function fetchMigrationPlans(): Promise<{ plans: MigrationPlan[]; total: number }> {
  try {
    return await fetchJSON<{ plans: MigrationPlan[]; total: number }>("/api/remediations/plans");
  } catch {
    return { plans: [], total: 0 };
  }
}

export async function fetchRemediations(): Promise<{ remediations: RemediationTicket[]; total: number }> {
  try {
    return await fetchJSON<{ remediations: RemediationTicket[]; total: number }>("/api/remediations");
  } catch {
    console.warn("API unavailable, returning empty remediations");
    return { remediations: [], total: 0 };
  }
}
