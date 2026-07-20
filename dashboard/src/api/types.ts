// ---- API response types ----

export interface Session {
  session_id: string;
  agent_name: string;
  created_at: string;
  request_count: number;
  status: "active" | "completed" | "terminated";
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  event_type: string;
  session_id: string;
  details: string;
  hash: string;
  prev_hash: string;
}

export interface Threat {
  id: number;
  timestamp: string;
  session_id: string;
  threat_type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  blocked: boolean;
}

export interface Stats {
  total_sessions: number;
  total_requests: number;
  active_threats: number;
  audit_entries: number;
  requests_per_minute: number[];
  threat_counts: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  recent_threats: Threat[];
}

export interface AuditVerifyResult {
  valid: boolean;
  checked: number;
  errors: string[];
}

// ---- Posture & CBOM types ----

export type PqcStatus = "pqc_ready" | "hybrid" | "classical_secure" | "classical_weak" | "unknown";

export interface CategoryScore {
  category: string;
  score: number;
  assetCount: number;
}

export interface ProviderScore {
  provider: string;
  score: number;
  tlsVersion: string | null;
  pqcStatus: PqcStatus;
}

export interface PostureSummary {
  overallScore: number;
  totalAssets: number;
  byStatus: Record<string, number>;
  byCategory: CategoryScore[];
  byProvider: ProviderScore[];
  calculatedAt: string;
}

export interface PostureSnapshot {
  timestamp: string;
  overallScore: number;
  totalAssets: number;
  byStatus: Record<string, number>;
  trigger: string;
}

export interface AgentProviderPosture {
  provider: string;
  pqcStatus: PqcStatus;
  tlsVersion: string | null;
  cipherSuite: string | null;
  score: number;
  observed: boolean;
}

export interface AgentPosture {
  name: string;
  description: string;
  offline: boolean;
  overallScore: number;
  pqcStatus: PqcStatus;
  sessionCount: number;
  requestCount: number;
  modelCount: number;
  lastActive: string | null;
  providers: AgentProviderPosture[];
}

export interface AgentPostureResponse {
  agents: AgentPosture[];
  total: number;
  atRisk: number;
  avgScore: number;
}

export interface FrameworkSummary {
  id: string;
  name: string;
  authority: string;
  description: string;
  compliant: number;
  atRisk: number;
  nonCompliant: number;
  compliancePct: number;
  nearestDeadline: number | null;
}

export interface MigrationItem {
  id: string;
  title: string;
  priority: string;
  currentState: string;
  targetState: string;
  deadlineYear: number;
  affectedCount: number;
  severity: string;
  frameworks: string[];
  recommendation: string;
  findingRefs: string[];
}

export interface ComplianceReport {
  overallCompliancePct: number;
  totalFindings: number;
  compliant: number;
  atRisk: number;
  nonCompliant: number;
  frameworks: FrameworkSummary[];
  migrationItems: MigrationItem[];
  generatedAt: string;
}

export type AlertSeverity = "info" | "warning" | "critical";

export interface AlertEvent {
  id: string;
  timestamp: string;
  kind: string;
  severity: AlertSeverity;
  title: string;
  message: string;
  metadata: Record<string, string>;
  delivered: number;
}

export interface AlertsResponse {
  alerts: AlertEvent[];
  total: number;
  enabled: boolean;
  channels: { id: string; type: string }[];
  rules: { postureDropThreshold: number; alertOnCritical: boolean; certExpiryDays: number };
}

export interface Measurement {
  name: string;
  value: string;
}

export type GraphNodeType = "identity" | "data" | "agent" | "provider" | "certificate" | "dependency" | "asset";

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  sublabel: string;
  pqcStatus: string;
  risk: number;
  blastRadius: number;
  observed: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: string;
  observed: boolean;
}

export interface AttackPath {
  id: string;
  title: string;
  severity: FindingSeverity;
  score: number;
  hndl: boolean;
  observed: boolean;
  requestCount: number;
  kind: "data-exposure" | "access-risk" | "external-asset";
  dataClass: string;
  agent: string;
  provider: string;
  tlsVersion: string | null;
  channelPqc: PqcStatus;
  nodeIds: string[];
  recommendation: string;
}

export interface GraphSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  hndl: number;
  observed: number;
}

export interface AttackPathsResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: AttackPath[];
  summary: GraphSummary;
}

export interface SimulateResponse extends AttackPathsResponse {
  before: GraphSummary;
  after: GraphSummary;
  baseRisk: number;
  simRisk: number;
  riskReduction: number;
  mitigatedPaths: AttackPath[];
}

export interface GraphSnapshotPoint {
  timestamp: string;
  total: number;
  critical: number;
  high: number;
  hndl: number;
  pathIds: string[];
}

export interface AttackPathTimeline {
  timeline: GraphSnapshotPoint[];
  total: number;
}

export interface AssetRow {
  id: string;
  kind: string;
  address: string;
  environment: string;
  tags: string[];
  pqcStatus: PqcStatus;
  tlsVersion: string | null;
  lastScanned: string | null;
  source: string;
}

export interface AssetsResponse {
  assets: AssetRow[];
  total: number;
  vulnerable: number;
  environments: Record<string, number>;
  connectors: { name: string; type: string; environment: string; endpoints: number }[];
}

export interface SloResult {
  name: string;
  metric: string;
  operator: string;
  threshold: number;
  actual: number;
  pass: boolean;
  action: string;
}

export interface SlosResponse {
  slos: SloResult[];
  allPass: boolean;
  gateBreach: boolean;
}

export interface SloSnapshot {
  timestamp: string;
  total: number;
  passing: number;
  failing: number;
  gateBreach: boolean;
}

export interface SloHistoryResponse {
  history: SloSnapshot[];
  total: number;
}

export interface Attestation {
  attestationType: string;
  algorithm: string;
  signerFingerprint: string;
  bomDigest: string;
  nonce: string;
  measurements: Measurement[];
  signature: string;
  publicKey: string;
  signedAt: string;
  note: string;
}

export interface CryptoComponent {
  bomRef: string;
  type: string;
  name: string;
  version?: string;
  cryptoProperties?: Record<string, unknown>;
  evidence: {
    scannerId: string;
    scanTimestamp: string;
    source: string;
    confidence: number;
  };
  "x-quantawatch-posture-score": number;
  "x-quantawatch-pqc-status": PqcStatus;
}

export interface CryptoService {
  bomRef: string;
  name: string;
  endpoints: string[];
  authenticated: boolean;
  tlsVersion?: string;
  cipherSuite?: string;
  pqcStatus: PqcStatus;
  postureScore: number;
}

export interface CryptoBom {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { vendor: string; name: string; version: string }[];
  };
  components: CryptoComponent[];
  services: CryptoService[];
  "x-quantawatch-posture": PostureSummary;
}

// ---- Scanner types ----

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface ScanRecord {
  id: string;
  scannerId: string;
  targetId: string;
  targetAddress: string;
  status: "completed" | "partial_failure" | "failed";
  findingCount: number;
  startedAt: string;
  completedAt: string;
  contentHash: string;
}

export interface FindingRecord {
  id: string;
  scanId: string;
  category: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  assetType: string;
  algorithm?: string;
  pqcStatus: PqcStatus;
  location: string;
  remediation?: string;
  createdAt: string;
}

export interface ScanResult {
  scannerId: string;
  targetId: string;
  startedAt: string;
  completedAt: string;
  findings: FindingRecord[];
  status: string;
  error?: string;
}

// ---- Integration types ----

export interface IntegrationInfo {
  id: string;
  integrationType: string;
  displayName: string;
  capabilities: string[];
  status: {
    connected: boolean;
    user?: string;
    scopes: string[];
    error?: string;
  };
}

export interface ConnectionStatus {
  connected: boolean;
  user?: string;
  scopes: string[];
  error?: string;
}

export interface DiscoveredTarget {
  id: string;
  targetType: string;
  address: string;
  metadata?: Record<string, string>;
}

export interface IntegrationScanResult {
  reposScanned: number;
  filesScanned: number;
  findings: number;
  results: ScanResult[];
}

export type TicketStatus = "open" | "in_progress" | "resolved" | "closed" | "unknown";

export interface RemediationTicket {
  id: string;
  integrationId: string;
  externalId: string;
  externalUrl: string;
  status: TicketStatus;
  findingId: string;
  createdAt: string;
  updatedAt: string;
}

// ---- Governance: SOC2 controls report ----

export type Soc2Status = "enforced" | "partial" | "configurable" | "manual";

export interface Soc2Control {
  criteria: string;
  title: string;
  status: Soc2Status;
  evidence: string;
  verify_at: string;
}

export interface Soc2Report {
  framework: string;
  note: string;
  summary: {
    total: number;
    enforced: number;
    partial: number;
    configurable: number;
    manual: number;
  };
  controls: Soc2Control[];
}

// ---- Governance: RBAC role -> permission matrix ----

export interface RbacRole {
  name: string;
  builtin: boolean;
  permissions: string[];
}

export interface RbacReport {
  resources: string[];
  actions: string[];
  roles: RbacRole[];
}

// ---- Multi-framework compliance ----

export type FrameworkStatus = "enforced" | "partial" | "configurable" | "manual";

export interface FrameworkControl {
  id: string;
  title: string;
  required: boolean;
  status: FrameworkStatus;
  evidence: string;
  verify_at: string;
}

export interface FrameworkSummary {
  id: string;
  name: string;
  description: string;
  verdict: "PASS" | "GAPS";
  summary: { total: number; enforced: number; partial: number; configurable: number; manual: number; gaps: number };
  gapControls: string[];
}

export interface FrameworkDetail {
  id: string;
  name: string;
  description: string;
  verdict: "PASS" | "GAPS";
  summary: { total: number; enforced: number; partial: number; configurable: number; manual: number; gaps: number };
  controls: FrameworkControl[];
}
