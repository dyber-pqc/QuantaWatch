/**
 * QuantaWatch SDK type definitions.
 *
 * All interfaces used across the SDK are defined here so consumers can
 * import them directly from `@quantawatch/sdk`.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Configuration for the QuantaWatch SDK client. */
export interface QuantaWatchConfig {
  /** Base URL of the QuantaWatch gateway (e.g. "http://localhost:9090"). */
  gatewayUrl: string;
  /** Base URL of the QuantaWatch admin API (e.g. "http://localhost:9091"). */
  adminUrl: string;
  /** Optional agent name attached to requests routed through the gateway. */
  agentName?: string;
  /** Optional extra headers to include on every request to the gateway / admin API. */
  headers?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/** Represents an active or historical gateway session. */
export interface SessionInfo {
  sessionId: string;
  agentName: string;
  createdAt: string;
  expiresAt: string;
  requestCount: number;
  totalTokens: number;
  publicKeyFingerprint: string;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** A single entry in the tamper-evident audit log. */
export interface AuditEntry {
  sequence: number;
  timestamp: string;
  eventType: string;
  sessionId: string;
  details: Record<string, unknown>;
  signature: string;
}

// ---------------------------------------------------------------------------
// Threat Detection
// ---------------------------------------------------------------------------

/** Result of a threat assessment performed by the gateway. */
export interface ThreatAssessment {
  threats: DetectedThreat[];
  overallSeverity: string;
  blocked: boolean;
}

/** An individual threat detected by the gateway's analysis engine. */
export interface DetectedThreat {
  category: string;
  severity: string;
  patternName: string;
  confidence: number;
  description: string;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/** High-level gateway statistics. */
export interface GatewayStats {
  totalSessions: number;
  activeSessions: number;
  totalRequests: number;
  totalAuditEntries: number;
  activeThreats: number;
}
