/**
 * @quantawatch/sdk -- public API surface.
 *
 * Everything consumers need is re-exported from this barrel module so that a
 * single import path suffices:
 *
 * ```ts
 * import { QuantaWatchClient, protect, protectMcpServer } from '@quantawatch/sdk';
 * ```
 */

// Client
export { QuantaWatchClient } from "./client.js";

// Protect wrapper
export { protect } from "./protect.js";
export type { ProtectOptions } from "./protect.js";

// MCP middleware (Phase 2)
export { protectMcpServer } from "./middleware.js";

// Types
export type {
  AuditEntry,
  DetectedThreat,
  GatewayStats,
  QuantaWatchConfig,
  SessionInfo,
  ThreatAssessment,
} from "./types.js";
