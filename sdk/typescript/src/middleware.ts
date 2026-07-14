/**
 * MCP server protection middleware.
 *
 * Phase 2 stub -- will eventually intercept MCP tool calls and route them
 * through the QuantaWatch gateway for auditing and threat detection.
 */

import type { QuantaWatchConfig } from "./types.js";

/**
 * Wrap an MCP server instance so that every tool call is inspected and
 * audited by the QuantaWatch gateway.
 *
 * @param server - The MCP server instance to protect.
 * @param config - QuantaWatch gateway configuration.
 * @returns The wrapped server (same shape as the input).
 *
 * @throws Always -- this is a Phase 2 feature and is not yet implemented.
 */
export function protectMcpServer(
  server: unknown,
  _config: QuantaWatchConfig,
): unknown {
  // Acknowledge the server parameter to keep linters happy while the
  // implementation is still pending.
  void server;

  // Phase 2: Intercept MCP tool calls and route through QuantaWatch
  throw new Error("MCP server protection is a Phase 2 feature");
}
