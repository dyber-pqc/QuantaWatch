/**
 * QuantaWatchClient -- primary SDK entry point for interacting with the
 * QuantaWatch gateway and admin APIs.
 *
 * Uses the native `fetch()` API (available in Node >= 18) so the package
 * ships with zero runtime dependencies.
 */

import type {
  AuditEntry,
  GatewayStats,
  QuantaWatchConfig,
  SessionInfo,
} from "./types.js";

export class QuantaWatchClient {
  private readonly gatewayUrl: string;
  private readonly adminUrl: string;
  private readonly agentName: string | undefined;
  private readonly headers: Record<string, string>;

  constructor(config: QuantaWatchConfig) {
    // Strip trailing slashes for consistent URL construction.
    this.gatewayUrl = config.gatewayUrl.replace(/\/+$/, "");
    this.adminUrl = config.adminUrl.replace(/\/+$/, "");
    this.agentName = config.agentName;
    this.headers = { ...config.headers };
  }

  // -----------------------------------------------------------------------
  // Gateway proxy
  // -----------------------------------------------------------------------

  /**
   * Proxy an arbitrary HTTP request through the QuantaWatch gateway.
   *
   * The gateway will inspect, audit, and optionally block the request before
   * forwarding it to the upstream AI provider.
   */
  async proxyRequest(
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<Response> {
    const url = `${this.gatewayUrl}${path}`;

    const mergedHeaders: Record<string, string> = {
      ...this.headers,
      ...headers,
    };

    if (this.agentName) {
      mergedHeaders["X-QuantaWatch-Agent"] = this.agentName;
    }

    return fetch(url, {
      method,
      headers: mergedHeaders,
      body: body ?? undefined,
    });
  }

  // -----------------------------------------------------------------------
  // Admin API helpers
  // -----------------------------------------------------------------------

  /** Retrieve all known sessions from the admin API. */
  async getSessions(): Promise<SessionInfo[]> {
    const res = await this.adminFetch("/api/sessions");
    return (await res.json()) as SessionInfo[];
  }

  /**
   * Retrieve audit log entries from the admin API.
   *
   * @param limit - Optional maximum number of entries to return.
   */
  async getAuditEntries(limit?: number): Promise<AuditEntry[]> {
    const query = limit !== undefined ? `?limit=${limit}` : "";
    const res = await this.adminFetch(`/api/audit${query}`);
    return (await res.json()) as AuditEntry[];
  }

  /** Retrieve high-level gateway statistics. */
  async getStats(): Promise<GatewayStats> {
    const res = await this.adminFetch("/api/stats");
    return (await res.json()) as GatewayStats;
  }

  /**
   * Ask the admin API to verify the integrity of the tamper-evident audit
   * chain.
   *
   * @returns An object indicating whether the chain is valid plus any
   *          error messages describing where integrity checks failed.
   */
  async verifyAuditChain(): Promise<{ valid: boolean; errors: string[] }> {
    const res = await this.adminFetch("/api/audit/verify");
    return (await res.json()) as { valid: boolean; errors: string[] };
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private async adminFetch(path: string, init?: RequestInit): Promise<Response> {
    const url = `${this.adminUrl}${path}`;

    const mergedHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      ...this.headers,
    };

    const res = await fetch(url, {
      ...init,
      headers: {
        ...mergedHeaders,
        ...(init?.headers as Record<string, string> | undefined),
      },
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(
        `QuantaWatch admin API error: ${res.status} ${res.statusText}${body ? ` - ${body}` : ""}`,
      );
    }

    return res;
  }
}
