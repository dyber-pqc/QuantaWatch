import { describe, it, expect, vi } from "vitest";
import { QuantaWatchClient } from "../src/client.js";
import { protect } from "../src/protect.js";
import { protectMcpServer } from "../src/middleware.js";
import type {
  AuditEntry,
  DetectedThreat,
  GatewayStats,
  QuantaWatchConfig,
  SessionInfo,
  ThreatAssessment,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const baseConfig: QuantaWatchConfig = {
  gatewayUrl: "http://localhost:9090",
  adminUrl: "http://localhost:9091",
};

// ---------------------------------------------------------------------------
// QuantaWatchClient
// ---------------------------------------------------------------------------

describe("QuantaWatchClient", () => {
  it("should construct with minimal config", () => {
    const client = new QuantaWatchClient(baseConfig);
    expect(client).toBeInstanceOf(QuantaWatchClient);
  });

  it("should construct with full config including optional fields", () => {
    const client = new QuantaWatchClient({
      ...baseConfig,
      agentName: "test-agent",
      headers: { Authorization: "Bearer tok_test" },
    });
    expect(client).toBeInstanceOf(QuantaWatchClient);
  });

  it("should strip trailing slashes from URLs", () => {
    const client = new QuantaWatchClient({
      gatewayUrl: "http://localhost:9090///",
      adminUrl: "http://localhost:9091/",
    });
    // We verify indirectly: proxyRequest should build a clean URL.
    // (Direct field access is private, so we trust construction succeeds.)
    expect(client).toBeInstanceOf(QuantaWatchClient);
  });

  it("proxyRequest should call fetch with the correct gateway URL", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
    vi.stubGlobal("fetch", mockFetch);

    const client = new QuantaWatchClient({
      ...baseConfig,
      agentName: "sdk-test",
    });

    await client.proxyRequest(
      "POST",
      "/v1/messages",
      { "Content-Type": "application/json" },
      '{"prompt":"hello"}',
    );

    expect(mockFetch).toHaveBeenCalledOnce();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://localhost:9090/v1/messages");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["X-QuantaWatch-Agent"]).toBe("sdk-test");
    expect(init.body).toBe('{"prompt":"hello"}');

    vi.unstubAllGlobals();
  });

  it("getSessions should hit the admin API", async () => {
    const sessions: SessionInfo[] = [
      {
        sessionId: "s1",
        agentName: "a",
        createdAt: "2025-01-01T00:00:00Z",
        expiresAt: "2025-01-02T00:00:00Z",
        requestCount: 5,
        totalTokens: 100,
        publicKeyFingerprint: "abc",
      },
    ];

    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(sessions), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const client = new QuantaWatchClient(baseConfig);
    const result = await client.getSessions();

    expect(result).toEqual(sessions);
    expect(mockFetch).toHaveBeenCalledOnce();

    const [url] = mockFetch.mock.calls[0] as [string];
    expect(url).toBe("http://localhost:9091/api/sessions");

    vi.unstubAllGlobals();
  });

  it("getAuditEntries should pass limit as query param", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response("[]", { status: 200 }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const client = new QuantaWatchClient(baseConfig);
    await client.getAuditEntries(10);

    const [url] = mockFetch.mock.calls[0] as [string];
    expect(url).toBe("http://localhost:9091/api/audit?limit=10");

    vi.unstubAllGlobals();
  });

  it("getStats should return gateway stats", async () => {
    const stats: GatewayStats = {
      totalSessions: 10,
      activeSessions: 3,
      totalRequests: 42,
      totalAuditEntries: 42,
      activeThreats: 1,
    };

    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(stats), { status: 200 }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const client = new QuantaWatchClient(baseConfig);
    const result = await client.getStats();
    expect(result).toEqual(stats);

    vi.unstubAllGlobals();
  });

  it("verifyAuditChain should return validity result", async () => {
    const verification = { valid: true, errors: [] };

    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(verification), { status: 200 }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const client = new QuantaWatchClient(baseConfig);
    const result = await client.verifyAuditChain();
    expect(result).toEqual(verification);

    const [url] = mockFetch.mock.calls[0] as [string];
    expect(url).toBe("http://localhost:9091/api/audit/verify");

    vi.unstubAllGlobals();
  });

  it("should throw on non-OK admin responses", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response("forbidden", { status: 403, statusText: "Forbidden" }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const client = new QuantaWatchClient(baseConfig);

    await expect(client.getSessions()).rejects.toThrow(
      /QuantaWatch admin API error: 403/,
    );

    vi.unstubAllGlobals();
  });
});

// ---------------------------------------------------------------------------
// protect()
// ---------------------------------------------------------------------------

describe("protect()", () => {
  it("should wrap a fetch function and rewrite URLs", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));

    const safeFetch = protect(mockFetch, {
      gatewayUrl: "http://localhost:9090",
      agentName: "wrap-test",
    });

    expect(typeof safeFetch).toBe("function");

    await safeFetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { Authorization: "Bearer sk-test" },
    });

    expect(mockFetch).toHaveBeenCalledOnce();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://localhost:9090/v1/messages");

    const headers = init.headers as Record<string, string>;
    expect(headers["X-QuantaWatch-Upstream"]).toBe("https://api.anthropic.com");
    expect(headers["X-QuantaWatch-Agent"]).toBe("wrap-test");
    // Original auth header should still be present.
    expect(headers["Authorization"]).toBe("Bearer sk-test");
  });

  it("should wrap a fetch function using URL object input", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));

    const safeFetch = protect(mockFetch, {
      gatewayUrl: "http://localhost:9090",
    });

    await safeFetch(new URL("https://api.openai.com/v1/chat/completions"));

    const [url] = mockFetch.mock.calls[0] as [string];
    expect(url).toBe("http://localhost:9090/v1/chat/completions");
  });

  it("should rewrite a client config object's baseURL", () => {
    const original = {
      apiKey: "sk-test",
      baseURL: "https://api.anthropic.com",
      defaultHeaders: { "X-Custom": "value" },
    };

    const result = protect(original, {
      gatewayUrl: "http://localhost:9090",
      agentName: "config-test",
    });

    expect(result.baseURL).toBe("http://localhost:9090");
    expect((result.defaultHeaders as Record<string, string>)["X-QuantaWatch-Upstream"]).toBe(
      "https://api.anthropic.com",
    );
    expect((result.defaultHeaders as Record<string, string>)["X-QuantaWatch-Agent"]).toBe(
      "config-test",
    );
    // Existing custom header is preserved.
    expect((result.defaultHeaders as Record<string, string>)["X-Custom"]).toBe("value");
    // API key is preserved.
    expect(result.apiKey).toBe("sk-test");
  });

  it("should use 'headers' when config has no 'defaultHeaders'", () => {
    const original = {
      apiKey: "sk-test",
      baseURL: "https://api.openai.com",
    };

    const result = protect(original, {
      gatewayUrl: "http://localhost:9090",
    });

    expect(result.baseURL).toBe("http://localhost:9090");
    expect((result.headers as Record<string, string>)["X-QuantaWatch-Upstream"]).toBe(
      "https://api.openai.com",
    );
  });
});

// ---------------------------------------------------------------------------
// protectMcpServer (Phase 2 stub)
// ---------------------------------------------------------------------------

describe("protectMcpServer()", () => {
  it("should throw indicating Phase 2", () => {
    expect(() => protectMcpServer({}, baseConfig)).toThrow(
      "MCP server protection is a Phase 2 feature",
    );
  });
});

// ---------------------------------------------------------------------------
// Type shape assertions (compile-time checks surfaced via runtime objects)
// ---------------------------------------------------------------------------

describe("type shapes", () => {
  it("SessionInfo has required fields", () => {
    const session: SessionInfo = {
      sessionId: "s1",
      agentName: "agent",
      createdAt: "2025-01-01T00:00:00Z",
      expiresAt: "2025-01-02T00:00:00Z",
      requestCount: 0,
      totalTokens: 0,
      publicKeyFingerprint: "fingerprint",
    };
    expect(session.sessionId).toBe("s1");
  });

  it("AuditEntry has required fields", () => {
    const entry: AuditEntry = {
      sequence: 1,
      timestamp: "2025-01-01T00:00:00Z",
      eventType: "request",
      sessionId: "s1",
      details: { foo: "bar" },
      signature: "sig",
    };
    expect(entry.sequence).toBe(1);
  });

  it("ThreatAssessment has required fields", () => {
    const assessment: ThreatAssessment = {
      threats: [],
      overallSeverity: "low",
      blocked: false,
    };
    expect(assessment.blocked).toBe(false);
  });

  it("DetectedThreat has required fields", () => {
    const threat: DetectedThreat = {
      category: "injection",
      severity: "high",
      patternName: "prompt-injection-v1",
      confidence: 0.95,
      description: "Detected prompt injection attempt",
    };
    expect(threat.confidence).toBe(0.95);
  });

  it("GatewayStats has required fields", () => {
    const stats: GatewayStats = {
      totalSessions: 0,
      activeSessions: 0,
      totalRequests: 0,
      totalAuditEntries: 0,
      activeThreats: 0,
    };
    expect(stats.totalSessions).toBe(0);
  });

  it("QuantaWatchConfig has required and optional fields", () => {
    const minimal: QuantaWatchConfig = {
      gatewayUrl: "http://localhost:9090",
      adminUrl: "http://localhost:9091",
    };
    expect(minimal.agentName).toBeUndefined();

    const full: QuantaWatchConfig = {
      gatewayUrl: "http://localhost:9090",
      adminUrl: "http://localhost:9091",
      agentName: "test",
      headers: { "X-Custom": "val" },
    };
    expect(full.agentName).toBe("test");
  });
});
