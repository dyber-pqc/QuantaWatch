/**
 * `protect()` -- convenience wrapper that re-routes HTTP traffic through the
 * QuantaWatch gateway with a single function call.
 *
 * Supports two usage patterns:
 *
 * 1. **Wrap `fetch`** (or any fetch-compatible function):
 *    ```ts
 *    const safeFetch = protect(fetch, { gatewayUrl: 'http://localhost:9090' });
 *    const res = await safeFetch('https://api.anthropic.com/v1/messages', { method: 'POST', body });
 *    ```
 *
 * 2. **Wrap an AI client config object** (e.g. Anthropic / OpenAI SDK configs):
 *    ```ts
 *    const config = protect(
 *      { apiKey: '...', baseURL: 'https://api.anthropic.com' },
 *      { gatewayUrl: 'http://localhost:9090' },
 *    );
 *    // config.baseURL is now rewritten to point at the gateway
 *    ```
 */

// ---------------------------------------------------------------------------
// Public options type
// ---------------------------------------------------------------------------

/** Options accepted by the `protect()` helper. */
export interface ProtectOptions {
  /** Base URL of the QuantaWatch gateway. */
  gatewayUrl: string;
  /** Optional agent name header. */
  agentName?: string;
  /** Optional extra headers to inject into every proxied request. */
  headers?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Internal type helpers
// ---------------------------------------------------------------------------

/** Signature of a standard `fetch`-compatible function. */
type FetchFn = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** Shape of a typical AI SDK client config with a `baseURL` property. */
interface ClientConfig {
  baseURL?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Overloads
// ---------------------------------------------------------------------------

/**
 * Wrap a `fetch`-compatible function so that every request is proxied through
 * the QuantaWatch gateway.
 */
export function protect(fetchFn: FetchFn, options: ProtectOptions): FetchFn;

/**
 * Rewrite an AI SDK client config so that its `baseURL` points at the
 * QuantaWatch gateway, which will forward traffic to the original upstream.
 */
export function protect<T extends ClientConfig>(config: T, options: ProtectOptions): T;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function protect(target: FetchFn | ClientConfig, options: ProtectOptions): FetchFn | ClientConfig {
  const gatewayUrl = options.gatewayUrl.replace(/\/+$/, "");

  // ---- Wrap fetch ----------------------------------------------------------
  if (typeof target === "function") {
    const originalFetch = target as FetchFn;

    const wrappedFetch: FetchFn = async (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> => {
      // Resolve the original URL string.
      let url: string;
      if (typeof input === "string") {
        url = input;
      } else if (input instanceof URL) {
        url = input.toString();
      } else {
        // Request object
        url = input.url;
      }

      // Parse the URL so we can extract the path + query and re-root it
      // under the gateway.
      const parsed = new URL(url);
      const proxiedUrl = `${gatewayUrl}${parsed.pathname}${parsed.search}`;

      // Build merged headers.
      const extraHeaders: Record<string, string> = {
        ...options.headers,
        // Tell the gateway what the original upstream host was so it can
        // forward correctly.
        "X-QuantaWatch-Upstream": parsed.origin,
      };
      if (options.agentName) {
        extraHeaders["X-QuantaWatch-Agent"] = options.agentName;
      }

      // Merge into the init headers.
      const mergedInit: RequestInit = {
        ...init,
        headers: {
          ...(init?.headers as Record<string, string> | undefined),
          ...extraHeaders,
        },
      };

      return originalFetch(proxiedUrl, mergedInit);
    };

    return wrappedFetch;
  }

  // ---- Wrap client config --------------------------------------------------
  const config = { ...target } as ClientConfig;

  // Preserve the original baseURL so the gateway knows where to forward.
  const originalBaseURL = config.baseURL ?? "";

  // Point the SDK at the gateway instead.
  config.baseURL = gatewayUrl;

  // Inject default headers if the config shape supports it.
  const existingHeaders = (config["defaultHeaders"] ?? config["headers"] ?? {}) as Record<string, string>;
  const newHeaders: Record<string, string> = {
    ...existingHeaders,
    ...options.headers,
    "X-QuantaWatch-Upstream": originalBaseURL,
  };
  if (options.agentName) {
    newHeaders["X-QuantaWatch-Agent"] = options.agentName;
  }

  // Prefer `defaultHeaders` (Anthropic SDK) then fall back to `headers`.
  if ("defaultHeaders" in target) {
    config["defaultHeaders"] = newHeaders;
  } else {
    config["headers"] = newHeaders;
  }

  return config as typeof target;
}
