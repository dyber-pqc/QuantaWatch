# @quantawatch/sdk

[![npm](https://img.shields.io/npm/v/@quantawatch/sdk.svg)](https://www.npmjs.com/package/@quantawatch/sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

TypeScript SDK for [QuantaWatch](https://github.com/dyber-inc/quantawatch) — the post-quantum security layer for AI agents.

Route your AI traffic through the QuantaWatch gateway for threat detection, policy enforcement, and tamper-proof audit logging — all signed with post-quantum cryptography (ML-DSA-65).

**Zero runtime dependencies.** Works in Node.js 18+ and browsers.

## Installation

```bash
npm install @quantawatch/sdk
```

## Quick Start

### Option 1: Wrap `fetch` (recommended)

The `protect()` wrapper intercepts fetch calls and routes them through the gateway:

```typescript
import { protect } from '@quantawatch/sdk';

const safeFetch = protect(fetch, { gatewayUrl: 'http://localhost:9090' });

// Use safeFetch exactly like regular fetch — requests are proxied through QuantaWatch
const response = await safeFetch('https://api.anthropic.com/v1/messages', {
  method: 'POST',
  headers: {
    'x-api-key': process.env.ANTHROPIC_API_KEY!,
    'anthropic-version': '2023-06-01',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1024,
    messages: [{ role: 'user', content: 'Hello!' }],
  }),
});
```

### Option 2: Wrap an AI SDK client config

Rewrite a client config's `baseURL` to point at the gateway:

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { protect } from '@quantawatch/sdk';

const config = protect(
  { apiKey: process.env.ANTHROPIC_API_KEY },
  { gatewayUrl: 'http://localhost:9090' },
);

const client = new Anthropic(config);

// All requests are now routed through QuantaWatch
const response = await client.messages.create({
  model: 'claude-sonnet-4-20250514',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hello!' }],
});
```

### Option 3: Use the gateway client directly

The `QuantaWatchClient` provides direct access to the gateway proxy and admin API:

```typescript
import { QuantaWatchClient } from '@quantawatch/sdk';

const qw = new QuantaWatchClient({
  gatewayUrl: 'http://localhost:9090',
  adminUrl: 'http://localhost:9091',
});

// Proxy a raw request
const response = await qw.proxyRequest('POST', '/v1/messages', {
  'x-api-key': process.env.ANTHROPIC_API_KEY!,
  'anthropic-version': '2023-06-01',
  'Content-Type': 'application/json',
}, JSON.stringify({
  model: 'claude-sonnet-4-20250514',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hello!' }],
}));

// Query the admin API
const sessions = await qw.getSessions();
const stats = await qw.getStats();
const audit = await qw.getAuditEntries(10);

// Verify audit chain integrity
const result = await qw.verifyAuditChain();
console.log('Audit chain valid:', result.valid);
```

## API Reference

### `protect(fetchFn, options)`

Wraps a `fetch`-compatible function so every request is proxied through the gateway.

### `protect(config, options)`

Rewrites an AI SDK client config's `baseURL` to point at the gateway. Works with Anthropic SDK (`defaultHeaders`) and OpenAI SDK (`headers`).

#### `ProtectOptions`

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `gatewayUrl` | `string` | Yes | Base URL of the QuantaWatch gateway |
| `agentName` | `string` | No | Agent name sent via `X-QuantaWatch-Agent` header |
| `headers` | `Record<string, string>` | No | Extra headers injected into every proxied request |

### `QuantaWatchClient`

| Method | Returns | Description |
|--------|---------|-------------|
| `proxyRequest(method, path, headers, body?)` | `Promise<Response>` | Proxy an HTTP request through the gateway |
| `getSessions()` | `Promise<SessionInfo[]>` | List all gateway sessions |
| `getAuditEntries(limit?)` | `Promise<AuditEntry[]>` | Fetch recent audit log entries |
| `getStats()` | `Promise<GatewayStats>` | Fetch aggregate gateway statistics |
| `verifyAuditChain()` | `Promise<{ valid, errors }>` | Verify cryptographic audit chain integrity |

### Types

All types are exported from the main package:

```typescript
import type {
  QuantaWatchConfig,
  SessionInfo,
  AuditEntry,
  GatewayStats,
  ThreatAssessment,
  DetectedThreat,
  ProtectOptions,
} from '@quantawatch/sdk';
```

| Type | Description |
|------|-------------|
| `QuantaWatchConfig` | Client constructor config (gateway URL, admin URL, agent name, headers) |
| `SessionInfo` | Gateway session with agent name, token count, PQC key fingerprint |
| `AuditEntry` | Signed audit log entry with sequence number and hash chain |
| `GatewayStats` | Aggregate stats (sessions, requests, threats, audit entries) |
| `ThreatAssessment` | Threat analysis result with severity and blocked status |
| `DetectedThreat` | Individual threat with category, severity, confidence, and pattern name |
| `ProtectOptions` | Options for the `protect()` helper |

## Prerequisites

The SDK requires a running QuantaWatch gateway. Start one with Docker:

```bash
git clone https://github.com/dyber-inc/quantawatch.git
cd quantawatch
cp quantawatch.yaml.example quantawatch.yaml
export ANTHROPIC_API_KEY=sk-ant-...
docker compose up -d
```

Or build from source:

```bash
cargo run -p qw-gateway
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Watch mode
npm run test:watch
```

## License

[Apache License 2.0](../../LICENSE)

## Links

- [QuantaWatch repository](https://github.com/dyber-inc/quantawatch)
- [Documentation](https://docs.quantawatch.dev)
- [OpenAPI spec](https://github.com/dyber-inc/quantawatch/blob/main/docs/openapi.yaml)
- [Examples](https://github.com/dyber-inc/quantawatch/tree/main/examples)
