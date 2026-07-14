# QuantaWatch Python SDK

[![PyPI](https://img.shields.io/pypi/v/quantawatch.svg)](https://pypi.org/project/quantawatch/)
[![Python](https://img.shields.io/pypi/pyversions/quantawatch.svg)](https://pypi.org/project/quantawatch/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

Python SDK for [QuantaWatch](https://github.com/dyber-inc/quantawatch) — the post-quantum security layer for AI agents.

Route your AI SDK traffic through the QuantaWatch gateway for threat detection, policy enforcement, and tamper-proof audit logging — all signed with post-quantum cryptography (ML-DSA-65).

## Installation

```bash
pip install quantawatch
```

**Requirements:** Python 3.10+

## Quick Start

### Option 1: Protect an existing AI client (recommended)

The `protect()` wrapper transparently routes your existing SDK's HTTP traffic through the gateway. No code changes needed beyond the wrap call.

```python
from anthropic import Anthropic
from quantawatch import protect

# One line — all API calls now flow through QuantaWatch
client = protect(Anthropic(), gateway_url="http://localhost:9090")

# Use the client exactly as before
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}],
)
```

Works with any httpx-based SDK, including OpenAI:

```python
from openai import OpenAI
from quantawatch import protect

client = protect(OpenAI(), gateway_url="http://localhost:9090")
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

### Option 2: Use the gateway client directly

The `QuantaWatchClient` gives you direct access to the gateway proxy and admin API.

```python
import asyncio
from quantawatch import QuantaWatchClient

async def main():
    async with QuantaWatchClient() as qw:
        # Proxy a raw request through the gateway
        response = await qw.proxy_request(
            "POST",
            "/v1/messages",
            headers={
                "x-api-key": "sk-ant-...",
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            body=b'{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[{"role":"user","content":"Hello!"}]}',
        )
        print(response.status_code, response.text)

        # Query the admin API
        sessions = await qw.get_sessions()
        stats = await qw.get_stats()
        audit = await qw.get_audit_entries(limit=10)

        # Verify audit chain integrity
        result = await qw.verify_audit_chain()
        print("Audit chain valid:", result.get("valid"))

asyncio.run(main())
```

## API Reference

### `protect(client, *, gateway_url="http://localhost:9090")`

Wraps an AI SDK client so its HTTP traffic flows through the QuantaWatch gateway.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `client` | `Any` | — | An AI SDK client (Anthropic, OpenAI, or any httpx-based client) |
| `gateway_url` | `str` | `http://localhost:9090` | URL of the QuantaWatch gateway |

Returns a proxy object that behaves identically to the original client.

### `QuantaWatchClient`

Async client for the QuantaWatch gateway and admin APIs.

```python
QuantaWatchClient(
    gateway_url="http://localhost:9090",
    admin_url="http://localhost:9091",
    timeout=30.0,
)
```

| Method | Description |
|--------|-------------|
| `proxy_request(method, path, headers, body)` | Proxy an HTTP request through the gateway |
| `get_sessions()` | List all gateway sessions |
| `get_audit_entries(limit=100)` | Fetch recent audit log entries |
| `get_stats()` | Fetch aggregate gateway statistics |
| `verify_audit_chain()` | Verify cryptographic audit chain integrity |
| `close()` | Close the underlying HTTP client |

### Types

All response types are [Pydantic](https://docs.pydantic.dev/) models:

- `SessionInfo` — Gateway session with agent name, token count, PQC key fingerprint
- `AuditEntry` — Signed audit log entry with sequence number and hash chain
- `GatewayStats` — Aggregate stats (sessions, requests, threats, audit entries)
- `ThreatAssessment` — Threat analysis result with severity and blocked status
- `DetectedThreat` — Individual threat with category, severity, confidence, and pattern name

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
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking (if mypy installed)
mypy quantawatch/
```

## License

[Apache License 2.0](../../LICENSE)

## Links

- [QuantaWatch repository](https://github.com/dyber-inc/quantawatch)
- [Documentation](https://docs.quantawatch.dev)
- [OpenAPI spec](https://github.com/dyber-inc/quantawatch/blob/main/docs/openapi.yaml)
- [Examples](https://github.com/dyber-inc/quantawatch/tree/main/examples)
