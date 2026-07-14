# QuantaWatch Examples

Runnable examples demonstrating how to integrate with the QuantaWatch security
gateway.

## Prerequisites

Start the gateway before running any example:

```bash
docker compose up -d
```

The gateway listens on two ports:

| Port | Purpose                  |
|------|--------------------------|
| 9090 | AI API proxy (gateway)   |
| 9091 | Admin / observability API|

---

## Python

| File | Description |
|------|-------------|
| [python/basic_protect.py](python/basic_protect.py) | Wrap an Anthropic client with `protect()` so all API calls are routed through the gateway for threat detection and audit logging. |
| [python/admin_client.py](python/admin_client.py) | Use `QuantaWatchClient` to query sessions, retrieve the audit log, verify the cryptographic audit chain, and fetch gateway statistics. |

Install the SDK first:

```bash
pip install -e sdk/python
```

---

## TypeScript

| File | Description |
|------|-------------|
| [typescript/basic_protect.ts](typescript/basic_protect.ts) | Wrap the global `fetch` with `protect()` to route Anthropic requests through the gateway. |
| [typescript/admin_client.ts](typescript/admin_client.ts) | Use `QuantaWatchClient` to query the admin API for sessions, audit entries, chain verification, and statistics. |

Install the SDK first:

```bash
cd sdk/typescript && npm install && npm run build
```

---

## curl

| File | Description |
|------|-------------|
| [curl/README.md](curl/README.md) | Copy-pasteable curl commands for every admin API endpoint: health check, proxied requests, sessions, audit log, chain verification, and stats. |
