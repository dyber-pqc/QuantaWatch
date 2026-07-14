# QuantaWatch curl Examples

These examples assume the gateway is running on `localhost:9090` (proxy) and
`localhost:9091` (admin API).  Start the gateway first:

```bash
docker compose up -d
```

---

## Health check

```bash
curl http://localhost:9090/health
```

Expected response:

```json
{ "status": "ok", "version": "0.1.0", "uptime_seconds": 42 }
```

---

## Proxy an Anthropic request through the gateway

All traffic to the Anthropic API is routed through QuantaWatch for threat
inspection and audit logging.  The gateway forwards the request to
`https://api.anthropic.com` and returns the upstream response.

```bash
curl -X POST http://localhost:9090/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 256,
    "messages": [
      { "role": "user", "content": "Say hello in three languages." }
    ]
  }'
```

---

## Query sessions

```bash
curl http://localhost:9091/api/sessions
```

Example response:

```json
[
  {
    "session_id": "a1b2c3d4",
    "agent_name": "support-bot",
    "created_at": "2025-06-01T10:00:00Z",
    "expires_at": "2025-06-01T11:00:00Z",
    "request_count": 15,
    "total_tokens": 8200,
    "public_key_fingerprint": "ML-DSA-65:ab12cd34..."
  }
]
```

---

## Query audit log

Retrieve the 10 most recent audit entries:

```bash
curl "http://localhost:9091/api/audit?limit=10"
```

Example response:

```json
[
  {
    "sequence": 42,
    "timestamp": "2025-06-01T10:05:00Z",
    "event_type": "request_proxied",
    "session_id": "a1b2c3d4",
    "details": { "method": "POST", "path": "/v1/messages" },
    "hash": "3a7f...",
    "signature": "ML-DSA:..."
  }
]
```

---

## Verify audit chain integrity

Ask the gateway to cryptographically verify the entire audit chain:

```bash
curl -X POST http://localhost:9091/api/audit/verify
```

Expected response when the chain is intact:

```json
{
  "valid": true,
  "entries_checked": 42,
  "signatures_valid": 42,
  "chain_intact": true,
  "merkle_roots_valid": true,
  "errors": []
}
```

---

## Get gateway statistics

```bash
curl http://localhost:9091/api/stats
```

Example response:

```json
{
  "total_sessions": 5,
  "active_sessions": 2,
  "total_requests": 128,
  "total_audit_entries": 256,
  "active_threats": 0
}
```

---

## Get gateway configuration info

```bash
curl http://localhost:9091/api/config
```

Returns the active (non-secret) gateway configuration.
