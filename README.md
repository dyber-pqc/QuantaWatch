<p align="center">
  <img src="docs/assets/logo.svg" alt="QuantaWatch Logo" width="120" />
</p>

<h1 align="center">QuantaWatch</h1>

<p align="center">
  <strong>Post-quantum security layer for AI agents</strong>
</p>

<p align="center">
  <a href="https://github.com/dyber-inc/quantawatch/actions/workflows/ci.yml"><img src="https://github.com/dyber-inc/quantawatch/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://crates.io/crates/qw-gateway"><img src="https://img.shields.io/crates/v/qw-gateway.svg" alt="crates.io" /></a>
  <a href="https://pypi.org/project/quantawatch/"><img src="https://img.shields.io/pypi/v/quantawatch.svg" alt="PyPI" /></a>
  <a href="https://www.npmjs.com/package/@quantawatch/sdk"><img src="https://img.shields.io/npm/v/@quantawatch/sdk.svg" alt="npm" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License" /></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="docs/openapi.yaml">API Docs</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

QuantaWatch is a transparent security gateway that sits between your AI agents and LLM providers. It enforces policies, detects prompt injection attacks, logs tamper-proof audit trails signed with post-quantum cryptography, and gives you a real-time dashboard to monitor everything.

Deploy it as a sidecar, a shared proxy, or a standalone gateway. Your agents keep using their existing SDKs &mdash; QuantaWatch intercepts and secures every request and response without changing a single line of application code.

## Why QuantaWatch?

- **Quantum-resistant audit trails** &mdash; Every audit entry is signed with [ML-DSA-65](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204) and chained with SHA3-256 Merkle trees. Tamper-proof today, safe against quantum computers tomorrow.
- **Zero-code integration** &mdash; Point your AI SDK at the gateway URL. That's it. Works with Anthropic, OpenAI, Ollama, and any OpenAI-compatible provider.
- **Real-time threat detection** &mdash; Catches prompt injection, jailbreak attempts, data exfiltration, PII leakage, and dangerous commands before they reach the model or leave as output.
- **Policy enforcement** &mdash; YAML-based rules control which agents can use which models, tools, and providers. Default-deny with first-match evaluation.
- **Built for production** &mdash; Pure Rust core with async I/O, non-blocking audit writes, concurrent session management, and sub-millisecond overhead on the request path.

## Quick Start

### Option 1: Docker Compose (recommended)

```bash
git clone https://github.com/dyber-inc/quantawatch.git
cd quantawatch

# Configure your API keys
cp quantawatch.yaml.example quantawatch.yaml
export ANTHROPIC_API_KEY=sk-ant-...

# Start gateway + dashboard
docker compose up -d
```

- Gateway proxy: [http://localhost:9090](http://localhost:9090)
- Admin dashboard: [http://localhost:3000](http://localhost:3000)
- Admin API: [http://localhost:9091](http://localhost:9091)

### Option 2: From source

```bash
# Prerequisites: Rust 1.82+, Node 22+
git clone https://github.com/dyber-inc/quantawatch.git
cd quantawatch

# Build and run the gateway
cp quantawatch.yaml.example quantawatch.yaml
cargo run -p qw-gateway

# In another terminal: start the dashboard
cd dashboard && npm install && npm run dev
```

### Option 3: Protect your existing code

**Python:**

```bash
pip install quantawatch
```

```python
from anthropic import Anthropic
from quantawatch import protect

# One line to route through QuantaWatch
client = protect(Anthropic(), gateway_url="http://localhost:9090")

# Use the client exactly as before
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}]
)
```

**TypeScript:**

```bash
npm install @quantawatch/sdk
```

```typescript
import { protect } from '@quantawatch/sdk';

const safeFetch = protect(fetch, { gatewayUrl: 'http://localhost:9090' });

const response = await safeFetch('https://api.anthropic.com/v1/messages', {
  method: 'POST',
  headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY },
  body: JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1024,
    messages: [{ role: 'user', content: 'Hello!' }]
  })
});
```

**curl:**

```bash
# Just change the base URL
curl http://localhost:9090/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[{"role":"user","content":"Hello!"}]}'
```

## Architecture

```
                         +------------------+
                         |   AI Agents      |
                         |  (Python, TS,    |
                         |   curl, etc.)    |
                         +--------+---------+
                                  |
                                  v
                    +-------------+-------------+
                    |     QuantaWatch Gateway    |
                    |         :9090              |
                    |                            |
                    |  +---------------------+   |
                    |  | Identity Manager    |   |  PQC session keys
                    |  | (ML-DSA + ML-KEM)   |   |  per agent
                    |  +---------------------+   |
                    |  | Policy Engine       |   |  YAML rules,
                    |  | (first-match, deny) |   |  model/tool/provider ACLs
                    |  +---------------------+   |
                    |  | Prompt Monitor      |   |  Injection, exfiltration,
                    |  | (regex patterns)    |   |  PII, dangerous commands
                    |  +---------------------+   |
                    |  | Audit Logger        |   |  ML-DSA signed,
                    |  | (async, Merkle)     |   |  SHA3 hash chain
                    |  +---------------------+   |
                    |           |                 |
                    +-----------+-----------------+
                                |
              +-----------------+------------------+
              |                 |                   |
              v                 v                   v
       +------+------+  +------+------+  +---------+----+
       |  Anthropic   |  |   OpenAI    |  |   Ollama     |
       |  Claude API  |  | GPT/o-series|  |  Local LLMs  |
       +--------------+  +-------------+  +--------------+
```

### Components

| Crate | Purpose |
|-------|---------|
| [`qw-crypto`](crates/qw-crypto/) | ML-DSA-65 signing, ML-KEM-768 key encapsulation, SHA3-256, Merkle trees |
| [`qw-policy`](crates/qw-policy/) | YAML policy engine with glob matching and deny-overrides |
| [`qw-monitor`](crates/qw-monitor/) | Prompt injection, data exfiltration, and PII detection |
| [`qw-audit`](crates/qw-audit/) | Append-only audit log with PQC signatures and Merkle batching |
| [`qw-gateway`](crates/qw-gateway/) | Axum-based proxy with provider adapters and middleware pipeline |
| [`qw-cli`](crates/qw-cli/) | CLI tools: `qw verify`, `qw inspect`, `qw keygen` |

| Package | Purpose |
|---------|---------|
| [`dashboard/`](dashboard/) | React 19 + Vite + Tailwind CSS monitoring dashboard |
| [`sdk/python/`](sdk/python/) | Python SDK with `protect()` wrapper for any AI client |
| [`sdk/typescript/`](sdk/typescript/) | TypeScript SDK with zero runtime dependencies |

## Features

### Post-Quantum Cryptography

QuantaWatch uses NIST-standardized post-quantum algorithms implemented in pure Rust (no C dependencies):

| Algorithm | Standard | Purpose | Security Level |
|-----------|----------|---------|----------------|
| **ML-DSA-65** | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Digital signatures (audit signing) | Category 3 |
| **ML-KEM-768** | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | Key encapsulation (session keys) | Category 3 |
| **SHA3-256** | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) | Hashing (audit chain, Merkle tree) | 128-bit |

### Threat Detection

The prompt monitor scans both requests and responses:

| Category | Examples | Default Severity |
|----------|----------|-----------------|
| Prompt injection | "ignore previous instructions", role reassignment, delimiter injection | High - Critical |
| Jailbreak attempts | DAN-style, developer mode, bypass safety | High |
| System prompt extraction | "show me your system prompt", instruction boundary manipulation | Medium |
| Data exfiltration | Large base64 blocks, API keys in output, destructive commands | Medium - Critical |
| PII exposure | SSN, credit card numbers, email addresses, phone numbers | Low - Critical |

### Policy Engine

Define fine-grained access control in YAML:

```yaml
policies:
  - name: production-agents
    agents: ["prod-*"]
    effect: allow
    models: ["claude-sonnet-*", "gpt-4o"]
    providers: ["anthropic", "openai"]
    blocked_tools: ["shell_exec", "file_write"]

  - name: deny-all
    agents: ["*"]
    effect: deny
```

### Tamper-Proof Audit Trail

Every gateway event produces a signed audit entry:

```jsonl
{"seq":1,"ts":"2025-03-11T...","event":"request","session":"sess-abc","hash":"a1b2c3...","prev_hash":"000...","sig":"ML-DSA-65:..."}
{"seq":2,"ts":"2025-03-11T...","event":"response","session":"sess-abc","hash":"d4e5f6...","prev_hash":"a1b2c3...","sig":"ML-DSA-65:..."}
```

- Each entry is signed with ML-DSA-65
- Hash chain links entries sequentially
- Merkle tree batches provide efficient verification
- Async writes via tokio channels (non-blocking on request path)

Verify the chain:

```bash
cargo run --bin qw -- verify ./audit/audit.jsonl --public-key ./keys/gateway_public.key
```

### Dashboard

<p align="center">
  <img src="docs/assets/dashboard-overview.png" alt="Dashboard Overview" width="800" />
</p>

Real-time monitoring with four views:

- **Overview** &mdash; Stats cards, request rate chart, recent threats
- **Sessions** &mdash; Active and historical agent sessions with PQC fingerprints
- **Audit Log** &mdash; Browse and verify the tamper-proof audit chain
- **Threats** &mdash; Security events with severity, action taken, and session context

## Configuration

QuantaWatch is configured via `quantawatch.yaml`:

```yaml
listen: "0.0.0.0:9090"
admin_listen: "0.0.0.0:9091"

providers:
  anthropic:
    upstream: "https://api.anthropic.com"
    protocol: anthropic
    api_key_env: ANTHROPIC_API_KEY
  openai:
    upstream: "https://api.openai.com"
    protocol: openai
    api_key_env: OPENAI_API_KEY
  ollama:
    upstream: "http://localhost:11434"
    protocol: ollama

identity:
  session_ttl: 3600
  key_dir: "./keys"

audit:
  log_dir: "./audit"
  merkle_batch_size: 100
  sign_entries: true

monitor:
  injection_detection: true
  exfiltration_detection: true
  pii_detection: true

policy_file: "./policy.yaml"
```

See [`quantawatch.yaml.example`](quantawatch.yaml.example) for a complete reference.

## CLI

```
qw - QuantaWatch CLI

USAGE:
    qw <COMMAND>

COMMANDS:
    verify    Verify audit chain integrity
    inspect   Inspect audit log entries with filtering
    keygen    Generate ML-DSA-65 key pair
    version   Show version and PQC algorithm info

EXAMPLES:
    qw verify ./audit/audit.jsonl --public-key ./keys/gateway_public.key
    qw inspect ./audit/audit.jsonl -n 10 --session sess-abc
    qw keygen -o ./keys
    qw version
```

## Deployment

### Docker

```bash
docker compose up -d
```

Services:
- **gateway** &mdash; Rust binary on ports 9090 (proxy) and 9091 (admin)
- **dashboard** &mdash; Nginx serving React SPA on port 3000, proxying API to gateway

### Kubernetes (Helm)

```bash
helm install quantawatch ./deploy/helm/quantawatch \
  --set-string secretEnv.ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY
```

### Sidecar Mode

Deploy alongside your agent container:

```yaml
# In your pod spec
containers:
  - name: my-agent
    image: my-agent:latest
    env:
      - name: ANTHROPIC_BASE_URL
        value: "http://localhost:9090"
  - name: quantawatch
    image: ghcr.io/dyber-inc/quantawatch:latest
    ports:
      - containerPort: 9090
      - containerPort: 9091
```

## Supported Providers

| Provider | Protocol | Route | Status |
|----------|----------|-------|--------|
| Anthropic | `anthropic` | `/v1/messages` | Stable |
| OpenAI | `openai` | `/v1/chat/completions` | Stable |
| Ollama | `ollama` | `/api/chat`, `/api/generate` | Stable |
| Any OpenAI-compatible | `openai-compat` | Custom | Stable |
| AWS Bedrock | `bedrock` | `/bedrock/*` | Planned |
| DeepSeek | `openai-compat` | `/deepseek/*` | Planned |
| vLLM | `openai-compat` | `/vllm/*` | Planned |

## Admin API

The admin API runs on port 9091 and provides:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sessions` | GET | List all sessions |
| `/api/sessions/:id` | GET | Get session details |
| `/api/audit` | GET | List audit entries |
| `/api/audit/verify` | POST | Verify audit chain integrity |
| `/api/stats` | GET | Gateway statistics |
| `/api/config` | GET | Current configuration |
| `/health` | GET | Health check |

Full OpenAPI spec: [`docs/openapi.yaml`](docs/openapi.yaml)

## Performance

QuantaWatch is designed for minimal overhead:

| Operation | Time | Notes |
|-----------|------|-------|
| ML-DSA-65 key generation | ~2ms | Once per session |
| ML-DSA-65 sign | ~1ms | Per audit entry (async, non-blocking) |
| ML-DSA-65 verify | ~0.5ms | On-demand verification |
| ML-KEM-768 encapsulate | ~0.2ms | Once per session |
| SHA3-256 hash | ~1us/KB | Per entry |
| Policy evaluation | ~5us | Per request |
| Prompt scanning | ~50us | Per request (regex-based) |

Total added latency per proxied request: **< 1ms** (excluding audit signing, which is async).

Run benchmarks yourself:

```bash
cargo bench -p qw-crypto
```

## Project Structure

```
quantawatch/
+-- Cargo.toml                 # Workspace root
+-- crates/
|   +-- qw-crypto/             # PQC primitives (ML-DSA, ML-KEM, SHA3, Merkle)
|   +-- qw-policy/             # YAML policy engine
|   +-- qw-monitor/            # Threat detection (injection, exfil, PII)
|   +-- qw-audit/              # Signed audit logger with hash chain
|   +-- qw-gateway/            # Axum gateway server + provider adapters
|   +-- qw-cli/                # CLI tools
+-- dashboard/                 # React + Vite + Tailwind dashboard
+-- sdk/
|   +-- python/                # Python SDK (quantawatch on PyPI)
|   +-- typescript/            # TypeScript SDK (@quantawatch/sdk on npm)
+-- examples/                  # Usage examples
+-- deploy/                    # Helm chart + Terraform module
+-- sidecar/                   # Dashboard nginx config
+-- docs/                      # OpenAPI spec, architecture docs
+-- tests/                     # Integration tests
```

## Development

```bash
# Run all tests
cargo test --workspace

# Run with logging
RUST_LOG=info cargo run -p qw-gateway

# Lint
cargo fmt --check
cargo clippy --workspace -- -D warnings

# Dashboard dev
cd dashboard && npm run dev

# Python SDK tests
cd sdk/python && pip install -e ".[dev]" && pytest

# TypeScript SDK tests
cd sdk/typescript && npm install && npm test
```

## Roadmap

- [x] ML-DSA-65 + ML-KEM-768 post-quantum crypto
- [x] Gateway proxy with Anthropic, OpenAI, Ollama adapters
- [x] YAML policy engine with deny-overrides
- [x] Prompt injection + PII detection
- [x] PQC-signed audit chain with Merkle batching
- [x] React monitoring dashboard
- [x] Python and TypeScript SDKs
- [x] CLI tools (verify, inspect, keygen)
- [x] Docker + Helm deployment
- [ ] Cedar policy language support
- [ ] LangChain / CrewAI / Strands middleware
- [ ] MCP server protection wrapper
- [ ] Behavioral baselining with ONNX models
- [ ] AWS CloudTrail export
- [ ] WebSocket real-time dashboard updates
- [ ] AWS Bedrock / DeepSeek / vLLM adapters

## License

Licensed under the [Apache License 2.0](LICENSE).

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the PR process.

## Security

For vulnerability reports, please see [SECURITY.md](SECURITY.md). Do **not** open public issues for security vulnerabilities.

---

<p align="center">
  Built by <a href="https://dyber.io">Dyber, Inc.</a> &bull; Securing AI agents with post-quantum cryptography
</p>
