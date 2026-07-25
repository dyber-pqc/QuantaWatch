<p align="center">
  <img src="docs/assets/logo.svg" alt="QuantaWatch Logo" width="120" />
</p>

<h1 align="center">QuantaWatch</h1>

<p align="center">
  <strong>Post-quantum Cryptographic Posture Management &mdash; with an in-path AI gateway</strong>
</p>

<p align="center">
  <a href="https://github.com/dyber-pqc/QuantaWatch/actions/workflows/ci.yml"><img src="https://github.com/dyber-pqc/QuantaWatch/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License" /></a>
</p>

<p align="center">
  <a href="#what-it-does">What it does</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#honest-status">Honest status</a> &bull;
  <a href="docs/openapi.yaml">API</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

QuantaWatch discovers the cryptography your infrastructure and AI agents actually
use, scores its exposure to a future quantum computer, and produces concrete,
cryptographically-signed evidence and migration plans. It has two halves that
share one PQC core:

- **Cryptographic Posture Management (CPM)** &mdash; scan TLS endpoints,
  certificates, and dependency manifests; build a CycloneDX **CBOM**; score
  post-quantum readiness against **CNSA 2.0 / NIST** timelines; and generate
  concrete migration plans (which can be opened as pull requests).
- **In-path AI gateway** &mdash; sit between your agents and LLM providers to
  enforce policy, detect prompt injection / exfiltration / PII in real time, and
  write a post-quantum-signed, hash-chained **audit log** that anyone can verify
  independently.

Everything is signed with NIST-standardized post-quantum algorithms, and the
verifiers (`qw verify`, `qw verify-attestation`, `qw verify-evidence`) work
**without trusting the gateway** &mdash; they check the math.

## What it does

### Discover
- **TLS scanner** &mdash; connects to endpoints, extracts protocol version,
  cipher suite, and certificate signature algorithms, and classifies each as
  PQC-ready / hybrid / classical / weak. Algorithm OIDs are resolved to
  human-readable names (`1.2.840.10045.4.3.2` &rarr; `ECDSA-SHA256`).
- **Dependency scanner** &mdash; parses `Cargo.toml`, `package.json`,
  `requirements.txt`, `go.mod`, `pom.xml`, `Gemfile`, and `composer.json` and
  flags crypto libraries by PQC status.
- **Certificate & code scanners** &mdash; X.509 algorithm/key-size/expiry
  checks, and regex-based detection of hardcoded keys and weak primitives.
- **Cloud connectors** &mdash; AWS KMS/ACM (SigV4), Azure Key Vault, GCP Cloud
  KMS discovery from configured credentials.

### Prioritize
- **Posture engine** &mdash; a 0&ndash;100 score weighted across TLS, certs,
  and dependencies.
- **Compliance** &mdash; maps findings to CNSA 2.0 / NIST IR 8547 / FIPS
  203&ndash;204 with deadline-aware prioritization.
- **Quantum attack-path graph** &mdash; surfaces harvest-now-decrypt-later
  (HNDL) toxic combinations, not just isolated findings.

### Remediate
- **Migration planner** &mdash; turns a finding into a concrete plan: target
  algorithm (classical signature &rarr; ML-DSA-65, key exchange &rarr; hybrid
  X25519 + ML-KEM-768, weak cipher &rarr; AES-256-GCM, exposed key &rarr;
  rotate to a KMS/HSM), a P0/P1/P2 priority, ordered steps, and a proposed
  patch.
- **Closed-loop** &mdash; file the plan as a ticket, or have the GitHub
  integration open a pull request with the migration playbook.

### Govern
- **Signed CBOM + attestation** &mdash; export a CycloneDX CBOM with an ML-DSA-65
  attestation quote binding the inventory to a signing key.
- **Signed evidence packs** and a **board report** for auditors.
- **SLOs as code** &mdash; `GET /api/slos?gate=1` returns HTTP 422 when a
  policy objective is breached, so a CI job fails on posture regressions.
- **Auth, RBAC, multi-tenancy, OIDC/SSO**, per-tenant isolation, alerting,
  Prometheus `/metrics`, SIEM export (JSONL/CEF), and an **air-gapped mode**.

### In-path enforcement
- Transparent proxy for **Anthropic, OpenAI, Ollama, Azure OpenAI, Cohere**, and
  any OpenAI-compatible provider (Mistral / Groq / DeepSeek / Together via
  `openai-compat`).
- YAML **policy engine** (default-deny, per-agent model/tool/provider ACLs).
- **Threat detection** on requests and responses: regex patterns plus
  model-free heuristics (invisible-character and homoglyph obfuscation, encoded
  payloads, and paraphrased instruction-overrides).
- **Data-path resilience** &mdash; per-request timeouts, retry-on-transport-error,
  and a per-provider circuit breaker.
- **Tamper-evident audit log** &mdash; every event is ML-DSA-65 signed and linked
  in a SHA3-256 hash chain with Merkle batching, so any modification is
  detectable by an independent verifier.

## Quick Start

Install a published release ([all releases](https://github.com/dyber-pqc/QuantaWatch/releases)):

```bash
# Python SDK — on PyPI
pip install quantawatch

# Container images — gateway + admin API, and the dashboard
docker pull ghcr.io/dyber-pqc/quantawatch:latest
docker pull ghcr.io/dyber-pqc/quantawatch-dashboard:latest

# Desktop app — download the Windows MSI (or Inno setup.exe) from a release
```

Or run the whole stack locally:

### Docker Compose

```bash
git clone https://github.com/dyber-pqc/QuantaWatch.git
cd QuantaWatch

cp quantawatch.yaml.example quantawatch.yaml   # then edit
export ANTHROPIC_API_KEY=sk-ant-...

docker compose up -d
```

- Gateway proxy: `http://localhost:9090`
- Admin API: `http://localhost:9091`
- Dashboard: `http://localhost:3000`

### From source

```bash
# Prerequisites: Rust 1.82+, Node 22+
git clone https://github.com/dyber-pqc/QuantaWatch.git
cd QuantaWatch

cp quantawatch.yaml.example quantawatch.yaml
cargo run -p qw-gateway -- quantawatch.yaml

# Dashboard (separate terminal)
cd dashboard && npm install && npm run dev
```

### Try it without deploying anything

Point the agentless onboarding scan at a few hostnames for an immediate
post-quantum exposure report &mdash; no gateway in the data path, no agents:

```bash
curl -s -X POST http://localhost:9091/api/onboarding/scan \
  -H 'content-type: application/json' \
  -d '{"domains":["example.com","api.example.com"]}'
```

## Architecture

```
   AI agents ──▶  QuantaWatch gateway (:9090)  ──▶  LLM providers
                    │  identity · policy · monitor · resilience
                    │  tamper-evident audit (ML-DSA-65 + SHA3 chain)
                    ▼
                  Admin API + dashboard (:9091 / :3000)
                    │  scanners · CBOM · posture · compliance
                    │  attack-path graph · remediation · attestation
                    ▼
                  SQLite store (per-tenant)  +  signed evidence / SIEM export
```

### Crates

| Crate | Purpose |
|-------|---------|
| [`qw-crypto`](crates/qw-crypto/) | ML-DSA-65 signing (FIPS 204), ML-KEM-768 (FIPS 203), SHA3-256, Merkle trees, Argon2id |
| [`qw-policy`](crates/qw-policy/) | YAML policy engine, per-agent ACLs, default-deny |
| [`qw-monitor`](crates/qw-monitor/) | Threat detection: regex + model-free heuristics |
| [`qw-audit`](crates/qw-audit/) | Append-only, PQC-signed, hash-chained audit log with Merkle batching |
| [`qw-scanner`](crates/qw-scanner/) | TLS / dependency / certificate / code scanners, OID resolution |
| [`qw-cbom`](crates/qw-cbom/) | CycloneDX CBOM, posture scoring, compliance, migration planner |
| [`qw-integrations`](crates/qw-integrations/) | GitHub / GitLab / Jira / Linear connectors |
| [`qw-store`](crates/qw-store/) | SQLite persistence, tenant-scoped |
| [`qw-graph`](crates/qw-graph/) | Quantum attack-path engine: crypto security graph + HNDL kill-chains |
| [`qw-pki`](crates/qw-pki/) | Local hybrid CA: Ed25519 X.509 leaf + ML-DSA-65 binding |
| [`qw-gateway`](crates/qw-gateway/) | Axum proxy + admin API, middleware, attestation, resilience, metrics |
| [`qw-cli`](crates/qw-cli/) | `verify`, `inspect`, `keygen`, `scan`, `posture`, `cbom`, `verify-evidence`, `verify-attestation` |
| [`qw-desktop`](crates/qw-desktop/) | Native (egui) offline desktop app — see [docs/desktop.md](docs/desktop.md) |

| Package | Purpose |
|---------|---------|
| [`dashboard/`](dashboard/) | React 19 + Vite + Tailwind monitoring UI |
| [`sdk/python/`](sdk/python/) | Python SDK with a `protect()` wrapper |
| [`sdk/typescript/`](sdk/typescript/) | Zero-dependency TypeScript SDK |

### Desktop app

A native, browser-free, offline-first build of the dashboard for air-gapped and
high-assurance use. Download the Windows MSI (or Inno `setup.exe`) from a
[release](https://github.com/dyber-pqc/QuantaWatch/releases), or build it:

```bash
cargo run -p qw-desktop -- ./data
```

Full guide, page tour, and the web↔desktop parity matrix:
**[docs/desktop.md](docs/desktop.md)**.

## Post-Quantum Cryptography

The post-quantum primitives are pure-Rust [RustCrypto](https://github.com/RustCrypto)
implementations (no C dependency for the PQC itself; the wider system does use
`ring` for classical TLS and bundled SQLite):

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| **ML-DSA-65** | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Signatures (audit log, evidence, attestation) |
| **ML-KEM-768** | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | Key encapsulation (session keys) |
| **SHA3-256** | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) | Hashing (audit chain, Merkle tree, digests) |

We publish QuantaWatch's own cryptographic inventory &mdash; generated by
QuantaWatch scanning itself &mdash; in [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md)
and as a CycloneDX CBOM at [`docs/quantawatch.cbom.json`](docs/quantawatch.cbom.json).

## Verify it yourself

The verifiers don't trust the gateway &mdash; they recompute and check signatures.

```bash
# Audit chain: signatures + hash-chain + Merkle roots
cargo run -p qw-cli -- verify ./audit/audit.jsonl --public-key ./keys/gateway_public.key

# CBOM attestation: re-hash the CBOM and check the ML-DSA-65 quote (and, for a
# hardware-rooted provider, the attestation-key certificate chain)
cargo run -p qw-cli -- verify-attestation ./cbom.json

# Signed evidence pack
cargo run -p qw-cli -- verify-evidence ./evidence.json

# Any file signed with ML-DSA-65 (e.g. a release SHA256SUMS)
cargo run -p qw-cli -- verify-file SHA256SUMS --signature SHA256SUMS.sig --public-key docs/release-signing-key.pub
```

Releases are reproducible and Sigstore-signed; when a release signing seed is
configured, they additionally carry QuantaWatch's own post-quantum ML-DSA-65
signature. See [`docs/RELEASES.md`](docs/RELEASES.md) to verify a release or
reproduce a build.

## Configuration

QuantaWatch is configured with a single YAML file passed as an argument
(`cargo run -p qw-gateway -- quantawatch.yaml`). Minimal example:

```yaml
gateway:
  listen: "0.0.0.0:9090"
  admin_listen: "0.0.0.0:9091"

providers:
  anthropic:
    upstream: "https://api.anthropic.com"
    protocol: anthropic
    api_key_env: ANTHROPIC_API_KEY

# Per-agent policy (default-deny).
policy:
  default: deny
agents:
  support-bot:
    description: "Customer support agent"
    allowed_models: ["claude-sonnet-*", "gpt-4o"]
    blocked_tools: ["code_execution", "file_delete"]

identity:
  key_dir: "./keys"        # 32-byte FIPS 204 seed persisted here (stable across restarts)

audit:
  path: "./audit"
  merkle_batch_size: 64

scanner:
  store_path: "./data"
  auto_scan_on_start: true
```

See [`quantawatch.yaml.example`](quantawatch.yaml.example) for the complete,
annotated reference (resilience, attestation, air-gapped mode, auth, SLOs,
alerts, integrations, cloud connectors).

## Deployment

```bash
# Docker
docker compose up -d

# Kubernetes (Helm)
helm install quantawatch ./deploy/helm/quantawatch \
  --set-string secretEnv.ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY

# Terraform (wraps the Helm chart)
cd deploy/terraform && terraform init && terraform apply
```

The gateway persists its signing identity, SQLite store, and audit log to a
volume, and is currently single-replica (see [Honest status](#honest-status)).
For multiple replicas, share the identity seed via `identity.seed_env` (a
Kubernetes Secret / KMS value) so every replica signs as the same gateway. Full
deployment guide: [`deploy/README.md`](deploy/README.md).

## Performance

The design keeps the request path cheap: audit signing is asynchronous
(non-blocking on the response), policy and monitor checks are in-memory, and the
PQC primitives are fast. We don't publish specific latency figures here because
they depend heavily on hardware, payload size, and configuration &mdash; measure
your own:

```bash
cargo bench -p qw-crypto      # ML-DSA / ML-KEM / SHA3 / Merkle microbenchmarks
```

By default the proxy **buffers** each upstream response, scans it, then forwards
— so it can block a bad response before any byte reaches the client. Set
`monitor.stream_responses: true` to instead stream chunks through with
incremental scanning and **cut the stream off** on detection (lower latency, at
the cost that already-forwarded bytes can't be recalled — detect-and-cutoff, not
pre-send block).

## Honest status

QuantaWatch is pre-1.0. In the interest of being auditable, here is what is
**not** yet what it will be:

- **Attestation is software-rooted.** The default provider signs the CBOM quote
  with the gateway's own ML-DSA-65 key (`software-ml-dsa-65`). A
  `synthetic-tpm` provider demonstrates the full hardware-style AK &rarr;
  platform-CA certificate-chain flow, but a **real** TPM 2.0 / AWS Nitro / SEV-SNP
  quote is not yet wired in. The dashboard and CLI report the actual provider
  type honestly &mdash; there is no hardware root of trust today.
- **Detection is pattern + heuristic based by default.** It catches known
  phrasings, obfuscation, and paraphrased overrides. An **optional trained
  classifier** slots in behind the `ml` build feature
  (`monitor.ml.enabled` + a model on disk) — the plumbing and enforcement are
  shipped and tested, but **no model is bundled**; you supply the weights.
- **Single-replica.** State is SQLite on a `ReadWriteOnce` volume; horizontal
  scale-out (external DB) is on the roadmap.
- **Cloud connectors** cover common resource types and read credentials from the
  environment; they are not exhaustive.
- **Installers are not yet code-signed.** The Windows MSI / `setup.exe` are
  unsigned, so SmartScreen shows an "unknown publisher" warning until an
  Authenticode certificate is wired in. The Python SDK (PyPI) and container
  images are published; the Rust crates and npm SDK are not yet.

## Development

```bash
cargo test --workspace                       # full test suite
cargo fmt --check && cargo clippy --workspace -- -D warnings
cd dashboard && npm run build                # dashboard
cd sdk/python && pip install -e ".[dev]" && pytest
cd sdk/typescript && npm ci && npm test
```

## License

Licensed under the [Apache License 2.0](LICENSE).

## Contributing & Security

Contributions welcome &mdash; see [CONTRIBUTING.md](CONTRIBUTING.md). For
vulnerability reports see [SECURITY.md](SECURITY.md); please do **not** open
public issues for security vulnerabilities.

---

<p align="center">
  Built by <a href="https://dyber.org">Dyber, Inc.</a>
</p>
