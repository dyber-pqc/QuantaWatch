# Changelog

All notable changes to QuantaWatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

QuantaWatch is pre-1.0 and has not yet cut a tagged release. This section
describes the current state of `main`.

### Cryptographic Posture Management

- **Scanners** — TLS endpoints, X.509 certificates, dependency manifests
  (`Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`, `pom.xml`,
  `Gemfile`, `composer.json`), and code; algorithm OIDs resolved to
  human-readable names.
- **CBOM** — CycloneDX cryptographic bill of materials with posture scoring.
- **Compliance** — mapping to CNSA 2.0 / NIST IR 8547 / FIPS 203–204 with
  deadline-aware prioritization.
- **Quantum attack-path graph** — harvest-now-decrypt-later toxic combinations.
- **Migration planner** — concrete per-finding plans (target algorithm,
  P0/P1/P2 priority, steps, proposed patch) that can be filed as tickets or
  opened as GitHub pull requests.
- **Agentless onboarding scan** — `POST /api/onboarding/scan` for an immediate
  post-quantum exposure report with no gateway in the data path.

### In-path AI gateway

- Transparent proxy for Anthropic, OpenAI, Ollama, Azure OpenAI, Cohere, and
  any OpenAI-compatible provider.
- YAML policy engine (default-deny, per-agent model/tool/provider ACLs).
- Threat detection: regex patterns plus model-free heuristics (obfuscation,
  encoded payloads, paraphrased instruction-overrides).
- Data-path resilience: per-request timeouts, retry-on-transport-error, and a
  per-provider circuit breaker.
- Tamper-evident audit log: ML-DSA-65 signed, SHA3-256 hash-chained, with
  Merkle batching; independently verifiable via `qw verify`.

### Trust & governance

- **Attestation** — pluggable provider: `software` (self-signed) and
  `synthetic-tpm` (demonstrates a hardware-style AK → platform-CA certificate
  chain). No real hardware root of trust yet.
- **Signed evidence packs** and a board report; independent CLI verifiers
  (`qw verify-evidence`, `qw verify-attestation`).
- **SLOs as code** with a CI gate; alerting; Prometheus `/metrics`; SIEM export
  (JSONL/CEF); air-gapped mode.
- **Auth & multi-tenancy** — Argon2id passwords, session tokens, API keys,
  RBAC, OIDC/SSO, per-tenant isolation.
- **Stable signing identity** — persisted as a 32-byte FIPS 204 seed
  (`gateway_seed.key`) so the audit chain and attestation survive restarts;
  shareable across replicas via `identity.seed_env`.

### Platform

- Rust workspace (10 crates), React 19 dashboard, Python and TypeScript SDKs.
- SQLite persistence (tenant-scoped); currently single-replica.
- Docker, Helm chart, and Terraform deployment artifacts.
- CLI: `verify`, `inspect`, `keygen`, `scan`, `posture`, `cbom`,
  `verify-evidence`, `verify-attestation`, `version`.

## [0.1.5] - 2026-07-26

### Fixed

- **Host-agent enrollment works off a clean install (no repo checkout).** The
  gateway now bundles and serves the agent scripts at `GET
  /api/endpoints/agent.ps1` and `/api/endpoints/agent.sh` (public routes — the
  enrollment token is the secret, not the script). The install command shown in
  the dashboard is now a one-line download-and-run instead of referencing a
  local `qw-agent.ps1` that only existed in the source tree.
- **Audit-chain `verify` reports real integrity evidence.** The `verify`
  console command and the Audit page previously showed an unpopulated entry
  count (read the wrong field) and no justification. They now report entries
  checked, ML-DSA-65 signatures validated, SHA3-256 hash-chain linkage, Merkle
  batch roots, and signed global checkpoints — the evidence the backend already
  computed but discarded.
- **No more falsely "valid" audit chain when the verifier is unreachable.** The
  dashboard client returned a mock `valid: true` result on API failure; it now
  reports the failure honestly.
