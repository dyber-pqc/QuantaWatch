# Changelog

All notable changes to QuantaWatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- **Post-quantum cryptography**: ML-DSA-65 (FIPS 204) signing, ML-KEM-768 (FIPS 203) key encapsulation, SHA3-256 hashing, Merkle tree verification - all pure Rust, no C dependencies
- **Gateway proxy**: Transparent HTTP proxy supporting Anthropic, OpenAI, Ollama, and OpenAI-compatible providers with path-based routing
- **Policy engine**: YAML-based policy rules with glob matching, model/provider/tool ACLs, and deny-overrides evaluation
- **Prompt monitor**: Regex-based detection for prompt injection, jailbreak attempts, system prompt extraction, data exfiltration, PII exposure, and dangerous commands
- **Audit chain**: Append-only JSONL audit log with ML-DSA-65 signed entries, SHA3-256 hash chain, and Merkle tree batching for efficient verification
- **Dashboard**: React 19 + Vite + Tailwind CSS real-time monitoring dashboard with overview, sessions, audit log, and threats views
- **Python SDK**: `quantawatch` package with `protect()` wrapper for Anthropic/OpenAI clients, async `QuantaWatchClient`, and Pydantic models
- **TypeScript SDK**: `@quantawatch/sdk` with zero runtime dependencies, `protect()` for fetch/client wrapping, and full type definitions
- **CLI**: `qw verify` (audit chain verification), `qw inspect` (audit log browser with filters), `qw keygen` (ML-DSA-65 key generation), `qw version`
- **Docker**: Multi-stage Dockerfile for gateway, Nginx-based dashboard container, docker-compose.yml for one-command deployment
- **Helm chart**: Kubernetes deployment templates with configurable replicas, resource limits, persistence, and optional dashboard
- **CI/CD**: GitHub Actions workflows for Rust (test, clippy, fmt), dashboard build, SDK tests, and release automation

[0.1.0]: https://github.com/dyber-inc/quantawatch/releases/tag/v0.1.0
