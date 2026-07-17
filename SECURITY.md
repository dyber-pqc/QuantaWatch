# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report them via email to **security@dyber.io**. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix timeline**: Within 90 days (critical vulnerabilities prioritized)

### Scope

The following components are in scope:

- `qw-crypto` — PQC signing, key encapsulation, hashing, Merkle trees, identity seed persistence
- `qw-gateway` — Request proxying, middleware pipeline, admin API, auth/RBAC/multi-tenancy, attestation, resilience
- `qw-audit` — Audit chain integrity, signature verification
- `qw-policy` — Policy evaluation logic
- `qw-monitor` — Threat detection patterns and heuristics
- `qw-scanner` — TLS/certificate/dependency/code scanning, OID resolution
- `qw-cbom` — CBOM generation, posture scoring, compliance, migration planning
- `qw-integrations` — GitHub/GitLab/Jira/Linear connectors, inbound webhooks
- `qw-store` — Tenant-scoped persistence
- `sdk/python/` — Python SDK
- `sdk/typescript/` — TypeScript SDK
- `dashboard/` — React dashboard

### Post-Quantum Considerations

QuantaWatch uses NIST-standardized post-quantum algorithms:

- **ML-DSA-65** (FIPS 204) for digital signatures
- **ML-KEM-768** (FIPS 203) for key encapsulation
- **SHA3-256** (FIPS 202) for hashing

We track updates to these standards and the underlying RustCrypto implementations. If you discover implementation issues in our usage of these algorithms, please report them through the process above.

Our own cryptographic inventory — including the classical-crypto surface we
have not yet migrated — is documented in [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md)
and published as a self-generated CBOM at `docs/quantawatch.cbom.json`.

Releases are reproducible (pinned toolchain + committed `Cargo.lock`) and signed
with both Sigstore and a post-quantum ML-DSA-65 signature. Verification and
build-reproduction instructions are in [`docs/RELEASES.md`](docs/RELEASES.md).

### Recognition

We will credit security researchers who responsibly disclose vulnerabilities (unless they prefer to remain anonymous).
