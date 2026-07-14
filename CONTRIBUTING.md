# Contributing to QuantaWatch

Welcome, and thank you for your interest in contributing to QuantaWatch! We appreciate all contributions, whether they are bug reports, feature requests, documentation improvements, or code changes.

QuantaWatch is a **post-quantum security layer for AI agents**. It provides cryptographic signing, policy enforcement, prompt monitoring, and auditing for AI agent communications -- all built on NIST-standardized post-quantum algorithms (ML-DSA-65, ML-KEM-768). By contributing, you help make AI agent infrastructure resilient against both classical and quantum threats.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Building](#building)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Commit Message Conventions](#commit-message-conventions)
- [Issue Reporting Guidelines](#issue-reporting-guidelines)
- [Architecture Overview](#architecture-overview)
- [License](#license)

## Getting Started

1. Read through this contributing guide in full.
2. Check the [issue tracker](https://github.com/dyber-io/quantawatch/issues) for open issues or create a new one to discuss the change you wish to make.
3. Fork the repository and create your feature branch.

## Development Setup

### Prerequisites

| Tool       | Minimum Version | Purpose                        |
|------------|-----------------|--------------------------------|
| **Rust**   | 1.82+           | Core crates and gateway        |
| **Node.js**| 22+             | Dashboard and TypeScript SDK   |
| **Python** | 3.10+           | Python SDK                     |

### Clone the repository

```bash
git clone https://github.com/<your-fork>/quantawatch.git
cd quantawatch
```

### Install Rust toolchain

```bash
rustup update stable
rustup component add rustfmt clippy
```

### Install Node.js dependencies (dashboard)

```bash
cd dashboard
npm install
```

### Install Python SDK dependencies

```bash
cd sdk/python
pip install -e ".[dev]"
```

## Building

### Rust workspace (all crates)

```bash
cargo build --workspace
```

### Dashboard (React)

```bash
cd dashboard
npm install
npm run dev
```

### Python SDK

```bash
cd sdk/python
pip install -e .
```

### TypeScript SDK

```bash
cd sdk/typescript
npm install
npm run build
```

## Testing

### Rust tests

```bash
cargo test --workspace
```

This runs unit tests and integration tests across all six crates.

### Python SDK tests

```bash
cd sdk/python
pytest
```

### TypeScript SDK tests

```bash
cd sdk/typescript
npx vitest run
```

### Dashboard tests

```bash
cd dashboard
npx vitest run
```

### End-to-end tests

```bash
cd tests
cargo test
```

## Code Style

We enforce consistent code style across all languages in the project.

### Rust

- **Formatter**: `rustfmt` -- run `cargo fmt --all` before committing.
- **Linter**: `clippy` -- run `cargo clippy --workspace -- -D warnings` and fix all warnings.
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).

### TypeScript

- **Strict mode**: All TypeScript code must compile with `strict: true`.
- Use the project's ESLint and Prettier configurations.
- Run `npm run lint` and `npm run format` in the relevant directory.

### Python

- Follow PEP 8 and use type annotations throughout.
- Run `ruff check` and `ruff format` before committing.

### General

- Write meaningful variable and function names.
- Add doc comments to all public APIs.
- Keep functions focused and small.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature main
   ```

2. **Make your changes** with clear, incremental commits following our [commit conventions](#commit-message-conventions).

3. **Add tests** for any new functionality. Ensure all existing tests pass.

4. **Run the full test suite** locally:
   ```bash
   cargo test --workspace
   cargo fmt --all --check
   cargo clippy --workspace -- -D warnings
   ```

5. **Push** your branch and open a **Pull Request** against `main`.

6. **Fill out the PR template** with:
   - A clear description of what changed and why.
   - Links to any related issues.
   - Steps to test the change.

7. **Address review feedback** promptly. We aim to review PRs within a few business days.

8. Once approved and CI passes, a maintainer will merge your PR.

### PR Requirements

- All CI checks must pass (tests, linting, formatting).
- At least one maintainer approval is required.
- The branch must be up-to-date with `main` before merging.
- No unresolved review conversations.

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for all commit messages.

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                                           |
|------------|-------------------------------------------------------|
| `feat`     | A new feature                                         |
| `fix`      | A bug fix                                             |
| `docs`     | Documentation only changes                            |
| `style`    | Code style changes (formatting, missing semicolons)   |
| `refactor` | Code change that neither fixes a bug nor adds a feature|
| `perf`     | Performance improvement                               |
| `test`     | Adding or correcting tests                            |
| `build`    | Changes to the build system or dependencies           |
| `ci`       | Changes to CI configuration                           |
| `chore`    | Other changes that don't modify src or test files     |

### Scopes

Use the crate or component name as the scope:

- `gateway`, `crypto`, `policy`, `monitor`, `audit`, `cli`
- `dashboard`, `sdk-python`, `sdk-ts`
- `docs`, `ci`, `docker`

### Examples

```
feat(gateway): add request rate limiting per agent identity
fix(crypto): handle ML-KEM-768 decapsulation edge case
docs(sdk-python): add LangChain integration example
test(audit): add property-based tests for chain verification
chore(ci): update Rust toolchain to 1.82
```

## Issue Reporting Guidelines

### Bug Reports

When filing a bug report, please include:

- **QuantaWatch version** (output of `quantawatch --version`).
- **Environment**: OS, Rust version, Node version, Python version.
- **Steps to reproduce**: Minimal, complete steps to trigger the bug.
- **Expected behavior**: What you expected to happen.
- **Actual behavior**: What actually happened, including error messages and logs.
- **Configuration**: Relevant portions of your `quantawatch.yaml` (redact any secrets).

### Feature Requests

- Describe the use case and problem you are trying to solve.
- Explain why existing features do not address this need.
- If possible, suggest an approach or API design.

### Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.** Please see our [Security Policy](SECURITY.md) for responsible disclosure instructions.

## Architecture Overview

QuantaWatch is organized as a Rust workspace with six core crates, a React dashboard, and SDKs for Python and TypeScript.

```
quantawatch/
+-- crates/
|   +-- quantawatch-crypto     # PQC primitives (ML-DSA-65, ML-KEM-768)
|   +-- quantawatch-gateway    # Reverse proxy with PQ-TLS termination
|   +-- quantawatch-policy     # Policy engine (OPA-compatible rules)
|   +-- quantawatch-monitor    # Prompt/response analysis and monitoring
|   +-- quantawatch-audit      # Append-only signed audit chain
|   +-- quantawatch-cli        # CLI tool for key management and ops
+-- dashboard/                 # React (TypeScript) admin dashboard
+-- sdk/
|   +-- python/                # Python SDK for agent integration
|   +-- typescript/            # TypeScript SDK for agent integration
+-- deploy/                    # Helm chart + Terraform module
+-- sidecar/                   # Dashboard nginx config
+-- tests/                     # End-to-end integration tests
+-- docs/                      # Documentation
```

### Key Design Principles

- **Post-quantum first**: All cryptographic operations use NIST FIPS 203/204 standardized algorithms.
- **Zero-trust agent model**: Every agent request is authenticated, authorized, and audited.
- **Minimal footprint**: The gateway adds sub-millisecond overhead to agent communications.
- **Pluggable policies**: Security policies are expressed as declarative rules, not code changes.

## License

By contributing to QuantaWatch, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

---

Thank you for helping make AI agent infrastructure quantum-safe!
