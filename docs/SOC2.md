# SOC2 Controls Mapping

QuantaWatch is not itself "SOC2 certified" — certification is an audit of *your*
organization by a licensed CPA firm. What QuantaWatch provides is the **technical
control surface** an auditor looks for, plus the **evidence** (a tamper-evident
audit log) that those controls actually ran.

This document maps QuantaWatch's enforced controls to the SOC2 Trust Services
Criteria. The same mapping is available **live** at `GET /api/soc2`, where each
control's status is evaluated against your running configuration — so it reports
what is actually turned on, not an aspirational checklist.

## How to read the status

| Status | Meaning |
|---|---|
| `enforced` | Enforced by the running system given the current config. |
| `partial` | Available and partly enforced, but a stronger setting is off (e.g. idle timeout disabled). |
| `configurable` | The mechanism ships in the product; enabling it is a deployment choice. |
| `manual` | Satisfied by organizational process, not the product. |

## Controls

### CC6 — Logical & Physical Access

| Criteria | Control | Provided by |
|---|---|---|
| CC6.1 | Logical access control (RBAC) | Permission-based RBAC — every route requires a `resource:action` permission; built-in and custom least-privilege roles (`crates/qw-gateway/src/rbac.rs`). |
| CC6.1 | Password strength policy | Argon2id hashing; `qw hash-password` enforces a minimum length (default 12). |
| CC6.1 | Brute-force protection | Failed-login lockout after N attempts, stored in the shared store so it holds across all replicas. |
| CC6.1 | SSO / MFA delegation | OIDC (Okta/Entra/Auth0/Google); MFA enforced by the IdP. |
| CC6.2 | User provisioning / de-provisioning | Users & API keys declared in version-controlled config (GitOps-reviewed). *Manual process.* |
| CC6.3 | Least privilege & role separation | Distinct read/write permissions per resource; operators cannot touch config; custom roles scope to an explicit permission set. |
| CC6.6 | Encryption of data in transit | TLS to upstreams; the crypto scanner fingerprints TLS and flags quantum-vulnerable transport. |
| CC6.7 | Session management | Absolute session TTL + idle timeout; tokens stored only as SHA3-256 hashes. |

### CC7 — System Monitoring

| Criteria | Control | Provided by |
|---|---|---|
| CC7.1 | Configuration drift detection | Crypto-agility governance gate + deterministic self-CBOM; CI can block on regression. |
| CC7.2 | Access monitoring / logging | Login success/failure, logout, and RBAC access-denied events in the tamper-evident audit log (principal, IP, outcome). |
| CC7.2 | Threat detection in the data path | In-path monitor inspects every LLM request/response for injection, exfiltration, and PII. |
| CC7.3 | Alerting on security events | Continuous-attestation alerting to Slack/webhook on posture drops and critical findings. |

### CC8 — Change Management

| Criteria | Control | Provided by |
|---|---|---|
| CC8.1 | Change tracking | Every successful mutating admin action is recorded as an `admin_action` audit event; runtime config is declarative (GitOps). |
| CC8.1 | Audit-trail integrity | SHA3-256 hash chain → Merkle roots → ML-DSA-65 (FIPS 204) signatures; the sharded multi-writer log stays verifiable across active/active replicas. |

### A1 — Availability

| Criteria | Control | Provided by |
|---|---|---|
| A1.2 | High availability / no single point of failure | Shared signing identity (KMS/Secret seed), shared Postgres store, stateless sessions, sharded multi-writer audit log → active/active replicas. |

## Evidence for auditors

- **Access events:** `GET /api/audit` (filter for `login_succeeded`, `login_failed`,
  `logout`, `access_denied`, `admin_action`), or `GET /api/audit/export` for a
  signed pull. Verify chain integrity with `POST /api/audit/verify`.
- **Live controls report:** `GET /api/soc2`.
- **Posture & crypto inventory:** `GET /api/posture`, `GET /api/cbom`.
- **Governance gate:** `GET /api/governance?gate=1`.

## Out of scope

This mapping covers the **technical** criteria QuantaWatch can enforce or
evidence. It does **not** cover physical/environmental controls (CC6.4–6.5),
HR/onboarding, vendor management, or the organizational policies that a SOC2
Type II report evaluates. Those remain your responsibility and your auditor's.
Nothing here is a substitute for an engagement with a licensed audit firm.
