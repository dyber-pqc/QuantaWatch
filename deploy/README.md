# Deploying QuantaWatch

Run QuantaWatch as a real service — not a local process. Three paths:

| Path | Use for | Directory |
|------|---------|-----------|
| Docker Compose | Local / single-host demo | repo root `docker-compose.yml` |
| Helm | Any Kubernetes cluster | `deploy/helm/quantawatch` |
| Terraform | IaC-managed cluster (wraps the Helm chart) | `deploy/terraform` |

The gateway is stateful: it holds a **store** (`/app/data`), its **ML-DSA-65
identity keys** (`/app/keys`), and the **hash-chained audit log** (`/app/audit`).
By default all three live on one `ReadWriteOnce` PVC, so the gateway runs as a
**single replica** with a `Recreate` update strategy.

### Toward HA / multiple replicas

Two pieces of the single-node story are now solvable from config:

- **Shared store.** Set `scanner.store_path` to a `postgres://…` URL and every
  replica reads and writes one Postgres database instead of a per-pod SQLite
  file. The schema is created on first start. The DB link uses a PQC-capable
  TLS client (rustls + aws-lc-rs, X25519MLKEM768 hybrid group by default), so
  pointing it at **[FortressQL](https://github.com/dyber-pqc/FortressQL)** — a
  post-quantum-hardened PostgreSQL 17 — with `?sslmode=require` makes the key
  exchange itself post-quantum (harvest-now-decrypt-later resistant). This is
  **verified end-to-end**: against a FortressQL server that offers *only* the PQC
  group, QuantaWatch's client still connects — see [`fortressql/`](fortressql/)
  to build FortressQL and reproduce. Against a classical Postgres it negotiates
  classical X25519; either way, set `sslmode=require` so the link isn't plaintext.
- **Shared signing identity.** Set `identity.seed_env` to an env var (backed by
  a Kubernetes Secret / KMS) holding one hex-encoded 32-byte seed, so every
  replica derives the *same* ML-DSA-65 identity — otherwise each pod signs with
  a different key and cross-pod signatures won't verify.

- **Shared auth sessions.** With a Postgres store, admin login sessions and
  OIDC CSRF state live in the shared database (keyed by a hash of the token, not
  the token itself), so a login on one replica is valid on all of them — no
  sticky sessions required. (On SQLite this also means sessions survive a
  restart.)

- **Sharded audit log.** The PQC-signed, tamper-evident audit trail now supports
  many concurrent writers. Each replica owns its own hash-chain (keyed by
  `audit.writer_id`, defaulting to the pod hostname) and appends lock-free to the
  shared store; a periodic signed **checkpoint** Merkle-roots across every
  replica's chain tip, giving a global tamper-evident anchor that detects a
  writer being dropped or its history rewritten. Verify the whole trail with
  `GET /api/audit/verify`. No single audit-writer, no leader election.

In short: the **shared Postgres store + shared seed** give every replica a shared
inventory, shared sessions, one signing identity, and one verifiable audit trail
— enough for active/active horizontal scale and failover. The remaining nuance is
operational: give each replica a stable, unique `writer_id` (automatic under a
Kubernetes StatefulSet or Deployment, since the pod hostname is unique).

## Images

```sh
# Gateway (Rust binary)
docker build -t ghcr.io/dyber-pqc/quantawatch:1.0.0 -f Dockerfile .
# Dashboard (static SPA)
docker build -t ghcr.io/dyber-pqc/quantawatch-dashboard:1.0.0 -f Dockerfile.dashboard .
docker push ghcr.io/dyber-pqc/quantawatch:1.0.0
docker push ghcr.io/dyber-pqc/quantawatch-dashboard:1.0.0
```

## Helm

```sh
helm install quantawatch deploy/helm/quantawatch \
  --namespace quantawatch --create-namespace \
  --set image.tag=1.0.0 \
  --set ingress.enabled=true --set ingress.host=quantawatch.acme.example.com \
  --set-string secretEnv.ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  --set-string secretEnv.QW_WEBHOOK_SECRET=$QW_WEBHOOK_SECRET
```

Provide a full config with `--set-file config=./quantawatch.yaml`. Every secret
is referenced **by env-var name** from that config (`api_key_env`,
`webhook_secret_env`, OIDC `client_secret_env`, per-integration
`webhook_secret_env`) and supplied via `secretEnv.*`, which becomes a Kubernetes
Secret — secrets never land in the ConfigMap.

Validate before applying:

```sh
helm lint deploy/helm/quantawatch
helm template quantawatch deploy/helm/quantawatch --set ingress.enabled=true | kubectl apply --dry-run=client -f -
```

### FortressQL as the in-cluster store (post-quantum DB link)

Set `fortressql.enabled=true` and the chart deploys **FortressQL** (Dyber's
PQC-hardened PostgreSQL 17) as a StatefulSet, then points the gateway's store at
it over PQC-capable TLS — no external database to run. Build and push the image
from [`fortressql/`](fortressql/) first (`ghcr.io/dyber-pqc/fortressql`).

```sh
helm install quantawatch deploy/helm/quantawatch \
  --namespace quantawatch --create-namespace \
  --set fortressql.enabled=true \
  --set-string fortressql.auth.password=$FORTRESSQL_PASSWORD
```

What this wires automatically:

- The gateway config's `scanner.store_path` is `${QW_STORE_PATH}`, which the
  chart sets to
  `postgres://quantawatch:$(FORTRESSQL_PASSWORD)@<release>-fortressql:5432/quantawatch?sslmode=require`.
  The password comes from the FortressQL **Secret** via a `secretKeyRef` env and
  is substituted by Kubernetes — it never appears in the ConfigMap. The gateway
  expands `${QW_STORE_PATH}` at startup.
- `sslmode=require` forces TLS; the rustls + aws-lc-rs client offers the
  **X25519MLKEM768** hybrid group, so against FortressQL the key exchange itself
  is post-quantum. `fortressql.pqcMode` (`hybrid` / `pqc-only`) tunes the server.
- Because the store is now shared, you can run **replicaCount > 1** — set
  `identity.seed_env` (a Secret-backed hex seed) so every replica signs as the
  same gateway. See "Toward HA" above.

The same image also runs standalone for local verification (self-signed cert,
default `qw_test` creds) — see [`fortressql/`](fortressql/). Credentials, TLS
mode, and an optional mounted cert are all env-driven (`FORTRESSQL_USER`,
`FORTRESSQL_PASSWORD`, `FORTRESSQL_DB`, `FORTRESSQL_SSL_PQC_MODE`,
`FORTRESSQL_CERT_DIR`).

### Scaling to multiple replicas (active/active)

A single gateway keeps local state (SQLite store, on-disk identity keys, audit
files) on one `ReadWriteOnce` PVC, so it runs as one replica with a `Recreate`
rollout. Give it a **shared store** and a **shared signing seed** and it becomes
fully stateless — no PVC — and scales horizontally:

```sh
helm install quantawatch deploy/helm/quantawatch \
  --set fortressql.enabled=true \
  --set-string fortressql.auth.password=$FORTRESSQL_PASSWORD \
  --set-string secretEnv.QW_GATEWAY_SEED=$(openssl rand -hex 32) \
  --set replicaCount=3
```

At `replicaCount > 1` the chart **requires** both a shared store
(`fortressql.enabled` or a `postgres://` `store.path`) and
`secretEnv.QW_GATEWAY_SEED`, and fails the render with a specific message if
either is missing. With both present it automatically:

- drops the PVC entirely — inventory/sessions/audit live in the shared DB, and
  the ML-DSA identity is derived from the seed (`identity.seed_env`), so every
  replica signs as the same gateway;
- switches the rollout to `RollingUpdate` and adds soft pod anti-affinity to
  spread replicas across nodes;
- gives each replica a unique, stable audit **writer id** from its pod name
  (downward API → `QW_AUDIT_WRITER_ID`), so every pod owns its own hash-chain in
  the sharded audit log and the periodic checkpoint Merkle-roots across them.

Keep the seed in a real secrets manager — it *is* the gateway's identity.

## Terraform

```sh
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # fill in, git-ignored
terraform init
terraform apply
```

The module renders the Helm chart via `helm_release`. Keep the sensitive
`secret_env` map out of VCS — use a `*.tfvars` file (git-ignored), `TF_VAR_*`
env vars, or a secrets manager.

To deploy FortressQL as the store, set `fortressql_enabled = true` and
`fortressql_password` (sensitive — supply via `*.tfvars`/`TF_VAR_fortressql_password`).

## Post-deploy

- `GET /api/health` on the admin port (9091) is the readiness/liveness probe.
- **Rotate the default admin password immediately.**
- The in-path proxy is port **9090**; point AI-agent traffic there. The admin
  API + dashboard are on **9091**.
