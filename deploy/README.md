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

## Post-deploy

- `GET /api/health` on the admin port (9091) is the readiness/liveness probe.
- **Rotate the default admin password immediately.**
- The in-path proxy is port **9090**; point AI-agent traffic there. The admin
  API + dashboard are on **9091**.
