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
  file. The schema is created on first start.
- **Shared signing identity.** Set `identity.seed_env` to an env var (backed by
  a Kubernetes Secret / KMS) holding one hex-encoded 32-byte seed, so every
  replica derives the *same* ML-DSA-65 identity — otherwise each pod signs with
  a different key and cross-pod signatures won't verify.

Two pieces are **not yet shared**, so running >1 replica today has caveats:

- **Auth sessions** live in an in-memory map per pod, so a login is only valid
  on the pod that issued it — front a multi-replica deployment with sticky
  sessions, or keep auth on a single replica, until sessions move to the store.
- **The audit hash-chain is single-writer** (sequential by construction). A
  multi-writer chain needs a design decision (per-replica chains + merge, or a
  single audit-writer); until then, route audited writes through one replica.

In short: the **shared Postgres store + shared seed** unblock horizontal read
scale and failover; full active/active HA still wants stateless sessions and a
multi-writer audit strategy.

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
