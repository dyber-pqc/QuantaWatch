# Deploying QuantaWatch

Run QuantaWatch as a real service — not a local process. Three paths:

| Path | Use for | Directory |
|------|---------|-----------|
| Docker Compose | Local / single-host demo | repo root `docker-compose.yml` |
| Helm | Any Kubernetes cluster | `deploy/helm/quantawatch` |
| Terraform | IaC-managed cluster (wraps the Helm chart) | `deploy/terraform` |

The gateway is stateful: it holds a **SQLite store** (`/app/data`), its **ML-DSA-65
identity keys** (`/app/keys`), and the **hash-chained audit log** (`/app/audit`).
All three live on one `ReadWriteOnce` PVC, so the gateway runs as a **single
replica** with a `Recreate` update strategy. For HA, move to an external DB and
externalize key storage (roadmap).

## Images

```sh
# Gateway (Rust binary)
docker build -t ghcr.io/dyber-inc/quantawatch:1.0.0 -f Dockerfile .
# Dashboard (static SPA)
docker build -t ghcr.io/dyber-inc/quantawatch-dashboard:1.0.0 -f Dockerfile.dashboard .
docker push ghcr.io/dyber-inc/quantawatch:1.0.0
docker push ghcr.io/dyber-inc/quantawatch-dashboard:1.0.0
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
