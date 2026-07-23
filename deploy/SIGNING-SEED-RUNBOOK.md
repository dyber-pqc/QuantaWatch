# Release Signing Seed — Runbook

Operational procedure for the gateway's **signing identity**: how to generate
it, store it, and rotate it. Written for whoever owns QuantaWatch in production.

> The maintainer generates the seed themselves, in a private terminal. It must
> never be produced by, pasted into, or transmitted through any assistant, CI
> log, chat, or ticket. A signing key is only trustworthy if exactly one party
> has ever held it.

---

## 1. What the seed is, and what it protects

The seed is a **hex-encoded 32-byte value** (64 hex characters) — the FIPS 204
seed from which the gateway deterministically derives its **ML-DSA-65 signing
identity**. That identity is the root of trust for everything the gateway
signs:

| Signed artifact | Where | Verified with |
|---|---|---|
| Tamper-evident **audit hash-chain** | every audit entry + checkpoints | the identity's public key |
| **CBOM attestation** quote | `GET /api/cbom/attestation` | published `public_key` in the response |
| **Signed evidence packs** (compliance) | `GET /api/evidence` | `qw verify-evidence` |
| **ML-DSA-65 binding** on issued certs | internal PKI (`pki.enabled`) | the identity's public key |

The identity is summarized by its **fingerprint** — `SHA3-256(public key)`,
surfaced at `GET /api/config` (`.fingerprint`) and `GET /api/stats`
(`.gateway_fingerprint`), and logged at startup. Same seed ⇒ same fingerprint,
always; a different seed ⇒ a different identity.

**Why it must be stable and shared:** regenerating the identity invalidates
every prior signature. Across multiple replicas, all must derive the *same*
identity or their signatures won't cross-verify — which is exactly why the seed
lives in one place all replicas read (see §4).

---

## 2. Golden rules

- **Unique & random.** 32 bytes from a CSPRNG. Never reuse across environments
  (prod / staging / dev each get their own).
- **Never in git, config files, images, CI logs, chat, or tickets.** Only in a
  secrets manager, referenced by env-var name.
- **Back it up offline** the moment it's created (see §4). Losing it is
  unrecoverable — you cannot re-sign historical artifacts under the same
  identity.
- **Env var wins over disk.** When `identity.seed_env` is set, the seed from the
  environment takes precedence over any `gateway_public.key`/`gateway_seed.key`
  on the pod's disk. (Verified: a replica with a stale on-disk identity still
  converges to the shared seed.)

---

## 3. Generate

In an ordinary, non-logged terminal — **not** an assistant session, **not** CI:

```bash
openssl rand -hex 32
```

Or PowerShell (no openssl):

```powershell
-join ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32) | ForEach-Object { $_.ToString('x2') })
```

The output is 64 hex characters. Do not echo it into shell history you keep
(`export HISTCONTROL=ignorespace` and prefix the command with a space, or pipe
straight into the secrets-manager CLI in §4).

---

## 4. Store & wire up

**a. Put it in your secrets manager**, keyed for QuantaWatch. Examples:

```bash
# HashiCorp Vault
vault kv put secret/quantawatch/prod gateway_seed=<64-hex>

# AWS Secrets Manager
aws secretsmanager create-secret --name quantawatch/prod/gateway-seed --secret-string <64-hex>

# Kubernetes Secret (prefer a sealed/external-secrets source over raw manifests)
kubectl create secret generic qw-gateway-seed --from-literal=seed=<64-hex>
```

**b. Back it up offline** — a second, independent copy (printed and vaulted, or
a second secrets manager). This is your only recovery path if the primary store
is lost.

**c. Reference it from the config** by env-var name (never the value):

```yaml
identity:
  key_dir: "/var/lib/quantawatch/keys"
  seed_env: "QW_GATEWAY_SEED"     # the ENV VAR name, not the seed
```

**d. Inject the env var into the service environment** so the process reads it:

- **Kubernetes:** mount the Secret as env `QW_GATEWAY_SEED` (`valueFrom.secretKeyRef`).
  Set it identically on **every** replica so they share one identity.
- **systemd:** `EnvironmentFile=` pointing at a `root:0600` file, or a
  `LoadCredential=` drop-in.
- **Windows service:** set a machine-scoped variable and restart the service:
  `[Environment]::SetEnvironmentVariable("QW_GATEWAY_SEED", $seed, "Machine")`.

**Validation is fail-closed:** if the value isn't valid hex, or doesn't decode
to exactly 32 bytes, the gateway refuses to start with a clear error rather than
silently minting a new identity.

---

## 5. Deploy & confirm

After the gateway starts, confirm it adopted the seed identity (not a
disk-generated one):

```
# startup log — expect this line, NOT "generated and persisted":
"Gateway identity loaded from environment"   fingerprint=<hex>
```

Then check the fingerprint over the API (authenticated):

```bash
curl -s https://<gw>/api/config  | jq -r .fingerprint
curl -s https://<gw>/api/stats   | jq -r .gateway_fingerprint
```

**All replicas must report the same fingerprint.** A mismatch means one replica
didn't get the env var and is signing with a divergent identity — fix before
serving traffic.

**Archive the public key + fingerprint** now, in your records (needed to verify
historical signatures after a future rotation). For an env-seed deployment the
public key isn't written to disk, so read it from the attestation:

```bash
curl -s https://<gw>/api/cbom/attestation | jq -r .public_key > gateway_public_<fingerprint>.hex
```

Verify a signed artifact end-to-end (audit chain):

```bash
# via API (uses the current identity's public key):
curl -s https://<gw>/api/audit/verify | jq .

# offline with the CLI, against an exported public-key file:
xxd -r -p gateway_public_<fingerprint>.hex > gateway_public.key
qw verify ./audit --public-key ./gateway_public.key
```

---

## 6. Rotate

Rotation replaces the signing identity. Treat it as an **epoch boundary**: every
artifact signed before the switch is verifiable only with the *old* public key,
and everything after only with the *new* one. Plan accordingly.

### When to rotate
- Suspected or confirmed seed exposure (leaked secret, compromised host).
- Offboarding of anyone who had access to the seed store.
- Scheduled crypto hygiene / a defined cryptoperiod.

### Procedure
1. **Freeze & anchor the old epoch.** Confirm the audit chain verifies clean
   under the current key, and archive: (a) the old public key file, (b) its
   fingerprint, (c) the `GET /api/audit/verify` result and latest checkpoint.
   Keep these **permanently** — they are how historical audit entries, evidence
   packs, and certs stay verifiable.
   ```bash
   curl -s https://<gw>/api/audit/verify | jq . > audit-verify-<old-fp>.json
   curl -s https://<gw>/api/cbom/attestation | jq -r .public_key > gateway_public_<old-fp>.hex
   ```
2. **Generate the new seed** (§3) and store it (§4). Do **not** delete the old
   seed/public key from cold storage.
3. **Roll all replicas together.** Update the Secret to the new seed and restart
   **every** replica in one coordinated rollout. A partial rollout means some
   pods sign with the old identity and some with the new — a split that breaks
   cross-verification. (A brief full drain/restart is safer here than a slow
   rolling update that straddles both identities.)
4. **Confirm the new epoch.** All replicas report the *new* fingerprint (§5);
   `GET /api/audit/verify` is clean for entries written after the switch.
5. **Update relying parties.** Anyone pinning the fingerprint/public key — CBOM
   consumers, evidence-pack verifiers, cert trust stores, external monitors —
   gets the new public key, and retains the old one to check pre-rotation
   artifacts.
6. **Re-issue if required.** Certs whose ML-DSA-65 binding was signed by the old
   identity remain valid under the old public key; re-issue them under the new
   identity if your policy requires a single active signer.

### Emergency rotation (suspected compromise)
Do steps 2–5 immediately; do step 1's archival in parallel from backups if the
live gateway is untrusted. Then **revoke the old seed** in the secrets manager
and rotate any credential that shared its blast radius.

---

## 7. Loss & recovery

| Situation | Consequence | Action |
|---|---|---|
| Seed lost, no backup | Cannot re-sign or extend the old identity; new replicas can't join the old epoch | Treat as a forced rotation (§6); the old chain stays verifiable **only** if you archived the old public key (§5) |
| Seed leaked | Attacker could forge signatures under your identity | Emergency rotation (§6); revoke old seed; audit for forged entries using checkpoints |
| One replica has a different fingerprint | That replica missed the env var; its signatures won't cross-verify | Fix its `QW_GATEWAY_SEED` injection and restart; do not serve from it until the fingerprint matches |
| Old public key not archived before rotation | Historical audit/evidence/certs can't be verified | Recover the old public key from any surviving replica's `/api/cbom/attestation` cache or a `gateway_public.key` on disk, if one exists |

---

## Quick reference

| Task | Command |
|---|---|
| Generate seed | `openssl rand -hex 32` |
| Wire into config | `identity.seed_env: "QW_GATEWAY_SEED"` |
| Confirm identity on boot | log line `Gateway identity loaded from environment`; `GET /api/config` `.fingerprint` |
| Export public key | `curl -s https://<gw>/api/cbom/attestation \| jq -r .public_key` |
| Verify audit chain (API) | `GET /api/audit/verify` |
| Verify audit chain (CLI) | `qw verify ./audit --public-key ./gateway_public.key` |
| Rotate | archive old public key → new seed → roll all replicas → confirm new fingerprint |
