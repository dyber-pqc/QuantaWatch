# Public-launch checklist

The repository is currently **private**. Going public is effectively
irreversible — a leaked secret, a false claim, or an unsigned release is on the
record the moment the repo flips. This is the gate to run first. Status is
marked as of the last update; re-verify the ✅ items on the exact commit you
publish.

## 1. Secrets & history — MUST pass at flip time

- [x] **No secrets in the working tree or git history.** Last full sweep
      (24 commits, HEAD `33c2126`): no API keys, tokens, private keys, or the
      live admin hash; the only email is a unit-test fixture (`a@x.com`).
- [x] **Runtime secrets are git-ignored**, not tracked: `quantawatch.yaml`
      (holds the admin hash), `data/*.db`, `keys/gateway_seed.key`, `audit/`,
      `.env`, `.claude/settings.local.json`.
- [ ] **Re-run the sweep on the exact publish commit** (history can't be fixed
      after the fact):
      ```bash
      git grep -nIE "sk-ant-[a-zA-Z0-9]{20}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|BEGIN (RSA |EC |)PRIVATE KEY" -- . ':(exclude)*.example'
      git log --all -p | grep -icE "sk-ant-[a-z0-9]{20}"   # expect 0
      ```
      Consider a dedicated scanner (`gitleaks detect`, `trufflehog git file://.`)
      as a second opinion.

## 2. Honesty — the claims must match the code

- [x] **Pre-open-source honesty audit done** (commit `69bfe4f`): removed the
      unsubstantiated performance table, changed "tamper-proof" → "tamper-evident",
      fixed the config/policy examples that didn't parse, removed
      install-from-registry instructions for unpublished packages, corrected all
      repo URLs, and rewrote README/CHANGELOG to match the current product with an
      explicit "Honest status" section.
- [x] **Attestation is labelled honestly** in code and UI (`software-ml-dsa-65`;
      no hardware root of trust claimed). Keep it that way until a real TPM/Nitro
      quote lands.
- [ ] **Re-read the README "Honest status" section** and confirm every limitation
      still holds (single-replica, heuristic detection, software attestation,
      unpublished).

## 3. Auditability artifacts

- [x] **Committed `Cargo.lock`** (reproducible dependency graph).
- [x] **Self-CBOM**, byte-reproducible and **CI-enforced** — `docs/quantawatch.cbom.json`
      is regenerated and diffed on every push (commit `e8292ff`).
- [x] **Reproducible builds**: pinned toolchain (`rust-toolchain.toml`),
      `--locked`, stripped release profile; recipe in `docs/RELEASES.md`.
- [x] **Signed releases**: Sigstore (cosign) + post-quantum ML-DSA-65 signatures,
      SLSA provenance. Verification in `docs/RELEASES.md`.
- [ ] **Third-party crypto audit.** Not done — needs an external firm. This is
      the single most important trust artifact for a crypto product and the one
      that most backs "auditable." Engage before or shortly after launch and
      publish the report.

## 4. Release signing key — one-time maintainer setup (needs you)

- [ ] Generate the release seed **yourself** and never share it:
      ```bash
      openssl rand -hex 32          # -> GitHub repo secret QW_RELEASE_SEED
      ```
- [ ] Derive and commit the **public** key as the trust anchor:
      ```bash
      export QW_RELEASE_SEED=<the hex seed>
      cargo run -p qw-cli -- sign README.md --seed-env QW_RELEASE_SEED \
        --pubkey-out docs/release-signing-key.pub
      git add docs/release-signing-key.pub && git commit -m "chore: publish release signing key"
      ```
      Until this exists, releases still publish (Sigstore-signed); the PQC
      signature step is skipped with a warning.

## 5. CI must actually run

- [x] Workflows exist and are **verified locally**: `ci.yml` (fmt, clippy,
      `cargo test --workspace`, dashboard build, SDK tests, self-CBOM drift,
      helm-lint) and `release.yml` (binaries, images, checksums, dual signing,
      provenance).
- [ ] **Restore GitHub Actions billing.** Until then none of these jobs have run
      in a real runner — they are reviewed, not exercised. Do not treat the CI
      badge as green until a real run passes.
- [ ] Push a trivial commit and confirm every `ci.yml` job passes on
      `ubuntu-latest` (Linux ≠ the local Windows box; the self-CBOM and path
      handling are the likeliest first-run surprises).

## 6. Community health & metadata

- [x] `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
      `CODE_OF_CONDUCT.md`, issue templates, PR template.
- [x] `SECURITY.md` lists all crates and a real disclosure address
      (`security@dyber.io` — confirm it's monitored before launch).
- [ ] Set the repo description, topics, and social preview on GitHub.
- [ ] Decide branch protection on `main` (require CI + review) before external
      contributors arrive.

## 7. The flip

1. Run the §1 sweep on the exact `HEAD` you intend to publish.
2. Complete §4 (signing key) so the first release is PQC-signed.
3. Confirm §5 (a real CI run is green).
4. **Make the repository public** (GitHub → Settings → Danger Zone).
5. Cut the first tag to trigger the release pipeline:
   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```
6. **Verify the published release yourself** before announcing, exactly as a
   user would (`docs/RELEASES.md`): `sha256sum -c`, `qw verify-file`,
   `cosign verify-blob`, `cosign verify` the images.

## 8. After launch

- [ ] Watch the security disclosure address and issues.
- [ ] Publish the third-party audit when complete (§3).
- [ ] Track the roadmap gaps openly: real hardware attestation, HA/Postgres
      scale-out, and the Kubernetes connector's private-cluster CA handling.

---

**Bottom line:** the software and its trust artifacts are launch-ready. The
remaining blockers are not code — they are a **third-party audit** (money + a
firm), the **release signing key** (yours to generate), and **GitHub billing**
(so CI can prove itself). Do not flip until §1, §4, and §5 are green.
