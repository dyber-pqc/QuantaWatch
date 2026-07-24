# Releases: reproducible builds and signed artifacts

QuantaWatch releases are **reproducible** and **signed twice** — with Sigstore
(what most consumers verify) and with QuantaWatch's own post-quantum signature
(ML-DSA-65, the scheme the product is built on). You do not have to trust the
release pipeline; you can check the math.

## Verifying a release

Every release attaches `SHA256SUMS` (the digest of each binary) plus signatures.

### 1. Check the binaries against the checksums

```bash
sha256sum -c SHA256SUMS
```

### 2. Verify the checksums are authentic

**Post-quantum (ML-DSA-65)** — using the same `qw` CLI the release ships:

```bash
qw verify-file SHA256SUMS \
  --signature SHA256SUMS.sig \
  --public-key docs/release-signing-key.pub
```

The public key `docs/release-signing-key.pub` is committed in this repository
and is the trust anchor: it does not change between releases.

**Sigstore (keyless)** — verifies the checksums were signed by this repo's
release workflow, no key distribution required:

```bash
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.cosign.sig \
  --certificate SHA256SUMS.cosign.pem \
  --certificate-identity-regexp 'https://github.com/dyber-pqc/QuantaWatch/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### 3. Verify a container image

```bash
cosign verify ghcr.io/dyber-pqc/quantawatch:<tag> \
  --certificate-identity-regexp 'https://github.com/dyber-pqc/QuantaWatch/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Images and the checksums also carry [SLSA build provenance](https://slsa.dev)
(`actions/attest-build-provenance`), verifiable with `gh attestation verify`.

## Reproducing a build

Releases are built with a **pinned toolchain** (`rust-toolchain.toml`), a
**committed `Cargo.lock`** (`--locked`), and a stripped, single-codegen-unit
release profile — so the same source produces the same binary. Rebuild in the
pinned container and compare:

```bash
git checkout v<version>
docker run --rm -v "$PWD:/src" -w /src rust:1.93-bookworm \
  cargo build --release --locked -p qw-gateway -p qw-cli
sha256sum target/release/quantawatch target/release/qw
# Compare against SHA256SUMS from the release.
```

Reproducibility is validated by building in the pinned environment; a native
build on a different OS/linker may differ in platform-specific bytes.

## Maintainer: one-time signing-key setup

The post-quantum release key is a 32-byte seed. **Generate it yourself and never
share it** — QuantaWatch keys are derived deterministically from the seed.

```bash
# 1. Generate a seed and store it as the GitHub Actions secret QW_RELEASE_SEED
openssl rand -hex 32          # -> paste into repo Settings > Secrets > QW_RELEASE_SEED

# 2. Derive the PUBLIC key and commit it as the trust anchor
export QW_RELEASE_SEED=<the same hex seed>
qw sign README.md --seed-env QW_RELEASE_SEED --pubkey-out docs/release-signing-key.pub
git add docs/release-signing-key.pub && git commit -m "chore: publish release signing key"
```

If `QW_RELEASE_SEED` is not set, the release still publishes with the Sigstore
signature; the post-quantum signature is skipped with a warning.

## Windows desktop: MSI installer + Authenticode signing

Tagging a release also builds the native desktop app (`quantawatch-desktop.exe`)
on the Windows runner and packages it as an MSI installer (`cargo-wix` + WiX v3;
see `crates/qw-desktop/wix/main.wxs`). Both the exe and the MSI are attached to
the release and covered by `SHA256SUMS` + the post-quantum signature like every
other artifact.

Authenticode code-signing is applied when a signing certificate is configured,
and skipped (with a warning) otherwise — an unsigned exe + MSI still ship.

**Maintainer: one-time Authenticode setup.** Provide a code-signing certificate
as a PKCS#12 (`.pfx`). **The certificate is yours to obtain and safeguard — it is
never generated in CI.** Store it as two GitHub Actions secrets:

```bash
# Base64-encode your .pfx and store it as WINDOWS_CERT_PFX
base64 -w0 codesign.pfx     # -> repo Settings > Secrets > WINDOWS_CERT_PFX

# Store its password as WINDOWS_CERT_PASSWORD
#   -> repo Settings > Secrets > WINDOWS_CERT_PASSWORD
```

The pipeline decodes the `.pfx` into a temp file on the runner, signs with
`signtool` (SHA-256, RFC-3161 timestamped via `timestamp.digicert.com`), and
deletes it. The MSI's `UpgradeCode` is fixed, so new versions upgrade in place.

Locally (with WiX installed) you can build the MSI without CI:

```bash
cargo install cargo-wix
cargo build --release -p qw-desktop
cargo wix --package qw-desktop --no-build
```
