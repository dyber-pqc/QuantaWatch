# QuantaWatch Desktop

A native (egui) desktop app that gives you the QuantaWatch dashboard **without a
browser and without a network listener**. It links the crypto, scanner, CBOM,
graph, PKI and store crates directly and reads the on-disk SQLite store
**in-process**. Nothing is served and — by default — nothing is fetched, which
makes it a good fit for air-gapped and high-assurance environments.

- Crate: [`crates/qw-desktop`](../crates/qw-desktop)
- Binary: `quantawatch-desktop`

## Install

**Windows (recommended):** download an installer from the
[latest release](https://github.com/dyber-pqc/QuantaWatch/releases) — either
`quantawatch-desktop.msi` (MSI, for managed/silent deployment) or
`quantawatch-desktop-setup.exe` (a friendly Inno Setup wizard). Both install to
*Program Files*, add a Start-menu shortcut, and register an uninstall entry, and
both are covered by the release `SHA256SUMS` + post-quantum signature (see
[RELEASES.md](RELEASES.md)). You can also build either installer yourself —
`cargo wix --package qw-desktop` or `iscc crates\qw-desktop\installer\quantawatch-desktop.iss`.

**From source (any OS):**

```bash
cargo build --release -p qw-desktop
./target/release/quantawatch-desktop ./data
```

## Running

```
quantawatch-desktop [DATA_DIR]      # open the store (default: ./data)
quantawatch-desktop --selfcheck     # headless: verify the local crypto path, exit
quantawatch-desktop --board-report [DATA_DIR]   # headless: write the board report, exit
```

`DATA_DIR` is a directory a gateway or the CLI has populated (it holds
`quantawatch.db`), or a fresh one — the app always launches, and tells you when
the store is empty. The window title shows the exact running build
(`vX.Y.Z · <git hash> · <build time>`).

## Offline by default; opt-in Online mode

The top-bar badge always shows the current mode:

- **OFFLINE** (default) — fully air-gapped. No network calls of any kind; the app
  only reads the local store and local files.
- **PROBES ON** — enabled in **Settings → Mode**. Unlocks the network features:
  reachability probes, live packet capture (`tshark`), connection token tests,
  repo scans over a connection, and remediation-ticket filing.

The **local PQC certificate authority** (issue / renew / revoke) and **in-process
code scans** are local operations and work in either mode.

## Pages

**Posture** — Overview (posture score, severity mix, in-process scan, board
report), Attack Paths (the crypto security graph + HNDL kill-chains, with a
"harden to hybrid" remediation simulation), Estate, Endpoints, Assets, Findings,
Certificates, Crypto (CBOM).

**Governance** — Compliance, Crypto policies (the crypto-agility engine),
Frameworks, SOC 2, Governance/SLO trends.

**Operate** — Scans, Remediations, PQC Overlay, Connections.

**Monitor** — Agents, Sessions, Threats, Alerts, Audit log.

**Admin** — Access (RBAC), Settings, About.

Most list pages open a detail panel on click; list values like paths, hashes and
fingerprints are click-to-copy. Assets and Estate targets are editable in place.

### Certificates (local PQC CA)

The desktop runs its own offline certificate authority. Issuing produces a
**hybrid** cert: a classical Ed25519 X.509 leaf with an **ML-DSA-65 (FIPS 204)
binding** over it — the leaf key stays classical for interoperability, and the
quantum-safe proof lives in the cert record. Renew and revoke are supported;
the one-time leaf private key is shown once and never stored.

### Board report

**Overview → Board report** (or `--board-report`) writes a print-ready executive
*Quantum Risk* report to `quantawatch-board-report.html` next to the store —
posture, top HNDL attack paths, framework compliance and the prioritized
migration roadmap, with the same composite scoring as the gateway's
`/api/report/board`. Open it in a browser and Print → Save as PDF.

### Terminal

A built-in console (top-bar **Terminal**, or `Ctrl+`` `) with:
`help · clear · posture · findings [n] · estate · assets · certs · threats ·
paths · scan <dir> · open <page> · refresh · version`, plus (Online mode)
`wireshark · ifaces · capture <host> [count]`.

## Web ↔ desktop parity

The desktop mirrors the web dashboard. Differences are deliberate and follow from
being an offline, in-process client rather than a browser talking to a gateway.

| Web dashboard | Desktop | Notes |
|---|---|---|
| Dashboard / Posture | Overview | In-process scan + board report added |
| Attack Paths | Attack Paths | Same graph + kill-chains; adds remediation simulation |
| Estate / Endpoints / Assets | ✅ same | Assets & Estate editable in place |
| Findings / Certificates | ✅ same | Certs issued by the **local** PQC CA |
| Crypto (CBOM) | ✅ same | Built in-process from findings; JSON export |
| Compliance / Frameworks / SOC 2 | ✅ same | Shared `qw-cbom` engines |
| Crypto Policies | ✅ same | Shared agility engine + default policy set |
| Governance / SLO | Governance/SLO | Trend history from the local store |
| Scans / Remediations / PQC Overlay | ✅ same | Ticket filing needs Online mode |
| Integrations | Connections | Token test / repo scan need Online mode |
| Agents / Sessions / Threats / Alerts / Audit | ✅ same | Read from the local store |
| Access (RBAC) | ✅ view | Read-only; RBAC is enforced by the gateway |
| Board report (`/api/report/board`) | Overview → Board report | Generated offline |
| Login | — | Local app; no auth. Store access is filesystem-scoped |

**Intentional differences**

- **No enforcement.** The gateway is the in-path enforcement point; the desktop
  is an analysis + operations console over the same store. Threats/policies are
  shown as evaluated from stored data, not enforced live.
- **Board-report attestation.** The desktop report is generated offline, so it
  does not embed a live ML-DSA attestation quote. For a cryptographically-attested
  inventory, use a gateway-produced CBOM and verify its embedded quote with
  `qw cbom verify-attestation <cbom.json>`.
- **Certificate authority.** The desktop issues from its own local CA under
  `DATA_DIR/pki`, independent of any gateway CA.

## Security posture

- **No network listener** — the binary opens no socket; there is no embedded
  webview or browser.
- **No network egress** unless you turn on Online mode, and the top-bar badge
  always reflects it.
- **Secrets at rest** — connection tokens are encrypted at rest and masked in the
  UI; issued private keys are shown once and never persisted.
- **Signed distribution** — release exe + MSI carry SHA-256 checksums, a
  post-quantum (ML-DSA-65) signature, and (when configured) Authenticode signing.

## Development

```bash
cargo run -p qw-desktop -- ./data        # run against a data dir
cargo test -p qw-desktop                 # unit tests (CBOM aggregation, provenance)
cargo run -p qw-desktop -- --selfcheck   # main-thread crypto self-check (CI guard)
```

The desktop performs ML-DSA-65 keygen/signing on the eframe main thread; a linker
arg in [`build.rs`](../crates/qw-desktop/build.rs) reserves a 32 MiB main-thread
stack on Windows (the ~1 MiB default overflows). CI builds and runs `--selfcheck`
on `windows-latest` to guard that.
