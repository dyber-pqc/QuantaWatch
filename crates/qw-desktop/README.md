# QuantaWatch Desktop

A **native** desktop view of your post-quantum posture — built with
[egui](https://github.com/emilk/egui), not a browser.

## Why a native app

The web dashboard is served by the gateway over HTTP(S) and viewed in a browser.
This desktop build is for environments that want a tighter air gap:

- **No embedded browser / webview.** It's a pure-Rust immediate-mode GUI. There
  is no HTML engine, no Chromium/WebView2, and none of that attack surface.
- **No network listener, no outbound calls.** Nothing is served and nothing is
  fetched. The app links `qw-store`, `qw-scanner`, and `qw-cbom` directly and
  reads the on-disk SQLite store **in-process**.
- **One binary.** No gateway process, no localhost port, no separate dashboard
  server to run or firewall.

It reads the *same* store the gateway/CLI write, so it's a drop-in local viewer
for a machine that already has QuantaWatch data — or a standalone offline console
on an analyst's workstation.

## Build & run

```sh
cargo build --release -p qw-desktop
# Point it at a data directory containing quantawatch.db (default ./data):
./target/release/quantawatch-desktop /path/to/data
```

If the directory has no `quantawatch.db`, the app still launches against an empty
in-memory store and says so — populate it with `qw scan` or the gateway.

## What it shows (v1)

| Page | Source |
|------|--------|
| **Overview** | latest `PostureSnapshot` — score, severity breakdown, assets-by-status |
| **Findings** | `all_findings` — severity-ranked, filterable table |
| **Estate** | `list_targets` — hosts, environment, PQC status, service counts |
| **Certificates** | `list_certificates` — issued PQC certs |

## Roadmap

- In-process **scanning** (drive `qw-scanner` directly — no gateway) so the
  desktop app can generate findings, not just view them.
- **Attack-path** graph view (reuse the `qw-cbom` engine).
- Finding detail + one-click remediation plan.
- Read-only vs. operator modes.

## Air-gap note

This binary makes no network calls. If you need to *prove* that in a locked-down
environment, run it with outbound network denied — it functions identically,
because everything it needs is the local store and the linked crates.
