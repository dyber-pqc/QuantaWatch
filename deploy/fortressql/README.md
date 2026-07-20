# FortressQL: post-quantum database link for QuantaWatch

QuantaWatch's shared store (`scanner.store_path: postgres://…`) connects with a
PQC-capable TLS client (rustls + aws-lc-rs, which offers the **X25519MLKEM768**
hybrid key-exchange group by default). Point it at
**[FortressQL](https://github.com/dyber-pqc/FortressQL)** — Dyber's
post-quantum-hardened PostgreSQL 17 — and the key exchange itself becomes
post-quantum, so the database link resists harvest-now-decrypt-later.

This directory builds FortressQL from source (with liboqs, on OpenSSL 3.5) so the
PQC handshake can be **verified end-to-end**, not just asserted.

## Build & run

```sh
docker build -t fortressql:local deploy/fortressql
docker run -d --name fortressql -p 55433:5432 fortressql:local
```

The image builds liboqs, then FortressQL (`meson … -Dpqc=enabled -Dssl=openssl`),
and the entrypoint initializes a data dir, generates an **Ed25519** server cert
(matching FortressQL's `ssl_pqc_sigalgs = mldsa65:ed25519`, and verifiable by
rustls — which cannot verify ML-DSA certs), enables PQC **hybrid** TLS, and
provisions a `qw_test` / `quantawatch_test` role+db.

Point QuantaWatch at it:

```yaml
scanner:
  store_path: "postgres://qw_test:qw_test_pw@127.0.0.1:55433/quantawatch_test?sslmode=require"
```

## Verifying the PQC handshake

FortressQL's own per-connection log line ("classical groups only") is unreliable
in the current build — it prints the same text for connections that provably
used the hybrid group. So verify by **denial** instead: force the server to offer
*only* the PQC group, confirm a classical-only client is rejected, then confirm
the client under test still connects.

```sh
# Force PQC-only: the server now rejects every classical key exchange.
docker exec -u fortress fortressql bash -c '
  D=/var/lib/fortressql/data
  sed -i "s/^ssl_pqc_groups = .*/ssl_pqc_groups = '\''X25519MLKEM768'\''/" $D/postgresql.conf
  sed -i "s/^ssl_pqc_mode = .*/ssl_pqc_mode = '\''pqc-only'\''/"          $D/postgresql.conf
  pg_ctl -D $D reload'

# Control: a classical-only client MUST fail (handshake failure alert 40).
docker exec fortressql bash -c \
  "echo Q | openssl s_client -connect 127.0.0.1:5432 -starttls postgres -groups X25519"

# A client offering the hybrid MUST succeed with X25519MLKEM768.
docker exec fortressql bash -c \
  "echo Q | openssl s_client -connect 127.0.0.1:5432 -starttls postgres -groups X25519MLKEM768 \
   | grep 'Negotiated TLS1.3 group'"
```

QuantaWatch's client is verified the same way — with the server in PQC-only mode,
its store integration test connects successfully, which is only possible if it
negotiated X25519MLKEM768:

```sh
QW_TEST_PG_URL="postgres://qw_test:qw_test_pw@127.0.0.1:55433/quantawatch_test?sslmode=require" \
  cargo test -p qw-store postgres_backend
```

## What is and isn't post-quantum here

- **Key exchange — post-quantum.** X25519MLKEM768 (hybrid ML-KEM-768 + X25519),
  negotiated by both sides. This is the harvest-now-decrypt-later protection.
- **Server certificate — classical (Ed25519) in this setup.** rustls/aws-lc-rs
  cannot yet verify ML-DSA certificate signatures, and `sslmode=require` doesn't
  validate the chain anyway. FortressQL *can* present an ML-DSA-65 cert; consuming
  it from the Rust client is future work (see `crates/qw-store/src/lib.rs`).
- **At rest (TDE), WAL signing — not exercised here.** Those are FortressQL
  server-side features, independent of QuantaWatch's client.

> Dev/verification config only: self-signed cert, `sslmode=require` (no CA check),
> no TDE. Not a production deployment.
