#!/bin/bash
# FortressQL dev entrypoint: init on first run, enable PQC hybrid TLS, provision
# a test role/db, then run postgres in the foreground. For local verification of
# QuantaWatch's PQC DB link — NOT a production config (self-signed cert, no TDE).
set -euo pipefail

PGDATA=/var/lib/fortressql/data
export PATH=/usr/local/fortressql/bin:$PATH

if [ ! -f "$PGDATA/PG_VERSION" ]; then
    echo "==> initdb"
    initdb -D "$PGDATA" -U fortress --auth-host=scram-sha-256 --auth-local=trust >/dev/null

    # Ed25519 cert: matches FortressQL's ssl_pqc_sigalgs (mldsa65:ed25519) so the
    # server can sign the handshake, and rustls/aws-lc-rs can verify ed25519
    # (it can't verify ML-DSA certs). The PQC value here is the KEX, not the cert.
    echo "==> generating self-signed ed25519 server cert"
    openssl req -new -x509 -days 30 -nodes -newkey ed25519 \
        -out "$PGDATA/server.crt" -keyout "$PGDATA/server.key" \
        -subj "/CN=fortressql" >/dev/null 2>&1
    chmod 600 "$PGDATA/server.key"

    echo "==> enabling PQC hybrid TLS in postgresql.conf"
    cat >> "$PGDATA/postgresql.conf" <<'CONF'

# --- FortressQL PQC TLS (added by docker-entrypoint) ---
listen_addresses = '*'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_pqc_mode = 'hybrid'                               # off | hybrid | pqc-only
ssl_pqc_groups = 'X25519MLKEM768:X25519:prime256v1'   # PQC-hybrid first
ssl_pqc_sigalgs = 'mldsa65:ed25519'
CONF

    echo "==> pg_hba: scram over host (TLS)"
    cat >> "$PGDATA/pg_hba.conf" <<'HBA'
host    all             all             0.0.0.0/0               scram-sha-256
host    all             all             ::/0                    scram-sha-256
HBA

    echo "==> provisioning qw_test role + quantawatch_test db"
    pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w start >/dev/null
    psql --set ON_ERROR_STOP=1 -U fortress -d postgres >/dev/null <<'SQL'
CREATE ROLE qw_test LOGIN PASSWORD 'qw_test_pw';
CREATE DATABASE quantawatch_test OWNER qw_test;
SQL
    pg_ctl -D "$PGDATA" -w stop >/dev/null
    echo "==> init complete"
fi

echo "==> starting FortressQL (PQC hybrid TLS on 5432)"
exec postgres -D "$PGDATA"
