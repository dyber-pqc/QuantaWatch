#!/bin/bash
# FortressQL entrypoint: init on first run, enable PQC TLS, provision the
# configured role/db, then run postgres in the foreground.
#
# Credentials, TLS mode, and the server cert are env-driven so the SAME image
# works for local verification (self-signed cert, default test creds) and for a
# Helm/Kubernetes deployment (password from a Secret, optional mounted cert).
# Defaults preserve the original local-dev behaviour.
set -euo pipefail

PGDATA=/var/lib/fortressql/data
export PATH=/usr/local/fortressql/bin:$PATH

# Credentials (FORTRESSQL_* preferred; POSTGRES_* accepted as a convention).
FQ_USER="${FORTRESSQL_USER:-${POSTGRES_USER:-qw_test}}"
FQ_PW="${FORTRESSQL_PASSWORD:-${POSTGRES_PASSWORD:-qw_test_pw}}"
FQ_DB="${FORTRESSQL_DB:-${POSTGRES_DB:-quantawatch_test}}"
# PQC TLS knobs.
FQ_PQC_MODE="${FORTRESSQL_SSL_PQC_MODE:-hybrid}"                     # off | hybrid | pqc-only
FQ_PQC_GROUPS="${FORTRESSQL_SSL_PQC_GROUPS:-X25519MLKEM768:X25519:prime256v1}"
# Optional externally-mounted cert dir (expects server.crt + server.key).
CERT_DIR="${FORTRESSQL_CERT_DIR:-}"

if [ ! -f "$PGDATA/PG_VERSION" ]; then
    echo "==> initdb"
    initdb -D "$PGDATA" -U fortress --auth-host=scram-sha-256 --auth-local=trust >/dev/null

    # Server cert: use the mounted cert if provided (production), else generate a
    # self-signed ed25519 cert (dev). Ed25519 matches ssl_pqc_sigalgs and is
    # verifiable by rustls/aws-lc-rs (which cannot verify ML-DSA certs). The PQC
    # value here is the key exchange, not the cert signature.
    if [ -n "$CERT_DIR" ] && [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
        echo "==> using mounted server cert from $CERT_DIR"
        cp "$CERT_DIR/server.crt" "$PGDATA/server.crt"
        cp "$CERT_DIR/server.key" "$PGDATA/server.key"
    else
        echo "==> generating self-signed ed25519 server cert"
        openssl req -new -x509 -days 30 -nodes -newkey ed25519 \
            -out "$PGDATA/server.crt" -keyout "$PGDATA/server.key" \
            -subj "/CN=fortressql" >/dev/null 2>&1
    fi
    chmod 600 "$PGDATA/server.key"

    echo "==> enabling PQC TLS (mode=$FQ_PQC_MODE) in postgresql.conf"
    cat >> "$PGDATA/postgresql.conf" <<CONF

# --- FortressQL PQC TLS (added by docker-entrypoint) ---
listen_addresses = '*'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_pqc_mode = '$FQ_PQC_MODE'
ssl_pqc_groups = '$FQ_PQC_GROUPS'
ssl_pqc_sigalgs = 'mldsa65:ed25519'
CONF

    echo "==> pg_hba: scram over host (TLS)"
    cat >> "$PGDATA/pg_hba.conf" <<'HBA'
host    all             all             0.0.0.0/0               scram-sha-256
host    all             all             ::/0                    scram-sha-256
HBA

    echo "==> provisioning role '$FQ_USER' + database '$FQ_DB'"
    # SQL-escape single quotes in the password before interpolating.
    FQ_PW_ESC="${FQ_PW//\'/\'\'}"
    pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w start >/dev/null
    psql --set ON_ERROR_STOP=1 -U fortress -d postgres >/dev/null <<SQL
CREATE ROLE "$FQ_USER" LOGIN PASSWORD '$FQ_PW_ESC';
CREATE DATABASE "$FQ_DB" OWNER "$FQ_USER";
SQL
    pg_ctl -D "$PGDATA" -w stop >/dev/null
    echo "==> init complete"
fi

echo "==> starting FortressQL (PQC $FQ_PQC_MODE TLS on 5432)"
exec postgres -D "$PGDATA"
