# FortressQL (PQC-hardened PostgreSQL 17) built from source with liboqs, for
# verifying QuantaWatch's post-quantum database link end-to-end.
#
# Base debian:trixie for OpenSSL 3.5, which implements the *standardized*
# X25519MLKEM768 code point natively — matching QuantaWatch's rustls/aws-lc-rs
# client, so no oqs-provider and no draft-vs-final code-point mismatch.
#
#   docker build -t fortressql:local deploy/fortressql
#   docker run -d --name fortressql -p 55433:5432 fortressql:local
#
# Cloning happens on Linux (LF line endings), avoiding the Windows autocrlf
# breakage of PostgreSQL's Perl codegen scripts.
FROM debian:trixie AS build

ARG FORTRESSQL_REPO=https://github.com/dyber-pqc/FortressQL.git
ARG FORTRESSQL_REF=main

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential meson ninja-build cmake git pkg-config \
        flex bison libssl-dev libreadline-dev zlib1g-dev libxml2-dev \
        libxslt1-dev libicu-dev liblz4-dev libzstd-dev python3 ca-certificates \
    && openssl version \
    && rm -rf /var/lib/apt/lists/*

# --- liboqs (Open Quantum Safe): required for FortressQL PQC features ---
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
         -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
    && ninja -C /tmp/liboqs/build \
    && ninja -C /tmp/liboqs/build install \
    && ldconfig \
    && rm -rf /tmp/liboqs

# --- FortressQL (cloned on Linux => LF endings) ---
RUN git clone --depth 1 --branch "$FORTRESSQL_REF" "$FORTRESSQL_REPO" /src
WORKDIR /src
RUN meson setup build -Dpqc=enabled -Dssl=openssl -Dprefix=/usr/local/fortressql \
    && meson compile -C build \
    && meson install -C build \
    && ldconfig

ENV PATH=/usr/local/fortressql/bin:$PATH

# Non-root db user + data dir
RUN useradd -m -s /bin/bash fortress \
    && mkdir -p /var/lib/fortressql/data \
    && chown -R fortress:fortress /var/lib/fortressql

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 5432
USER fortress
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
