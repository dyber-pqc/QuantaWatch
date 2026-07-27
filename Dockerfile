# QuantaWatch Gateway - Multi-stage build
# Stage 1: Build the Rust binary
FROM rust:1.93-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# qw-gateway embeds the host-agent scripts via include_str!; they must be in the
# build context or the compile fails with "couldn't read .../deploy/agent/...".
COPY deploy/agent/ deploy/agent/

# Build release binary
RUN cargo build --release -p qw-gateway -p qw-cli

# Stage 2: Runtime image
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r quantawatch && useradd -r -g quantawatch -m quantawatch

WORKDIR /app

# Copy binaries
COPY --from=builder /build/target/release/quantawatch /app/quantawatch
COPY --from=builder /build/target/release/qw /app/qw
COPY quantawatch.yaml.example /app/quantawatch.yaml

# Create directories
RUN mkdir -p /app/audit /app/keys && chown -R quantawatch:quantawatch /app

USER quantawatch

EXPOSE 9090 9091

ENTRYPOINT ["/app/quantawatch"]
CMD ["quantawatch.yaml"]
