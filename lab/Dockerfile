# Multi-stage lightweight strongSwan + nftables + cco verification image (~200 MB runtime)
FROM rust:1.86-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates

RUN cargo build --release -p cco-cli \
    && strip target/release/cco

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-swanctl \
    strongswan-charon \
    nftables \
    iproute2 \
    tcpdump \
    iputils-ping \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/cco /usr/local/bin/cco
COPY lab/scripts /opt/cco-lab/scripts
RUN chmod +x /opt/cco-lab/scripts/*.sh

WORKDIR /opt/cco-lab
ENTRYPOINT ["/usr/local/bin/cco"]
