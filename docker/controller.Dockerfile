FROM rust:1.91.1-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build -p pecr-controller --release --features rlm

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/pecr-controller /usr/local/bin/pecr-controller
COPY scripts/rlm/pecr_rlm_bridge.py /usr/local/share/pecr/pecr_rlm_bridge.py
COPY vendor/rlm/rlm /usr/local/share/pecr/vendor/rlm/rlm
EXPOSE 8081
ENTRYPOINT ["pecr-controller"]
